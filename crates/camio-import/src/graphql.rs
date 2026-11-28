//! GraphQL import (plan §10 "imported OpenAPI/GraphQL").
//!
//! Turns a GraphQL **introspection result** (the JSON a server returns for the
//! standard introspection query) into request-only [`HttpExchange`]es — one
//! `POST` per root `Query`/`Mutation` field — that the operator can replay or
//! fuzz against the endpoint.
//!
//! Each generated request carries `{"query": "...", "variables": {...}}`: the
//! operation invokes the root field, passing its arguments as `$variables`
//! (placeholders by scalar type), and selects a one-level set of scalar/enum
//! sub-fields (plus `__typename`) of the return type. Nothing is sent; this is
//! pure parsing.

use crate::{ImportError, ImportResult};
use camio_core::{Body, HttpExchange, HttpRequest, Source};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

const MAX_OPERATIONS: usize = 2000;
const MAX_ARGS: usize = 20;
const MAX_SELECTION: usize = 40;

/// Import a GraphQL introspection result, generating one request per root
/// Query/Mutation field, each a `POST` to `endpoint`.
pub fn import_graphql(json: &str, endpoint: &str) -> Result<ImportResult, ImportError> {
    let doc: Value =
        serde_json::from_str(json).map_err(|e| ImportError::Parse(format!("not valid JSON: {e}")))?;

    // The schema may be at `data.__schema` (a raw server response) or `__schema`.
    let schema = doc
        .get("data")
        .and_then(|d| d.get("__schema"))
        .or_else(|| doc.get("__schema"))
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ImportError::Unsupported(
                "no `__schema` — not a GraphQL introspection result".to_string(),
            )
        })?;

    // Index every type by name for return-type/selection lookup.
    let mut types: BTreeMap<String, &Value> = BTreeMap::new();
    if let Some(list) = schema.get("types").and_then(Value::as_array) {
        for t in list {
            if let Some(name) = t.get("name").and_then(Value::as_str) {
                types.insert(name.to_string(), t);
            }
        }
    }

    let mut exchanges = Vec::new();
    let mut warnings = Vec::new();

    for (root_key, keyword) in [("queryType", "query"), ("mutationType", "mutation")] {
        let Some(root_name) = schema
            .get(root_key)
            .and_then(|r| r.get("name"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        let Some(root) = types.get(root_name) else {
            warnings.push(format!("{root_key} `{root_name}` not found in types"));
            continue;
        };
        let Some(fields) = root.get("fields").and_then(Value::as_array) else {
            continue;
        };
        for field in fields {
            if exchanges.len() >= MAX_OPERATIONS {
                warnings.push(format!("stopped at {MAX_OPERATIONS} operations"));
                break;
            }
            if let Some(req) = build_operation(endpoint, keyword, field, &types) {
                exchanges.push(HttpExchange::new(req, Source::Import));
            }
        }
    }

    if exchanges.is_empty() {
        warnings.push("no Query/Mutation fields found".to_string());
    }
    Ok(ImportResult {
        format: "graphql",
        exchanges,
        warnings,
    })
}

/// Build one operation request for a root field.
fn build_operation(
    endpoint: &str,
    keyword: &str,
    field: &Value,
    types: &BTreeMap<String, &Value>,
) -> Option<HttpRequest> {
    let name = field.get("name").and_then(Value::as_str)?;

    // Arguments → variable declarations + the call argument list + variables map.
    let mut var_decls: Vec<String> = Vec::new();
    let mut call_args: Vec<String> = Vec::new();
    let mut variables = Map::new();
    if let Some(args) = field.get("args").and_then(Value::as_array) {
        for arg in args.iter().take(MAX_ARGS) {
            let Some(arg_name) = arg.get("name").and_then(Value::as_str) else {
                continue;
            };
            let type_ref = arg.get("type");
            let type_str = render_type(type_ref);
            var_decls.push(format!("${arg_name}: {type_str}"));
            call_args.push(format!("{arg_name}: ${arg_name}"));
            variables.insert(arg_name.to_string(), scalar_placeholder(type_ref));
        }
    }

    // Selection set from the return type's object fields (one level of scalars).
    let selection = selection_set(field.get("type"), types);

    let decl = if var_decls.is_empty() {
        String::new()
    } else {
        format!("({})", var_decls.join(", "))
    };
    let call = if call_args.is_empty() {
        String::new()
    } else {
        format!("({})", call_args.join(", "))
    };
    let query = format!("{keyword} {name}{decl} {{ {name}{call}{selection} }}");

    let body = json!({ "query": query, "variables": Value::Object(variables) });
    let mut req = HttpRequest::get(endpoint);
    req.method = "POST".to_string();
    req.headers.push("Content-Type", "application/json");
    req.body = Body::from_text(body.to_string());
    Some(req)
}

/// A one-level selection set (` { a b __typename }`) for a field's return type,
/// or empty when it resolves to a scalar/enum (no sub-selection allowed).
fn selection_set(type_ref: Option<&Value>, types: &BTreeMap<String, &Value>) -> String {
    let Some(named) = named_type(type_ref) else {
        return String::new();
    };
    let Some(def) = types.get(&named) else {
        return String::new();
    };
    match def.get("kind").and_then(Value::as_str) {
        Some("OBJECT") | Some("INTERFACE") => {}
        _ => return String::new(), // SCALAR/ENUM/UNION → no sub-selection
    }
    let mut fields: Vec<String> = Vec::new();
    if let Some(list) = def.get("fields").and_then(Value::as_array) {
        for f in list.iter().take(MAX_SELECTION) {
            let Some(fname) = f.get("name").and_then(Value::as_str) else {
                continue;
            };
            // Only select sub-fields that are themselves scalar/enum AND take no
            // required args, so the generated query stays valid without nesting.
            if field_takes_required_args(f) {
                continue;
            }
            // Read the leaf kind from the field's own type ref: built-in scalars
            // (ID/String/Int/…) are not always present in `types`, so looking
            // them up there would wrongly drop them.
            if let Some(kind) = leaf_kind(f.get("type")) {
                if kind == "SCALAR" || kind == "ENUM" {
                    fields.push(fname.to_string());
                }
            }
        }
    }
    fields.push("__typename".to_string());
    format!(" {{ {} }}", fields.join(" "))
}

/// Whether a field declares any non-null argument (which would make a bare
/// selection invalid).
fn field_takes_required_args(field: &Value) -> bool {
    field
        .get("args")
        .and_then(Value::as_array)
        .map(|args| {
            args.iter()
                .any(|a| a.get("type").and_then(|t| t.get("kind")).and_then(Value::as_str) == Some("NON_NULL"))
        })
        .unwrap_or(false)
}

/// The `kind` of a type's leaf (innermost named type), read straight from the
/// introspection type ref after unwrapping NON_NULL/LIST wrappers. Does not
/// consult the `types` map, so built-in scalars resolve correctly.
fn leaf_kind(type_ref: Option<&Value>) -> Option<String> {
    let mut cur = type_ref?;
    for _ in 0..16 {
        let named = cur
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|n| !n.is_empty());
        if named {
            return cur.get("kind").and_then(Value::as_str).map(str::to_string);
        }
        cur = cur.get("ofType")?;
    }
    None
}

/// The underlying named type, unwrapping NON_NULL/LIST `ofType` wrappers.
fn named_type(type_ref: Option<&Value>) -> Option<String> {
    let mut cur = type_ref?;
    for _ in 0..16 {
        if let Some(name) = cur.get("name").and_then(Value::as_str) {
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
        cur = cur.get("ofType")?;
    }
    None
}

/// Reconstruct a GraphQL type string (`[ID!]!`) from an introspection type ref.
fn render_type(type_ref: Option<&Value>) -> String {
    match type_ref {
        None => "String".to_string(),
        Some(t) => match t.get("kind").and_then(Value::as_str) {
            Some("NON_NULL") => format!("{}!", render_type(t.get("ofType"))),
            Some("LIST") => format!("[{}]", render_type(t.get("ofType"))),
            _ => t
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("String")
                .to_string(),
        },
    }
}

/// A placeholder variable value for an argument, by its underlying scalar type.
fn scalar_placeholder(type_ref: Option<&Value>) -> Value {
    match named_type(type_ref).as_deref() {
        Some("Int") => json!(1),
        Some("Float") => json!(1.0),
        Some("Boolean") => json!(true),
        // ID/String and every custom/unknown scalar → a string.
        _ => json!("1"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTROSPECTION: &str = r#"{
      "data": { "__schema": {
        "queryType": { "name": "Query" },
        "mutationType": { "name": "Mutation" },
        "types": [
          { "kind": "OBJECT", "name": "Query", "fields": [
            { "name": "user",
              "args": [ { "name": "id", "type": { "kind": "NON_NULL", "ofType": { "kind": "SCALAR", "name": "ID" } } } ],
              "type": { "kind": "OBJECT", "name": "User" } }
          ] },
          { "kind": "OBJECT", "name": "Mutation", "fields": [
            { "name": "deleteUser",
              "args": [ { "name": "id", "type": { "kind": "SCALAR", "name": "ID" } } ],
              "type": { "kind": "SCALAR", "name": "Boolean" } }
          ] },
          { "kind": "OBJECT", "name": "User", "fields": [
            { "name": "id", "args": [], "type": { "kind": "SCALAR", "name": "ID" } },
            { "name": "name", "args": [], "type": { "kind": "SCALAR", "name": "String" } },
            { "name": "friends", "args": [], "type": { "kind": "LIST", "ofType": { "kind": "OBJECT", "name": "User" } } }
          ] }
        ]
      } }
    }"#;

    #[test]
    fn generates_query_and_mutation_operations() {
        let result = import_graphql(INTROSPECTION, "https://api.test/graphql").unwrap();
        assert_eq!(result.format, "graphql");
        assert_eq!(result.exchanges.len(), 2);

        let query = result
            .exchanges
            .iter()
            .find(|e| e.request.body.as_text().contains("query user"))
            .expect("query operation");
        assert_eq!(query.request.method, "POST");
        assert_eq!(query.request.url, "https://api.test/graphql");
        let body: Value = serde_json::from_str(&query.request.body.as_text()).unwrap();
        let q = body["query"].as_str().unwrap();
        // Arg becomes a typed variable; scalar sub-fields are selected, the
        // nested object field (friends) is not.
        assert!(q.contains("query user($id: ID!)"), "{q}");
        // Scalar sub-fields are selected; the nested object field (friends) is
        // not. Assert the exact selection set, not incidental substrings.
        assert!(q.contains("user(id: $id) { id name __typename }"), "{q}");
        assert!(!q.contains("friends"), "{q}");
        assert_eq!(body["variables"]["id"], "1");

        let mutation = result
            .exchanges
            .iter()
            .find(|e| e.request.body.as_text().contains("mutation deleteUser"))
            .expect("mutation operation");
        let body: Value = serde_json::from_str(&mutation.request.body.as_text()).unwrap();
        // Scalar return type → no sub-selection (just the single operation body
        // braces, so exactly one `{`).
        let mq = body["query"].as_str().unwrap();
        assert_eq!(mq.matches('{').count(), 1, "scalar return must not nest a selection: {mq}");
    }

    #[test]
    fn schema_without_data_wrapper_is_accepted() {
        let spec = r#"{ "__schema": { "queryType": { "name": "Q" }, "types": [
            { "kind": "OBJECT", "name": "Q", "fields": [ { "name": "ping", "args": [], "type": { "kind": "SCALAR", "name": "String" } } ] }
        ] } }"#;
        let result = import_graphql(spec, "https://x.test/graphql").unwrap();
        assert_eq!(result.exchanges.len(), 1);
    }

    #[test]
    fn not_an_introspection_result_is_unsupported() {
        assert!(matches!(
            import_graphql(r#"{"hello":"world"}"#, "https://x.test/graphql"),
            Err(ImportError::Unsupported(_))
        ));
    }

    #[test]
    fn invalid_json_is_a_parse_error() {
        assert!(matches!(
            import_graphql("{bad", "https://x.test/graphql"),
            Err(ImportError::Parse(_))
        ));
    }
}

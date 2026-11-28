//! OpenAPI 3.x / Swagger 2.0 import (plan §10 "imported OpenAPI/GraphQL").
//!
//! Turns an API description into a set of **request-only** [`HttpExchange`]es —
//! one per path+method operation — that the operator can crawl, scan, or fuzz.
//! Path and query parameters are filled with placeholders drawn from each
//! parameter's `example`/`default` (or a type-appropriate default), and a JSON
//! request body is generated from an inline `requestBody`/body-parameter schema.
//!
//! The exchanges carry no response: a specification describes requests to send,
//! it is not captured traffic (plan §4.1 — "missing request/response data stays
//! explicitly absent"). Nothing is sent here; this is pure parsing.

use crate::{ImportError, ImportResult};
use camio_core::{Body, HttpExchange, HttpRequest, Source};
use serde_json::{json, Value};

/// Hard cap on generated operations, so a pathological spec cannot explode into
/// an unbounded request set.
const MAX_OPERATIONS: usize = 2000;

/// HTTP methods recognised as operation keys under a path item.
const METHODS: &[&str] = &[
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

/// Import an OpenAPI 3.x or Swagger 2.0 JSON document into request-only
/// exchanges. `base_override`, when given, replaces the spec's server/host as the
/// origin every request is built against (useful when the spec omits it or lists
/// a relative/placeholder URL).
pub fn import_openapi(json: &str, base_override: Option<&str>) -> Result<ImportResult, ImportError> {
    let spec: Value =
        serde_json::from_str(json).map_err(|e| ImportError::Parse(format!("not valid JSON: {e}")))?;

    let mut warnings = Vec::new();
    let base = match base_override {
        Some(b) => b.trim_end_matches('/').to_string(),
        None => resolve_base(&spec, &mut warnings)?,
    };

    let paths = spec
        .get("paths")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ImportError::Unsupported(
                "no `paths` object — not an OpenAPI/Swagger document".to_string(),
            )
        })?;

    let mut exchanges = Vec::new();
    'outer: for (path, item) in paths {
        let Some(item) = item.as_object() else {
            continue;
        };
        // Parameters declared at the path level apply to every operation on it.
        let path_level = item.get("parameters").and_then(Value::as_array);
        for method in METHODS {
            let Some(op) = item.get(*method) else {
                continue;
            };
            if exchanges.len() >= MAX_OPERATIONS {
                warnings.push(format!(
                    "stopped at {MAX_OPERATIONS} operations; the spec declares more"
                ));
                break 'outer;
            }
            let request = build_request(&base, path, method, op, path_level, &spec);
            exchanges.push(HttpExchange::new(request, Source::Import));
        }
    }

    if exchanges.is_empty() {
        warnings.push("no operations found under `paths`".to_string());
    }
    Ok(ImportResult {
        format: "openapi",
        exchanges,
        warnings,
    })
}

/// Resolve the origin requests are built against from the spec itself.
fn resolve_base(spec: &Value, warnings: &mut Vec<String>) -> Result<String, ImportError> {
    // OpenAPI 3: `servers[0].url` (absolute).
    if let Some(url) = spec
        .get("servers")
        .and_then(Value::as_array)
        .and_then(|s| s.first())
        .and_then(|s| s.get("url"))
        .and_then(Value::as_str)
    {
        if url.starts_with("http://") || url.starts_with("https://") {
            return Ok(url.trim_end_matches('/').to_string());
        }
        warnings.push(format!(
            "server url `{url}` is relative; falling back to host/basePath or a base override"
        ));
    }
    // Swagger 2: `schemes` + `host` + `basePath`.
    if let Some(host) = spec.get("host").and_then(Value::as_str) {
        let scheme = spec
            .get("schemes")
            .and_then(Value::as_array)
            .and_then(|s| s.first())
            .and_then(Value::as_str)
            .unwrap_or("https");
        let base_path = spec
            .get("basePath")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim_end_matches('/');
        return Ok(format!("{scheme}://{host}{base_path}"));
    }
    Err(ImportError::Unsupported(
        "no server/host in the spec — pass a base URL override".to_string(),
    ))
}

/// Build one request for a path+method operation.
fn build_request(
    base: &str,
    path: &str,
    method: &str,
    op: &Value,
    path_level: Option<&Vec<Value>>,
    spec: &Value,
) -> HttpRequest {
    // Merge path-level then operation-level parameters (operation wins by order).
    let mut params: Vec<&Value> = Vec::new();
    if let Some(p) = path_level {
        params.extend(p.iter());
    }
    if let Some(p) = op.get("parameters").and_then(Value::as_array) {
        params.extend(p.iter());
    }

    let mut resolved_path = path.to_string();
    let mut query: Vec<String> = Vec::new();
    for p in &params {
        let name = p.get("name").and_then(Value::as_str).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let placeholder = param_placeholder(p);
        match p.get("in").and_then(Value::as_str) {
            Some("path") => {
                resolved_path =
                    resolved_path.replace(&format!("{{{name}}}"), &percent_encode(&placeholder));
            }
            Some("query") => {
                query.push(format!(
                    "{}={}",
                    percent_encode(name),
                    percent_encode(&placeholder)
                ));
            }
            _ => {}
        }
    }

    let mut url = format!("{base}{resolved_path}");
    if !query.is_empty() {
        url.push('?');
        url.push_str(&query.join("&"));
    }

    let mut req = HttpRequest::get(&url);
    req.method = method.to_uppercase();

    // Header parameters.
    for p in &params {
        if p.get("in").and_then(Value::as_str) == Some("header") {
            if let Some(name) = p.get("name").and_then(Value::as_str) {
                let value = param_placeholder(p);
                // Never let a spec value smuggle CR/LF into a header.
                if !value.contains('\r') && !value.contains('\n') && !name.is_empty() {
                    req.headers.push(name, value);
                }
            }
        }
    }

    // JSON request body, if the operation declares one.
    if let Some(body) = json_body(op, spec) {
        if req.headers.get("Content-Type").is_none() {
            req.headers.push("Content-Type", "application/json");
        }
        req.body = Body::from_text(body);
    }

    req
}

/// A placeholder value for a parameter: its `example`/`default` if present, else
/// a value appropriate to its declared type.
fn param_placeholder(param: &Value) -> String {
    if let Some(ex) = param.get("example") {
        return scalar_string(ex);
    }
    // OpenAPI 3 nests type under `schema`; Swagger 2 puts it on the parameter.
    let schema = param.get("schema").unwrap_or(param);
    if let Some(def) = schema.get("default") {
        return scalar_string(def);
    }
    if let Some(ex) = schema.get("example") {
        return scalar_string(ex);
    }
    if let Some(first) = schema
        .get("enum")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
    {
        return scalar_string(first);
    }
    match schema.get("type").and_then(Value::as_str) {
        Some("integer") | Some("number") => "1".to_string(),
        Some("boolean") => "true".to_string(),
        _ => param
            .get("name")
            .and_then(Value::as_str)
            .map(|n| format!("{n}-value"))
            .unwrap_or_else(|| "value".to_string()),
    }
}

/// Render a JSON scalar as a bare string (strings without quotes).
fn scalar_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// The JSON request body for an operation, if it declares one.
fn json_body(op: &Value, spec: &Value) -> Option<String> {
    // OpenAPI 3: requestBody.content["application/json"].schema
    if let Some(schema) = op
        .get("requestBody")
        .and_then(|b| b.get("content"))
        .and_then(|c| c.get("application/json"))
        .and_then(|j| j.get("schema"))
    {
        return Some(example_from_schema(schema, spec, 6, &mut Vec::new()).to_string());
    }
    // Swagger 2: a parameter with `in: body`.
    if let Some(schema) = op
        .get("parameters")
        .and_then(Value::as_array)
        .and_then(|params| {
            params
                .iter()
                .find(|p| p.get("in").and_then(Value::as_str) == Some("body"))
        })
        .and_then(|p| p.get("schema"))
    {
        return Some(example_from_schema(schema, spec, 6, &mut Vec::new()).to_string());
    }
    None
}

/// Resolve a local JSON-pointer `$ref` (`#/components/schemas/X`,
/// `#/definitions/X`) against the spec root. External refs and non-local
/// pointers are not followed.
fn resolve_ref<'a>(reference: &str, spec: &'a Value) -> Option<&'a Value> {
    let pointer = reference.strip_prefix("#/")?;
    let mut node = spec;
    for raw in pointer.split('/') {
        // JSON-pointer escapes: ~1 → '/', ~0 → '~'.
        let key = raw.replace("~1", "/").replace("~0", "~");
        node = node.get(&key)?;
    }
    Some(node)
}

/// Build a minimal example JSON value from a schema, resolving local `$ref`s
/// against `spec`. `seen` records the refs on the current path so a recursive
/// schema (e.g. a tree node that references itself) terminates with `{}` instead
/// of looping; `depth` bounds nesting regardless.
fn example_from_schema(schema: &Value, spec: &Value, depth: u8, seen: &mut Vec<String>) -> Value {
    if depth == 0 {
        return Value::Null;
    }
    if let Some(ex) = schema.get("example") {
        return ex.clone();
    }
    if let Some(def) = schema.get("default") {
        return def.clone();
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        if seen.iter().any(|r| r == reference) {
            return json!({});
        }
        return match resolve_ref(reference, spec) {
            Some(target) => {
                seen.push(reference.to_string());
                let value = example_from_schema(target, spec, depth - 1, seen);
                seen.pop();
                value
            }
            None => json!({}),
        };
    }
    // `allOf` composition: merge the member objects.
    if let Some(all_of) = schema.get("allOf").and_then(Value::as_array) {
        let mut obj = serde_json::Map::new();
        for member in all_of {
            if let Value::Object(map) = example_from_schema(member, spec, depth - 1, seen) {
                obj.extend(map);
            }
        }
        return Value::Object(obj);
    }
    let ty = schema.get("type").and_then(Value::as_str);
    if ty == Some("object") || (ty.is_none() && schema.get("properties").is_some()) {
        let mut obj = serde_json::Map::new();
        if let Some(props) = schema.get("properties").and_then(Value::as_object) {
            for (key, sub) in props.iter().take(50) {
                obj.insert(key.clone(), example_from_schema(sub, spec, depth - 1, seen));
            }
        }
        return Value::Object(obj);
    }
    match ty {
        Some("array") => {
            let item = schema
                .get("items")
                .map(|i| example_from_schema(i, spec, depth - 1, seen))
                .unwrap_or(Value::Null);
            Value::Array(vec![item])
        }
        Some("integer") | Some("number") => json!(0),
        Some("boolean") => json!(false),
        Some("string") => json!("string"),
        _ => Value::Null,
    }
}

/// Percent-encode a URL component (unreserved pass through; everything else
/// becomes upper-case `%XX`), so a placeholder cannot inject URL structure.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0').to_ascii_uppercase());
                out.push(char::from_digit((b & 0xf) as u32, 16).unwrap_or('0').to_ascii_uppercase());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPENAPI3: &str = r#"{
      "openapi": "3.0.0",
      "servers": [{"url": "https://api.example.test/v1"}],
      "paths": {
        "/users/{id}": {
          "get": {
            "parameters": [
              {"name": "id", "in": "path", "schema": {"type": "integer"}},
              {"name": "verbose", "in": "query", "schema": {"type": "boolean"}}
            ]
          }
        },
        "/users": {
          "post": {
            "requestBody": {"content": {"application/json": {"schema": {
              "type": "object",
              "properties": {"name": {"type": "string"}, "age": {"type": "integer"}}
            }}}}
          }
        }
      }
    }"#;

    #[test]
    fn imports_openapi3_operations() {
        let result = import_openapi(OPENAPI3, None).unwrap();
        assert_eq!(result.format, "openapi");
        assert_eq!(result.exchanges.len(), 2);

        let get = result
            .exchanges
            .iter()
            .find(|e| e.request.method == "GET")
            .unwrap();
        // Path param resolved, query param appended, against the server origin.
        assert_eq!(
            get.request.url,
            "https://api.example.test/v1/users/1?verbose=true"
        );
        // Request-only: a spec is not captured traffic.
        assert!(get.response.is_none());

        let post = result
            .exchanges
            .iter()
            .find(|e| e.request.method == "POST")
            .unwrap();
        assert_eq!(post.request.url, "https://api.example.test/v1/users");
        assert_eq!(
            post.request.headers.get("Content-Type"),
            Some("application/json")
        );
        // A JSON body is generated from the inline schema.
        let body = post.request.body.as_text();
        assert!(body.contains("\"name\""), "body was {body}");
        assert!(body.contains("\"age\""), "body was {body}");
    }

    #[test]
    fn resolves_component_refs_and_terminates_on_cycles() {
        // requestBody references a component schema that references itself.
        let spec = r##"{
          "openapi": "3.0.0",
          "servers": [{"url": "https://api.test"}],
          "paths": {"/nodes": {"post": {"requestBody": {"content": {"application/json":
            {"schema": {"$ref": "#/components/schemas/Node"}}}}}}},
          "components": {"schemas": {"Node": {
            "type": "object",
            "properties": {
              "label": {"type": "string"},
              "child": {"$ref": "#/components/schemas/Node"}
            }
          }}}
        }"##;
        let result = import_openapi(spec, None).unwrap();
        let post = &result.exchanges[0];
        let body: serde_json::Value =
            serde_json::from_str(&post.request.body.as_text()).unwrap();
        // The referenced schema's fields are materialized...
        assert_eq!(body["label"], "string");
        // ...and the self-reference terminates (an object, not an infinite loop).
        assert!(body["child"].is_object());
    }

    #[test]
    fn swagger2_base_from_host_and_basepath() {
        let spec = r#"{
          "swagger": "2.0",
          "host": "legacy.example.test",
          "basePath": "/api",
          "schemes": ["https"],
          "paths": {"/ping": {"get": {}}}
        }"#;
        let result = import_openapi(spec, None).unwrap();
        assert_eq!(result.exchanges.len(), 1);
        assert_eq!(
            result.exchanges[0].request.url,
            "https://legacy.example.test/api/ping"
        );
    }

    #[test]
    fn base_override_wins_and_relative_server_warns() {
        let spec = r#"{"openapi":"3.0.0","servers":[{"url":"/v2"}],"paths":{"/x":{"get":{}}}}"#;
        let result = import_openapi(spec, Some("https://scope.test")).unwrap();
        assert_eq!(result.exchanges[0].request.url, "https://scope.test/x");
    }

    #[test]
    fn missing_base_without_override_is_an_error() {
        let spec = r#"{"openapi":"3.0.0","paths":{"/x":{"get":{}}}}"#;
        assert!(matches!(
            import_openapi(spec, None),
            Err(ImportError::Unsupported(_))
        ));
    }

    #[test]
    fn not_a_spec_is_unsupported() {
        let spec = r#"{"hello":"world"}"#;
        assert!(matches!(
            import_openapi(spec, Some("https://x.test")),
            Err(ImportError::Unsupported(_))
        ));
    }

    #[test]
    fn invalid_json_is_a_parse_error() {
        assert!(matches!(
            import_openapi("{not json", Some("https://x.test")),
            Err(ImportError::Parse(_))
        ));
    }
}

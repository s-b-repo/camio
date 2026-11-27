//! GraphQL-introspection check (plan §8 "Scan & crawl").
//!
//! A GraphQL endpoint that answers introspection queries lets anyone enumerate
//! the entire type system — every type, field and operation — which is a
//! substantial aid to attacking the API. This fires when the response body
//! carries introspection data (`"__schema"`/`"__type"`), or when a request to a
//! `…/graphql` endpoint carrying a query gets a `2xx` JSON response (a live,
//! query-answering endpoint). Severity [`Severity::Medium`], [`Confidence::Firm`].

use crate::checks::{content_type, finding, is_2xx};
use crate::PassiveCheck;
use camio_core::{Confidence, Finding, HttpExchange, Severity};

/// Flags GraphQL introspection data / live query-answering GraphQL endpoints.
pub struct GraphqlIntrospection;

impl PassiveCheck for GraphqlIntrospection {
    fn id(&self) -> &'static str {
        "graphql-introspection"
    }

    fn title(&self) -> &'static str {
        "GraphQL introspection enabled"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn check(&self, ex: &HttpExchange) -> Vec<Finding> {
        let Some(resp) = &ex.response else {
            return Vec::new();
        };
        let body = resp.body.as_text();

        // A server with introspection *disabled* answers with an `errors` array
        // that names `__schema` ("Cannot query field \"__schema\"") — that is
        // the opposite of an exposed schema, so it must not match. Only an
        // actual introspection *result* counts.
        let has_errors = body.contains("\"errors\"");
        let introspection = !has_errors
            && (body.contains("\"__schema\"") || body.contains("\"__type\""))
            && (body.contains("\"types\"") || body.contains("\"queryType\""));

        // A `…/graphql` endpoint that answered a query with a 2xx JSON response.
        // This shows a live endpoint, not necessarily an open one: it is a
        // tentative observation, never a firm "introspection enabled" claim.
        let is_json = content_type(resp)
            .map(|ct| ct.to_ascii_lowercase().contains("json"))
            .unwrap_or(false);
        let query_endpoint = ex.request.path().to_ascii_lowercase().ends_with("/graphql")
            && is_2xx(resp)
            && is_json
            && !has_errors
            && ex.request.body.as_text().contains("query");

        if introspection {
            return vec![finding(
                "GraphQL introspection enabled",
                Severity::Medium,
                Confidence::Firm,
                "The GraphQL endpoint returns full schema introspection data (`__schema` with the type system), which lets anyone enumerate every type and operation. Disable introspection in production and require authentication on the GraphQL endpoint.",
                ex.id,
            )];
        }
        if query_endpoint {
            return vec![finding(
                "GraphQL endpoint answers arbitrary queries",
                Severity::Low,
                Confidence::Tentative,
                "A `/graphql` endpoint answered a `query` with a 2xx JSON response. This shows a live endpoint that executes queries without erroring; it does not by itself prove introspection is enabled. Verify whether the endpoint requires authentication and whether introspection is disabled.",
                ex.id,
            )];
        }

        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn exchange(url: &str, req_body: &str, status: u16, ct: &str, resp_body: &str) -> HttpExchange {
        let mut req = HttpRequest::get(url);
        if !req_body.is_empty() {
            req.method = "POST".into();
            req.headers.push("Content-Type", "application/json");
            req.body = Body::from_text(req_body);
        }
        let mut h = HeaderList::new();
        h.push("Content-Type", ct);
        let resp = HttpResponse {
            status,
            version: HttpVersion::Http11,
            reason: None,
            headers: h,
            body: Body::from_text(resp_body),
        };
        HttpExchange::new(req, Source::Scanner).with_response(resp)
    }

    #[test]
    fn flags_introspection_response_body() {
        let ex = exchange(
            "https://api.test/graphql",
            "",
            200,
            "application/json",
            r#"{"data":{"__schema":{"types":[{"name":"User"}]}}}"#,
        );
        let f = GraphqlIntrospection.check(&ex);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].title, "GraphQL introspection enabled");
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[0].confidence, Confidence::Firm);
    }

    #[test]
    fn flags_live_graphql_query_endpoint() {
        let ex = exchange(
            "https://api.test/graphql",
            r#"{"query":"{ me { id } }"}"#,
            200,
            "application/json",
            r#"{"data":{"me":{"id":1}}}"#,
        );
        assert_eq!(GraphqlIntrospection.check(&ex).len(), 1);
    }

    #[test]
    fn graphql_path_without_query_or_non_2xx_does_not_fire() {
        // 400 response (query rejected) and no query body → not flagged.
        let ex = exchange(
            "https://api.test/graphql",
            "",
            400,
            "application/json",
            r#"{"errors":[{"message":"must provide query"}]}"#,
        );
        assert!(GraphqlIntrospection.check(&ex).is_empty());
    }

    #[test]
    fn ordinary_json_without_introspection_does_not_fire() {
        let ex = exchange(
            "https://api.test/users",
            "",
            200,
            "application/json",
            r#"{"data":{"users":[]}}"#,
        );
        assert!(GraphqlIntrospection.check(&ex).is_empty());
    }

    #[test]
    fn no_response_no_findings() {
        let ex = HttpExchange::new(
            HttpRequest::get("https://api.test/graphql"),
            Source::Scanner,
        );
        assert!(GraphqlIntrospection.check(&ex).is_empty());
    }
}

#[cfg(test)]
mod regression_tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn exchange(url: &str, req_body: &str, status: u16, ct: &str, resp_body: &str) -> HttpExchange {
        let mut req = HttpRequest::get(url);
        if !req_body.is_empty() {
            req.method = "POST".into();
            req.headers.push("Content-Type", "application/json");
            req.body = Body::from_text(req_body.to_string());
        }
        let mut h = HeaderList::new();
        h.push("Content-Type", ct);
        let resp = HttpResponse {
            status,
            version: HttpVersion::Http11,
            reason: None,
            headers: h,
            body: Body::from_text(resp_body),
        };
        HttpExchange::new(req, Source::Scanner).with_response(resp)
    }

    #[test]
    fn introspection_disabled_error_is_not_a_finding() {
        // "Cannot query field \"__schema\"" is the *disabled* answer; the old
        // check reported it as "introspection enabled" at Medium/Firm.
        let ex = exchange(
            "https://api.test/graphql",
            r#"{"query":"{ __schema { types { name } } }"}"#,
            200,
            "application/json",
            r#"{"errors":[{"message":"Cannot query field \"__schema\" on type \"Query\"."}]}"#,
        );
        assert!(GraphqlIntrospection.check(&ex).is_empty());
    }

    #[test]
    fn a_real_introspection_result_is_firm() {
        let ex = exchange(
            "https://api.test/graphql",
            r#"{"query":"{ __schema { types { name } } }"}"#,
            200,
            "application/json",
            r#"{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"User","kind":"OBJECT"}]}}}"#,
        );
        let f = GraphqlIntrospection.check(&ex);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[0].confidence, Confidence::Firm);
    }
}

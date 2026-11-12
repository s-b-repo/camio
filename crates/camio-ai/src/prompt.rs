//! Pure workbench prompt builders (plan §11: "summarizing project data and
//! proposing actions").
//!
//! Each builder returns a `Vec<Message>` — a `system` message that sets the
//! model's role and an instruction, followed by a `user` message with the
//! concrete input. They are pure (no I/O, no model call) so they can be unit
//! tested directly and composed by callers before a single request is sent.
//!
//! Raw request/response dumps are bounded with [`crate::truncate_chars`] so a
//! large body cannot blow up the prompt (and, in turn, the model's context).

use camio_core::HttpExchange;

use crate::message::Message;
use crate::truncate_chars;

/// Upper bound (characters) on each raw request/response dump placed in a prompt.
const RAW_DUMP_MAX: usize = 8000;

/// Ask the model to explain one HTTP exchange from a security standpoint.
///
/// `system` casts the model as a security analyst; `user` carries the raw
/// request and (when present) the raw response via
/// [`HttpExchange::raw`](camio_core::HttpRequest::raw)-style dumps, each bounded
/// to [`RAW_DUMP_MAX`] characters.
pub fn explain_exchange(ex: &HttpExchange) -> Vec<Message> {
    let system = "You are a web application security analyst reviewing captured HTTP traffic. \
Given one request/response exchange, give a concise, security-focused explanation: \
what the endpoint appears to do, any notable authentication, session, or input-handling \
behavior, and concrete risks worth testing. Be specific and do not invent fields that are \
not present in the data.";

    let mut user = String::from(
        "Analyze this HTTP exchange and summarize its security-relevant behavior.\n\n\
=== REQUEST ===\n",
    );
    user.push_str(&truncate_chars(&ex.request.raw(), RAW_DUMP_MAX));
    user.push_str("\n\n=== RESPONSE ===\n");
    match &ex.response {
        Some(resp) => user.push_str(&truncate_chars(&resp.raw(), RAW_DUMP_MAX)),
        None => user.push_str("(no response captured)"),
    }

    vec![Message::system(system), Message::user(user)]
}

/// Ask the model to propose the next tests given a summary of findings/history.
///
/// `context` is a caller-produced summary (findings, interesting endpoints,
/// prior results); it is bounded to [`RAW_DUMP_MAX`] characters.
pub fn suggest_tests(context: &str) -> Vec<Message> {
    let system =
        "You are a web security testing assistant helping a tester decide what to do next. \
Given a summary of findings and request history, propose a short, prioritized list of concrete \
next tests: the endpoint or parameter to target, the technique, and what a positive result would \
look like. Prefer high-signal, low-noise tests and respect that testing must stay in scope.";

    let user = format!(
        "Here is the current project context (findings and history summary):\n\n{}\n\n\
Propose the next tests to run.",
        truncate_chars(context, RAW_DUMP_MAX)
    );

    vec![Message::system(system), Message::user(user)]
}

/// Ask the model to translate a natural-language request into a CamioQL query.
///
/// The `system` prompt pins the model to output **only** a CamioQL query and
/// gives it worked examples of the `namespace.field.operator:value` grammar
/// (plan §7.1); `user` is the natural-language request.
pub fn nl_to_camioql(nl: &str) -> Vec<Message> {
    let system = "You translate a tester's natural-language request into a single CamioQL query \
and output ONLY that query — no prose, no code fences, no explanation.\n\
CamioQL clauses are `namespace.field.operator:value`, combined with AND / OR / NOT and \
parentheses. Namespaces are `req` and `resp` (plus top-level `source`, `scope`, `id`). \
String operators: eq, ne, cont, ncont, like, nlike, regex. Numeric operators: eq, ne, gt, \
gte, lt, lte.\n\
Examples:\n\
- requests to an API host that returned a server error:\n  \
resp.code.gte:500 AND req.host.cont:\"api\"\n\
- JavaScript files served from example.com:\n  \
req.ext.eq:\".js\" AND req.host.cont:\"example\"\n\
- POST requests whose response mentions a password:\n  \
req.method.eq:\"POST\" AND resp.body.cont:\"password\"\n\
- admin paths that returned 200 OK:\n  \
req.path.cont:\"/admin\" AND resp.code.eq:200";

    let user = format!("Natural-language request:\n{nl}\n\nCamioQL:");

    vec![Message::system(system), Message::user(user)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn exchange_with_response() -> HttpExchange {
        let mut req = HttpRequest::get("https://api.example.com/v1/login");
        req.method = "POST".to_string();
        req.headers.push("Host", "api.example.com");
        req.headers.push("Content-Type", "application/json");
        req.body = Body::from_text(r#"{"user":"a","pass":"b"}"#);

        let mut headers = HeaderList::new();
        headers.push("Content-Type", "application/json");
        headers.push("Set-Cookie", "sid=abc; HttpOnly");
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: Some("OK".to_string()),
            headers,
            body: Body::from_text(r#"{"token":"xyz"}"#),
        };
        HttpExchange::new(req, Source::Replay).with_response(resp)
    }

    #[test]
    fn explain_exchange_builds_system_and_user() {
        let msgs = explain_exchange(&exchange_with_response());
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].role, "system");
        assert_eq!(msgs[1].role, "user");
        assert!(msgs[0].content.to_lowercase().contains("security"));
        // User content carries both halves of the exchange.
        assert!(msgs[1].content.contains("=== REQUEST ==="));
        assert!(msgs[1].content.contains("=== RESPONSE ==="));
        assert!(msgs[1].content.contains("POST /v1/login"));
        assert!(msgs[1].content.contains("Set-Cookie"));
    }

    #[test]
    fn explain_exchange_notes_missing_response() {
        let req = HttpRequest::get("https://example.com/");
        let ex = HttpExchange::new(req, Source::Replay);
        let msgs = explain_exchange(&ex);
        assert!(msgs[1].content.contains("(no response captured)"));
    }

    #[test]
    fn explain_exchange_bounds_huge_bodies() {
        let mut req = HttpRequest::get("https://example.com/big");
        req.body = Body::from_text("A".repeat(50_000));
        let ex = HttpExchange::new(req, Source::Replay);
        let msgs = explain_exchange(&ex);
        // The whole user message must be far smaller than the raw 50k body:
        // one bounded dump (~8000) plus the response placeholder and framing.
        assert!(
            msgs[1].content.chars().count() < RAW_DUMP_MAX + 500,
            "prompt not bounded: {} chars",
            msgs[1].content.chars().count()
        );
        assert!(msgs[1].content.contains("[truncated]"));
    }

    #[test]
    fn suggest_tests_builds_system_and_user_with_context() {
        let msgs = suggest_tests("Found reflected XSS on /search?q=");
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].role, "system");
        assert_eq!(msgs[1].role, "user");
        assert!(msgs[1]
            .content
            .contains("Found reflected XSS on /search?q="));
    }

    #[test]
    fn nl_to_camioql_builds_pair_with_examples() {
        let msgs = nl_to_camioql("show me 500s from the api host");
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].role, "system");
        assert_eq!(msgs[1].role, "user");
        // System prompt instructs query-only output and includes CamioQL examples.
        assert!(msgs[0].content.contains("ONLY"));
        assert!(msgs[0].content.contains("resp.code.gte:500"));
        assert!(msgs[0].content.contains("req.host.cont"));
        // User prompt carries the natural-language request.
        assert!(msgs[1].content.contains("show me 500s from the api host"));
    }
}

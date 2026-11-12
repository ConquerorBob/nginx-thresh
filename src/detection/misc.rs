//! Malformed requests: null bytes, CRLF injection and structurally invalid
//! protocol / method / header values.

use super::rule::{excerpt, InspectionContext, RuleSpec};
use crate::model::threat::{Category, RuleHit};

const BAD_PROTOCOL: RuleSpec = RuleSpec::custom(
    "MALF-001",
    "Unrecognised HTTP protocol token",
    Category::MalformedRequest,
    5,
);

const BAD_METHOD: RuleSpec = RuleSpec::custom(
    "MALF-002",
    "Malformed HTTP method token",
    Category::MalformedRequest,
    6,
);

const HEADER_INJECTION: RuleSpec = RuleSpec::custom(
    "MALF-003",
    "CRLF injection in a request header",
    Category::MalformedRequest,
    5,
);

const LONG_TARGET: RuleSpec = RuleSpec::custom(
    "MALF-004",
    "Excessively long request target",
    Category::MalformedRequest,
    3,
);

pub const SPECS: &[RuleSpec] = &[
    RuleSpec::raw(
        "NULL-001",
        "Encoded null byte in request target",
        "null_byte_encoded",
        Category::MalformedRequest,
        5,
        r"%00",
    ),
    RuleSpec::target(
        "NULL-002",
        "Decoded null byte in request target",
        "null_byte_decoded",
        Category::MalformedRequest,
        5,
        r"\x00",
    ),
    RuleSpec::raw(
        "CRLF-001",
        "Encoded CRLF sequence in request target",
        "crlf_encoded",
        Category::MalformedRequest,
        5,
        r"%0d%0a|%0a%0d",
    ),
    RuleSpec::target(
        "CRLF-002",
        "Decoded CRLF sequence in request target",
        "crlf_decoded",
        Category::MalformedRequest,
        5,
        r"\r\n|\n\r",
    ),
    BAD_PROTOCOL,
    BAD_METHOD,
    HEADER_INJECTION,
    LONG_TARGET,
];

const ALLOWED_PROTOCOLS: &[&str] = &[
    "http/1.0",
    "http/1.1",
    "http/2",
    "http/2.0",
    "http/3",
    "http/3.0",
    "quic",
];

/// Manual checks for this family: protocol, method and header structure.
pub fn check(ctx: &InspectionContext<'_>) -> Vec<RuleHit> {
    let mut hits = Vec::new();
    let entry = ctx.entry;

    let protocol = entry.protocol.trim();
    if !protocol.is_empty()
        && protocol != "-"
        && !ALLOWED_PROTOCOLS
            .iter()
            .any(|allowed| protocol.eq_ignore_ascii_case(allowed))
    {
        hits.push(BAD_PROTOCOL.hit(format!(
            "protocol '{}' on '{}'",
            excerpt(protocol),
            excerpt(&ctx.path_lower)
        )));
    }

    let method = entry.method.trim();
    let method_bad = !method.is_empty()
        && method != "-"
        && (method.len() > 32
            || !method
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    if method_bad {
        hits.push(BAD_METHOD.hit(format!(
            "method '{}' on '{}'",
            excerpt(method),
            excerpt(&ctx.path_lower)
        )));
    }

    let injected = |value: Option<&str>| {
        value.is_some_and(|text| text.chars().any(|ch| ch == '\r' || ch == '\n'))
    };
    if injected(entry.user_agent.as_deref()) || injected(entry.referer.as_deref()) {
        hits.push(HEADER_INJECTION.hit(format!(
            "crlf in header for '{}'",
            excerpt(&ctx.path_lower)
        )));
    }

    if entry.path.len() > 4096 {
        hits.push(LONG_TARGET.hit(format!(
            "request target of {} bytes",
            entry.path.len()
        )));
    }

    hits
}

#[cfg(test)]
mod tests {
    use super::super::test_util::{assert_clean, assert_hit, entry};

    #[test]
    fn detects_null_bytes() {
        assert_hit(&entry("/index.php%00.jpg"), "NULL-001");
        assert_hit(&entry("/index.php%00.jpg"), "NULL-002");
        assert_hit(&entry("/upload?name=shell.php%00.txt"), "NULL-001");
    }

    #[test]
    fn detects_crlf_injection() {
        assert_hit(&entry("/?x=%0d%0aSet-Cookie:a=b"), "CRLF-001");
        assert_hit(&entry("/?x=%0d%0aSet-Cookie:a=b"), "CRLF-002");
        assert_hit(&entry("/?x=%0a%0dX:1"), "CRLF-001");
    }

    #[test]
    fn detects_bad_protocol_and_method() {
        let mut bad_protocol = entry("/");
        bad_protocol.protocol = "HTTP/9.9".to_string();
        assert_hit(&bad_protocol, "MALF-001");

        let mut bad_method = entry("/");
        bad_method.method = "GET /x".to_string();
        assert_hit(&bad_method, "MALF-002");

        let mut injected = entry("/");
        injected.user_agent = Some("agent\r\nX-Forwarded-For: 127.0.0.1".to_string());
        assert_hit(&injected, "MALF-003");
    }

    #[test]
    fn detects_oversized_target() {
        let long = format!("/{}", "a".repeat(5000));
        assert_hit(&entry(&long), "MALF-004");
    }

    #[test]
    fn tolerates_parser_placeholders() {
        // The parser represents degenerate request lines with "-" fields; they
        // must not be reported as malformed by the engine.
        let mut placeholder = entry("-");
        placeholder.method = "-".to_string();
        placeholder.protocol = "-".to_string();
        assert_clean(&placeholder);
    }

    #[test]
    fn ignores_valid_requests() {
        assert_clean(&entry("/"));
        assert_clean(&entry("/api/v1/items?page=2"));
        assert_clean(&entry("/assets/app.css"));
    }
}

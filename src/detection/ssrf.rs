//! Server-side request forgery: URL-bearing parameters aimed at internal
//! hosts, cloud metadata endpoints and non-HTTP schemes.

use super::rule::RuleSpec;
use crate::model::threat::Category;

pub const SPECS: &[RuleSpec] = &[
    // Informational only: this fires when a URL-fetch parameter carries an
    // absolute URL whose host is an IP literal or has no dot (internal
    // naming). Ordinary public CDN/checkout/OAuth links are normal traffic and
    // must not produce an SSRF event; host-aware rules (SSRF-003/004/005/009)
    // carry the real severity for internal targets.
    RuleSpec::target(
        "SSRF-001",
        "URL-fetch parameter pointing at an IP or dotless host",
        "ssrf_url_param",
        Category::Ssrf,
        2,
        r"[?&](?:url|uri|dest|destination|target|proxy|fetch|callback|callback_url|image|img|src|source|webhook|feed|host|site|domain|open|out|view)=https?://(?:\[[0-9a-f:.]+\]|\d{1,3}(?:\.\d{1,3}){1,3}|[^/?#&:.\s]+(?:[/?#&:]|$))",
    ),
    RuleSpec::target(
        "SSRF-002",
        "URL parameter with a scheme-relative URL",
        "ssrf_scheme_relative",
        Category::Ssrf,
        3,
        r"[?&](?:url|uri|dest|destination|target|proxy|fetch|callback|image|webhook|host)=//",
    ),
    RuleSpec::target(
        "SSRF-003",
        "Loopback host in a URL",
        "ssrf_loopback",
        Category::Ssrf,
        7,
        r"(?:https?://|//|@)(?:127\.\d{1,3}(?:\.\d{1,3}){0,2}|0\.0\.0\.0|localhost|\[::1\])",
    ),
    RuleSpec::target(
        "SSRF-004",
        "Private network host in a URL",
        "ssrf_private_network",
        Category::Ssrf,
        7,
        r"(?:https?://|//|@)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})",
    ),
    RuleSpec::target(
        "SSRF-005",
        "Cloud metadata endpoint",
        "ssrf_cloud_metadata",
        Category::Ssrf,
        9,
        r"(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|169\.254\.170\.2|fd00:ec2::254|metadata\.azure)",
    ),
    RuleSpec::target(
        "SSRF-006",
        "Dangerous URL scheme",
        "ssrf_dangerous_scheme",
        Category::Ssrf,
        8,
        r"(?:^|[?&=])(?:file|gopher|dict|ftp|ldap|tftp|jar|netdoc)://",
    ),
    RuleSpec::target(
        "SSRF-007",
        "URL parameter aimed at an internal service port",
        "ssrf_internal_port",
        Category::Ssrf,
        8,
        r"[?&](?:url|dest|destination|target|proxy|fetch|callback|webhook|host)=[^&\s]*:(?:22|23|25|445|1433|3306|5432|6379|9200|11211)\b",
    ),
    RuleSpec::target(
        "SSRF-008",
        "Obfuscated loopback address",
        "ssrf_obfuscated_loopback",
        Category::Ssrf,
        8,
        r"https?://(?:0x7f|2130706433|0177\.0)",
    ),
    RuleSpec::target(
        "SSRF-009",
        "Host parameter pointing at an internal address",
        "ssrf_internal_host_param",
        Category::Ssrf,
        8,
        r"[?&](?:host|url|dest|destination|target|proxy|fetch|callback|webhook|image|link|site)=[^&\s]*(?:127\.\d{1,3}(?:\.\d{1,3}){0,2}|localhost|\[::1\]|192\.168\.|10\.\d{1,3}\.|169\.254)",
    ),
];

#[cfg(test)]
mod tests {
    use super::super::test_util::{assert_clean, assert_hit, assert_no_category, entry, hits};
    use crate::model::threat::Category;

    #[test]
    fn detects_url_parameters() {
        assert_hit(
            &entry("/?url=http://169.254.169.254/latest/meta-data/"),
            "SSRF-001",
        );
        assert_hit(
            &entry("/?url=http://169.254.169.254/latest/meta-data/"),
            "SSRF-005",
        );
        assert_hit(&entry("/?dest=gopher://127.0.0.1:6379/_INFO"), "SSRF-006");
        assert_hit(&entry("/?target=file:///etc/passwd"), "SSRF-006");
    }

    #[test]
    fn scheme_relative_fetch_parameter_is_informational() {
        let found = hits(&entry("/?url=//cdn.example.com/image.png"));
        let ssrf = found
            .iter()
            .find(|hit| hit.rule_id == "SSRF-002")
            .expect("scheme-relative fetch parameter");
        assert_eq!(ssrf.severity, 3);
        assert_clean(&entry("/checkout?next=//shop.example.com/checkout"));
    }

    #[test]
    fn detects_internal_hosts() {
        assert_hit(&entry("/?url=http://127.0.0.1:8080/admin"), "SSRF-003");
        assert_hit(&entry("/?url=http://localhost/admin"), "SSRF-003");
        // Short-form loopback (127.0.0.1 written as 127.1) must still fire.
        assert_hit(&entry("/?url=http://127.1/"), "SSRF-003");
        assert_hit(&entry("/?url=http://127.1/"), "SSRF-009");
        assert_hit(&entry("/?url=http://192.168.1.1/"), "SSRF-004");
        assert_hit(&entry("/?url=http://10.0.0.5:6379/"), "SSRF-007");
        assert_hit(&entry("/?url=127.0.0.1:8080"), "SSRF-009");
        assert_hit(&entry("/?url=http://2130706433/"), "SSRF-008");
    }

    #[test]
    fn detects_metadata_service() {
        assert_hit(&entry("/proxy?url=http://metadata.google.internal/"), "SSRF-005");
        assert_hit(&entry("/proxy?url=http://100.100.100.200/latest/"), "SSRF-005");
        assert_hit(&entry("/proxy?host=169.254.169.254"), "SSRF-009");
    }

    /// Regression for the report's FP-1: routine checkout, OAuth, docs and CDN
    /// links are public absolute URLs and must not be reported as SSRF.
    #[test]
    fn public_absolute_urls_are_not_ssrf() {
        for path in [
            "/checkout?next=https://shop.example.com/checkout",
            "/account?return_url=https://shop.example.com/account",
            "/start?redirect=https://docs.example.com/start",
            "/img?url=https://cdn.example.com/image.png",
        ] {
            assert_no_category(&entry(path), Category::Ssrf);
        }
    }

    /// The demoted rule still reports an IP-literal / dotless-host URL, but
    /// only at informational severity.
    #[test]
    fn url_param_rule_is_informational() {
        let found = hits(&entry("/?image=http://intranet/app"));
        let rule = found
            .iter()
            .find(|hit| hit.rule_id == "SSRF-001")
            .expect("SSRF-001 should fire for a dotless host");
        assert!(rule.severity <= 2, "severity {}", rule.severity);
    }

    #[test]
    fn ignores_benign_requests() {
        let clean = [
            "/api/v1/proxy-settings",
            "/images/logo.png",
            "/search?q=localhost+setup+guide",
            "/blog/what-is-ssrf",
            "/product?next=https://shop.example.com/p/42",
            "/oauth/callback?redirect_uri=https://app.example.com/home",
        ];
        for path in clean {
            assert_no_category(&entry(path), Category::Ssrf);
        }
        // Normal browser traffic on a URL-bearing parameter must stay clean.
        assert_no_category(
            &entry("/img?url=https://cdn.example.com/hero.webp"),
            Category::Ssrf,
        );
    }
}

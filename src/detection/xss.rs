//! Cross-site scripting: script tags, event handlers, `javascript:` URIs and
//! DOM cookie access, in raw and percent-encoded form.

use super::rule::RuleSpec;
use crate::model::threat::Category;

pub const SPECS: &[RuleSpec] = &[
    RuleSpec::target(
        "XSS-001",
        "Script tag injection",
        "script_tag",
        Category::CrossSiteScripting,
        5,
        r"<script",
    ),
    RuleSpec::target(
        "XSS-002",
        "Script tag close sequence",
        "script_close",
        Category::CrossSiteScripting,
        5,
        r"</script",
    ),
    RuleSpec::raw(
        "XSS-003",
        "Percent-encoded script tag",
        "encoded_script_tag",
        Category::CrossSiteScripting,
        5,
        r"%3cscript|%3c%2fscript",
    ),
    RuleSpec::target(
        "XSS-004",
        "Inline event handler",
        "event_handler",
        Category::CrossSiteScripting,
        5,
        r"\bon(?:animation|beforetoggle|blur|change|click|context|copy|cut|dblclick|drag|drop|error|focus|formdata|input|invalid|key|load|mouse|paste|pointer|reset|resize|scroll|select|submit|toggle|touch|transition|wheel)[a-z]*\s*=",
    ),
    RuleSpec::target(
        "XSS-005",
        "javascript: URI",
        "javascript_uri",
        Category::CrossSiteScripting,
        5,
        r"javascript:",
    ),
    RuleSpec::target(
        "XSS-006",
        "DOM document access",
        "dom_document_access",
        Category::CrossSiteScripting,
        6,
        r"document\.(?:cookie|domain|location|write|referrer)",
    ),
    RuleSpec::target(
        "XSS-007",
        "SVG onload handler",
        "svg_onload",
        Category::CrossSiteScripting,
        6,
        r"<svg[^>]*\bonload\s*=",
    ),
    RuleSpec::target(
        "XSS-008",
        "Cookie theft via alert(document.cookie)",
        "cookie_theft",
        Category::CrossSiteScripting,
        6,
        r"alert\s*\(\s*document\.cookie",
    ),
    RuleSpec::raw(
        "XSS-009",
        "Percent-encoded HTML tag",
        "encoded_html_tag",
        Category::CrossSiteScripting,
        5,
        r"%3c(?:img|svg|iframe|body|input|details|marquee|video|audio|object|embed)",
    ),
    RuleSpec::target(
        "XSS-010",
        "Iframe with script payload",
        "iframe_injection",
        Category::CrossSiteScripting,
        6,
        r#"<iframe[^>]*(?:src\s*=\s*['"]?javascript:|onload\s*=)"#,
    ),
    RuleSpec::target(
        "XSS-011",
        "CSS expression() payload",
        "css_expression",
        Category::CrossSiteScripting,
        6,
        r#"style\s*=\s*['"]?[^'"]*expression\s*\("#,
    ),
    // Attacker-controlled headers: reported at low severity because they are
    // rarely reflected server-side.
    RuleSpec::user_agent(
        "XSS-012",
        "Script payload in User-Agent",
        "xss_in_user_agent",
        Category::CrossSiteScripting,
        4,
        r"(?:<script|onerror\s*=|javascript:)",
    ),
    RuleSpec::referer(
        "XSS-013",
        "Script payload in Referer",
        "xss_in_referer",
        Category::CrossSiteScripting,
        4,
        r"(?:<script|onerror\s*=|javascript:)",
    ),
];

#[cfg(test)]
mod tests {
    use super::super::test_util::{
        assert_clean, assert_hit, assert_no_category, entry, entry_ua,
    };
    use crate::model::threat::Category;

    #[test]
    fn detects_script_tags() {
        assert_hit(&entry("/?q=<script>alert(1)</script>"), "XSS-001");
        assert_hit(&entry("/?q=<script>alert(1)</script>"), "XSS-002");
        assert_hit(&entry("/?q=%3Cscript%3Ealert(1)%3C/script%3E"), "XSS-003");
        assert_hit(&entry("/?q=%3CSVG%20onload=alert(1)%3E"), "XSS-009");
    }

    #[test]
    fn detects_event_handlers_and_uris() {
        assert_hit(&entry("/?q=<img src=x onerror=alert(1)>"), "XSS-004");
        assert_hit(&entry("/?q=<body onload=alert(1)>"), "XSS-004");
        assert_hit(&entry("/?q=javascript:alert(1)"), "XSS-005");
        assert_hit(&entry("/?q=<svg/onload=alert(1)>"), "XSS-007");
        assert_hit(&entry("/?q=<iframe src=\"javascript:alert(1)\">"), "XSS-010");
    }

    /// Regression for the report's FN-6: pointer / touch / animation handlers
    /// were missing from the closed list.
    #[test]
    fn detects_expanded_event_handler_families() {
        assert_hit(&entry("/?q=<div ontouchmove=alert(1)>"), "XSS-004");
        assert_hit(&entry("/?q=<div onpointerdown=alert(1)>"), "XSS-004");
        assert_hit(&entry("/?q=<div onanimationiteration=alert(1)>"), "XSS-004");
        assert_hit(&entry("/?q=<div ontransitionrun=alert(1)>"), "XSS-004");
        assert_hit(&entry("/?q=<div ondragstart=alert(1)>"), "XSS-004");
        assert_hit(&entry("/?q=<div oncontextmenu=alert(1)>"), "XSS-004");
        assert_hit(&entry("/?q=<div onwheel=alert(1)>"), "XSS-004");
        assert_hit(&entry("/?q=<div onscroll=alert(1)>"), "XSS-004");
    }

    #[test]
    fn detects_script_payloads_in_headers() {
        assert_hit(&entry_ua("/", "<script>alert(1)</script>"), "XSS-012");
        assert_hit(&entry_ua("/", "Mozilla/5.0 onerror=alert(1)"), "XSS-012");

        let mut referer = entry("/");
        referer.referer = Some("http://evil.example/?q=<script>alert(1)</script>".to_string());
        assert_hit(&referer, "XSS-013");

        let mut js_ref = entry("/");
        js_ref.referer = Some("javascript:alert(document.cookie)".to_string());
        assert_hit(&js_ref, "XSS-013");
    }

    #[test]
    fn benign_header_values_have_no_xss_hits() {
        for agent in [
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "curl/8.7.1",
        ] {
            assert_no_category(&entry_ua("/", agent), Category::CrossSiteScripting);
        }
        let mut referer = entry("/");
        referer.referer =
            Some("https://example.com/blog/javascript-framework-comparison".to_string());
        assert_no_category(&referer, Category::CrossSiteScripting);
    }

    #[test]
    fn detects_cookie_theft_and_css_payloads() {
        assert_hit(&entry("/?q=javascript:alert(document.cookie)"), "XSS-008");
        assert_hit(&entry("/?q=javascript:alert(document.cookie)"), "XSS-006");
        assert_hit(&entry("/?q=<div style=\"width:expression(alert(1))\">"), "XSS-011");
    }

    #[test]
    fn ignores_benign_content() {
        assert_clean(&entry("/blog/understanding-cross-site-scripting"));
        assert_clean(&entry("/search?q=javascript+framework+comparison"));
        assert_clean(&entry("/docs/html-script-tag-reference"));
        assert_clean(&entry("/assets/js/app.js?v=2"));
    }
}

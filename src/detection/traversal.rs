//! Path traversal: `../` chains, their encoded / double-encoded forms and
//! traversal aimed at well-known sensitive files.

use super::rule::RuleSpec;
use crate::model::threat::Category;

pub const SPECS: &[RuleSpec] = &[
    RuleSpec::target(
        "TRAV-001",
        "Path traversal (../)",
        "traversal_dotdot",
        Category::PathTraversal,
        7,
        r"\.\./",
    ),
    RuleSpec::target(
        "TRAV-002",
        "Path traversal (..\\)",
        "traversal_dotdot_backslash",
        Category::PathTraversal,
        7,
        r"\.\.\\",
    ),
    RuleSpec::raw(
        "TRAV-003",
        "Percent-encoded path traversal",
        "traversal_encoded",
        Category::PathTraversal,
        7,
        r"%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c|\.\.%5c",
    ),
    RuleSpec::raw(
        "TRAV-004",
        "Double-encoded path traversal",
        "traversal_double_encoded",
        Category::PathTraversal,
        8,
        r"%252e%252e%252f|%252e%252e%2f|%252e%252e%255c|%252e%252e%5c",
    ),
    RuleSpec::target(
        "TRAV-005",
        "Obfuscated traversal (....//)",
        "traversal_obfuscated",
        Category::PathTraversal,
        8,
        r"\.{4,}//?",
    ),
    RuleSpec::target(
        "TRAV-006",
        "Traversal into a sensitive directory",
        "traversal_to_sensitive",
        Category::PathTraversal,
        9,
        r"(?:\.\./|\.\.\\)[^?\s]*(?:etc/|proc/|windows/|winnt/|boot\.ini|win\.ini|var/log|root/|home/[a-z0-9])",
    ),
    RuleSpec::target(
        "TRAV-007",
        "Direct access to a sensitive system path",
        "traversal_sensitive_path",
        Category::PathTraversal,
        9,
        r"(?:^|/)(?:etc/(?:passwd|shadow|group|hosts|sudoers)|proc/self/(?:environ|cmdline|fd/)|windows/win\.ini|boot\.ini)",
    ),
    RuleSpec::raw(
        "TRAV-008",
        "Encoded traversal into /etc or /proc",
        "traversal_encoded_sensitive",
        Category::PathTraversal,
        9,
        r"(?:%2e%2e|\.\.)(?:%2f|/|%5c|\\)[^?\s]*(?:etc|proc|windows|winnt)",
    ),
    // Java servlet / Tomcat path-parameter bypass: `..;` is normalised to `..`
    // by many containers even though it is not a real parent reference.
    RuleSpec::target(
        "TRAV-009",
        "Traversal with a path-parameter separator",
        "traversal_dotdot_semicolon",
        Category::PathTraversal,
        6,
        r"\.\.;",
    ),
    // Overlong UTF-8 encodings decode to U+FFFD, so no `../` ever appears in
    // the decoded view; the encoded bytes must be matched on the raw target.
    RuleSpec::raw(
        "TRAV-010",
        "Overlong UTF-8 traversal encoding",
        "traversal_overlong_utf8",
        Category::PathTraversal,
        6,
        r"%c0%ae|%c0%af|%c1%9c",
    ),
    RuleSpec::referer(
        "TRAV-011",
        "Path traversal in Referer",
        "traversal_in_referer",
        Category::PathTraversal,
        5,
        r"\.\./|%2e%2e",
    ),
    RuleSpec::user_agent(
        "TRAV-012",
        "Path traversal in User-Agent",
        "traversal_in_user_agent",
        Category::PathTraversal,
        5,
        r"\.\./|%2e%2e",
    ),
];

#[cfg(test)]
mod tests {
    use super::super::test_util::{
        assert_clean, assert_hit, assert_no_category, entry, entry_ua,
    };
    use crate::model::threat::Category;

    #[test]
    fn detects_traversal_in_user_agent() {
        assert_hit(
            &entry_ua("/", "Mozilla/5.0 ../../etc/passwd"),
            "TRAV-012",
        );
        assert_hit(
            &entry_ua("/", "Mozilla/5.0 %2e%2e%2fetc/passwd"),
            "TRAV-012",
        );
        assert_clean(&entry_ua("/", "Mozilla/5.0 (X11; Linux x86_64) Firefox/133.0"));
    }

    #[test]
    fn detects_plain_and_encoded_traversal() {
        assert_hit(&entry("/../../etc/passwd"), "TRAV-001");
        assert_hit(&entry("/../../etc/passwd"), "TRAV-006");
        assert_hit(&entry("/documents/../../../etc/shadow"), "TRAV-001");
        assert_hit(&entry("/download?file=..%2f..%2fetc%2fpasswd"), "TRAV-003");
        assert_hit(&entry("/download?file=..%5c..%5cwindows%5cwin.ini"), "TRAV-003");
    }

    #[test]
    fn detects_double_encoded_and_case_variants() {
        // Mixed case escapes must still be caught: haystacks are lowercased.
        assert_hit(&entry("/%2E%2E%2Fetc%2Fpasswd"), "TRAV-003");
        assert_hit(&entry("/%252e%252e%252fetc/passwd"), "TRAV-004");
        assert_hit(&entry("/%252E%252E%252Fetc/passwd"), "TRAV-004");
        assert_hit(&entry("/download?file=%252e%252e%252fetc/passwd"), "TRAV-004");
    }

    #[test]
    fn detects_obfuscated_and_sensitive_targets() {
        assert_hit(&entry("/....//....//etc/passwd"), "TRAV-005");
        assert_hit(&entry("/..\\..\\windows\\win.ini"), "TRAV-002");
        assert_hit(&entry("/../../windows/win.ini"), "TRAV-006");
        assert_hit(&entry("/etc/passwd"), "TRAV-007");
        assert_hit(&entry("/proc/self/environ"), "TRAV-007");
        assert_hit(&entry("/..%2f..%2fetc%2fpasswd"), "TRAV-008");
    }

    /// Regression for the report's FN-5: path-parameter and overlong UTF-8
    /// traversal variants were invisible.
    #[test]
    fn detects_path_parameter_and_overlong_traversal() {
        assert_hit(&entry("/..;/..;/config.php"), "TRAV-009");
        assert_hit(&entry("/..;/WEB-INF/web.xml"), "TRAV-009");
        assert_hit(&entry("/..%c0%af..%c0%afetc/passwd"), "TRAV-010");
        assert_hit(&entry("/..%c0%ae..%c0%aeetc/passwd"), "TRAV-010");
        assert_hit(&entry("/..%c1%9c..%c1%9cetc/passwd"), "TRAV-010");
    }

    #[test]
    fn detects_traversal_in_referer() {
        let mut referer = entry("/");
        referer.referer = Some("http://evil.example/../../etc/passwd".to_string());
        assert_hit(&referer, "TRAV-011");

        let mut encoded = entry("/");
        encoded.referer = Some("http://evil.example/%2e%2e/%2e%2e/admin".to_string());
        assert_hit(&encoded, "TRAV-011");
    }

    #[test]
    fn benign_referers_have_no_traversal_hits() {
        let mut referer = entry("/");
        referer.referer = Some("https://www.google.com/search?q=path+traversal".to_string());
        assert_no_category(&referer, Category::PathTraversal);

        let mut docs = entry("/");
        docs.referer = Some("https://example.com/docs/getting-started".to_string());
        assert_no_category(&docs, Category::PathTraversal);
    }

    #[test]
    fn ignores_benign_paths() {
        assert_clean(&entry("/assets/js/app.min.js"));
        assert_clean(&entry("/products/v1.2/reviews"));
        assert_clean(&entry("/search?q=how+to+go+back+again"));
        assert_clean(&entry("/download?file=report..final.pdf"));
    }
}

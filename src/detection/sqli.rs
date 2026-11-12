//! SQL injection: tautologies, UNION/stacked queries, time-based and
//! error-based probes, file access and command execution via SQL.

use super::rule::RuleSpec;
use crate::model::threat::Category;

pub const SPECS: &[RuleSpec] = &[
    RuleSpec::target(
        "SQLI-001",
        "UNION SELECT injection",
        "union_select",
        Category::SqlInjection,
        9,
        r"\bunion\b[\s(]+(?:all[\s(]+)?select\b",
    ),
    RuleSpec::target(
        "SQLI-002",
        "SELECT ... FROM statement",
        "select_from",
        Category::SqlInjection,
        8,
        r"\bselect\s+(?:\*|\d+|\w+\s*,\s*\w+)[^;]*\bfrom\b",
    ),
    RuleSpec::target(
        "SQLI-003",
        "OR 1=1 tautology",
        "or_one_equals_one",
        Category::SqlInjection,
        9,
        r"\bor\s+1\s*=\s*1\b",
    ),
    RuleSpec::target(
        "SQLI-004",
        "Quoted OR tautology",
        "quoted_or_tautology",
        Category::SqlInjection,
        9,
        r#"['"]\s*or\s*['"][^'"]{0,15}['"]\s*=\s*['"]"#,
    ),
    RuleSpec::target(
        "SQLI-005",
        "AND 1=1 tautology",
        "and_one_equals_one",
        Category::SqlInjection,
        8,
        r"\band\s+1\s*=\s*1\b",
    ),
    RuleSpec::target(
        "SQLI-006",
        "Time-based injection function",
        "sleep_function",
        Category::SqlInjection,
        9,
        r"\b(?:sleep|pg_sleep|benchmark)\s*\(\s*\d",
    ),
    RuleSpec::target(
        "SQLI-007",
        "WAITFOR DELAY time-based injection",
        "waitfor_delay",
        Category::SqlInjection,
        9,
        r"\bwaitfor\s+delay\s+'?\d",
    ),
    RuleSpec::target(
        "SQLI-008",
        "Database metadata enumeration",
        "db_metadata",
        Category::SqlInjection,
        9,
        r"\b(?:information_schema|pg_catalog|sysobjects|syscolumns|mysql\.user|all_tables)\b",
    ),
    RuleSpec::target(
        "SQLI-009",
        "INTO OUTFILE / DUMPFILE",
        "into_outfile",
        Category::SqlInjection,
        9,
        r"\binto\s+(?:out|dump)file\b",
    ),
    RuleSpec::target(
        "SQLI-010",
        "LOAD_FILE file read",
        "load_file",
        Category::SqlInjection,
        9,
        r"\bload_file\s*\(",
    ),
    RuleSpec::target(
        "SQLI-011",
        "Error-based injection function",
        "error_based",
        Category::SqlInjection,
        8,
        r"\b(?:extractvalue|updatexml)\s*\(",
    ),
    RuleSpec::target(
        "SQLI-012",
        "Destructive DDL statement",
        "ddl_table",
        Category::SqlInjection,
        8,
        r"\b(?:drop|truncate|alter)\s+table\b",
    ),
    RuleSpec::target(
        "SQLI-013",
        "MSSQL extended procedure",
        "mssql_procedure",
        Category::SqlInjection,
        9,
        r"\b(?:xp_cmdshell|sp_executesql|sp_oacreate)\b",
    ),
    RuleSpec::target(
        "SQLI-014",
        "Numeric literal followed by a comment",
        "quote_comment",
        Category::SqlInjection,
        8,
        r#"\d['"]\s*(?:--|#|/\*)"#,
    ),
    RuleSpec::target(
        "SQLI-015",
        "Stacked query after semicolon",
        "stacked_query",
        Category::SqlInjection,
        8,
        r";\s*(?:select|insert|update|delete|drop|create|exec|declare)\b",
    ),
    // Numeric-value probes that do not need a keyword: the quote-only and
    // comment-only forms used by every scanner's first request.
    RuleSpec::target(
        "SQLI-016",
        "Numeric parameter value closed with a quote",
        "numeric_quote",
        Category::SqlInjection,
        3,
        r"[?&][a-z0-9_.-]+=\d+'(?:$|[&\s)#;]|--)",
    ),
    RuleSpec::target(
        "SQLI-017",
        "Numeric value followed by a comment",
        "numeric_comment",
        Category::SqlInjection,
        4,
        r"\b\d+\s*(?:--|#)(?:[\s&]|$)",
    ),
    RuleSpec::target(
        "SQLI-018",
        "Numeric OR / AND tautology",
        "numeric_tautology",
        Category::SqlInjection,
        4,
        r"\b\d+\s+(?:or|and)\s+\d+\s*=\s*\d+",
    ),
    // Attacker-controlled headers: lower severity than the request target
    // because they are rarely reflected server-side.
    RuleSpec::user_agent(
        "SQLI-019",
        "SQL injection indicator in User-Agent",
        "sqli_in_user_agent",
        Category::SqlInjection,
        6,
        r#"(?:union[\s(]+(?:all[\s(]+)?select\b|['"]\s*or\s*['"]?\s*\d+['\"]?\s*=\s*['"]?\s*\d+|\bor\s+1\s*=\s*1\b|\band\s+1\s*=\s*1\b|\b(?:sleep|pg_sleep|benchmark)\s*\(|\binformation_schema\b|\bxp_cmdshell\b)"#,
    ),
    RuleSpec::referer(
        "SQLI-020",
        "SQL injection indicator in Referer",
        "sqli_in_referer",
        Category::SqlInjection,
        6,
        r#"(?:union[\s(]+(?:all[\s(]+)?select\b|['"]\s*or\s*['"]?\s*\d+['\"]?\s*=\s*['"]?\s*\d+|\bor\s+1\s*=\s*1\b|\band\s+1\s*=\s*1\b|\b(?:sleep|pg_sleep|benchmark)\s*\(|\binformation_schema\b|\bxp_cmdshell\b)"#,
    ),
];

#[cfg(test)]
mod tests {
    use super::super::test_util::{
        assert_clean, assert_hit, assert_no_category, entry, entry_ua,
    };
    use crate::model::threat::Category;

    #[test]
    fn detects_union_and_select_statements() {
        assert_hit(
            &entry("/product?id=1+union+select+username,password+from+users"),
            "SQLI-001",
        );
        assert_hit(&entry("/product?id=1+UNION+ALL+SELECT+1,2"), "SQLI-001");
        assert_hit(&entry("/product?q=select+*+from+users"), "SQLI-002");
        assert_hit(&entry("/product?q=select+id,name+from+users"), "SQLI-002");
    }

    #[test]
    fn detects_tautologies_and_comments() {
        assert_hit(&entry("/item?id=1%27%20OR%20%271%27%3D%271"), "SQLI-004");
        assert_hit(&entry("/item?id=1+or+1=1"), "SQLI-003");
        assert_hit(&entry("/item?id=1+and+1=1"), "SQLI-005");
        assert_hit(&entry("/item?id=1%27--"), "SQLI-014");
        assert_hit(&entry("/item?id=1%27%23"), "SQLI-014");
    }

    #[test]
    fn detects_time_based_and_metadata_probes() {
        assert_hit(&entry("/item?id=1;sleep(5)"), "SQLI-006");
        assert_hit(&entry("/item?id=1+and+pg_sleep(5)"), "SQLI-006");
        assert_hit(&entry("/item?id=1%3Bwaitfor+delay+%270%3A0%3A5%27"), "SQLI-007");
        assert_hit(&entry("/api?q=information_schema.tables"), "SQLI-008");
        assert_hit(&entry("/api?q=1+into+outfile+%27/var/www/x.php%27"), "SQLI-009");
        assert_hit(&entry("/api?q=load_file(%27/etc/passwd%27)"), "SQLI-010");
        assert_hit(&entry("/api?q=xp_cmdshell"), "SQLI-013");
        assert_hit(&entry("/api?id=1;drop+table+users"), "SQLI-012");
        assert_hit(&entry("/api?id=1;select+1"), "SQLI-015");
    }

    #[test]
    fn detects_percent_encoded_uppercase_keywords() {
        // `%53` decodes to `S`; the decoded haystack must still be lowercase.
        assert_hit(&entry("/x?q=%53ELECT%20*%20FROM%20users"), "SQLI-002");
        assert_hit(&entry("/x?q=1%20%55NION%20%53ELECT%201,2"), "SQLI-001");
    }

    /// Regression for the report's FN-2: bare quote, bare comment and numeric
    /// tautologies are standard first-request probes.
    #[test]
    fn detects_numeric_probes() {
        assert_hit(&entry("/item?id=1'"), "SQLI-016");
        assert_hit(&entry("/item?id=1%27"), "SQLI-016");
        assert_hit(&entry("/item?id=1'--"), "SQLI-016");
        assert_hit(&entry("/item?id=1--"), "SQLI-017");
        assert_hit(&entry("/item?id=1%23"), "SQLI-017");
        assert_hit(&entry("/item?id=1+OR+2=2"), "SQLI-018");
        assert_hit(&entry("/item?id=42+and+7=7"), "SQLI-018");
    }

    #[test]
    fn numeric_quote_needs_a_closing_context() {
        // A possessive in a search query must not look like a quote probe.
        assert_clean(&entry("/search?q=90's+hits"));
        assert_clean(&entry("/search?q=best+of+the+80's"));
    }

    /// Regression for the report's FN-2: inline comments split keywords and
    /// MySQL versioned comments hide them.
    #[test]
    fn detects_comment_obfuscated_keywords() {
        assert_hit(
            &entry("/?id=1+UN/**/ION+SEL/**/ECT+password+FROM+users"),
            "SQLI-001",
        );
        assert_hit(&entry("/?id=1+/*!50000UNION*/+SELECT+1"), "SQLI-001");
        assert_hit(&entry("/?id=1+union/**/select+1,2"), "SQLI-001");
    }

    #[test]
    fn detects_sql_injection_in_headers() {
        assert_hit(&entry_ua("/", "Mozilla/5.0 ' OR 1=1--"), "SQLI-019");
        assert_hit(&entry_ua("/", "sqlmap' union select 1,2"), "SQLI-019");
        assert_hit(
            &entry_ua("/", "Mozilla/5.0%20%27%20OR%201=1--"),
            "SQLI-019",
        );

        let mut referer = entry("/");
        referer.referer = Some("http://evil.example/?id=1' OR '1'='1".to_string());
        assert_hit(&referer, "SQLI-020");

        let mut time_based = entry("/");
        time_based.referer = Some("http://evil.example/?q=1;select+sleep(5)".to_string());
        assert_hit(&time_based, "SQLI-020");
    }

    #[test]
    fn ignores_benign_header_values() {
        for agent in [
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "curl/8.7.1",
            "python-requests/2.31.0",
            "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0",
        ] {
            assert_no_category(&entry_ua("/", agent), Category::SqlInjection);
        }

        let mut referer = entry("/");
        referer.referer = Some("https://www.google.com/search?q=select+a+size+from+the+list".to_string());
        assert_no_category(&referer, Category::SqlInjection);
    }

    #[test]
    fn ignores_benign_queries() {
        assert_clean(&entry("/articles/selecting-the-best-from-the-list"));
        assert_clean(&entry("/blog/how-to-select-a-plan-from-our-catalog"));
        assert_clean(&entry("/products?category=books&page=2"));
        assert_clean(&entry("/search?q=union+station+select+your+seat"));
        assert_clean(&entry("/search?q=select+a+size+from+the+list"));
        assert_clean(&entry("/search?q=union+station+coffee"));
        assert_clean(&entry("/download?file=release-notes.old"));
        assert_clean(&entry("/products?sort=price&order=desc&page=2"));
    }
}

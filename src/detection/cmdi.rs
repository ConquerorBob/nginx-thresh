//! Command injection: shell metacharacters followed by commands, command
//! substitution, shell binaries and dangerous PHP / Windows helpers.

use super::rule::RuleSpec;
use crate::model::threat::Category;

pub const SPECS: &[RuleSpec] = &[
    RuleSpec::target(
        "CMDI-001",
        "Shell metacharacter followed by a command",
        "shell_metachar_command",
        Category::CommandInjection,
        10,
        r"(?:;|\||&&|\|\|)\s*(?:/bin/|/usr/bin/)?(?:base64|bash|cat|chmod|chown|cmd|cp|curl|dd|dig|env|find|ftp|halt|id|kill|ls|mkfifo|mv|nc|netcat|nohup|nslookup|perl|pkill|powershell|python[0-9.]*|reboot|rm|scp|sh|shutdown|socat|ssh|tar|telnet|tftp|uname|unzip|wget|whoami|xargs|xxd|zip)(?:[\s/<>|&;]|$)",
    ),
    RuleSpec::target(
        "CMDI-002",
        "Backtick command substitution",
        "backtick_substitution",
        Category::CommandInjection,
        10,
        "`[^`\\s]+`",
    ),
    RuleSpec::target(
        "CMDI-003",
        "$() command substitution",
        "dollar_paren_substitution",
        Category::CommandInjection,
        10,
        r"\$\([^)]*\)",
    ),
    RuleSpec::target(
        "CMDI-004",
        "Absolute path to a shell binary",
        "bin_shell_path",
        Category::CommandInjection,
        10,
        r"/(?:bin|usr/bin|usr/local/bin)/(?:ba|z|k|c|da|fi)?sh\b",
    ),
    RuleSpec::target(
        "CMDI-005",
        "Windows shell binary",
        "windows_shell_binary",
        Category::CommandInjection,
        10,
        r"(?:cmd\.exe|powershell(?:\.exe)?)\b",
    ),
    RuleSpec::target(
        "CMDI-006",
        "PHP command execution function",
        "php_exec_function",
        Category::CommandInjection,
        10,
        r"\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(",
    ),
    RuleSpec::target(
        "CMDI-007",
        "certutil / bitsadmin payload download",
        "certutil_bitsadmin",
        Category::CommandInjection,
        10,
        r"\b(?:certutil|bitsadmin)(?:\.exe)?\s+-",
    ),
    RuleSpec::raw(
        "CMDI-008",
        "Encoded newline command injection",
        "encoded_newline_command",
        Category::CommandInjection,
        10,
        r"%0a\s*(?:base64|bash|cat|chmod|chown|cp|curl|dd|id|ls|mv|nc|perl|python|reboot|rm|sh|shutdown|socat|telnet|uname|wget|whoami)\b",
    ),
    RuleSpec::target(
        "CMDI-009",
        "Pipe into a shell",
        "pipe_to_shell",
        Category::CommandInjection,
        10,
        r"\|\s*(?:sudo\s+)?(?:/bin/)?(?:ba|z|k)?sh\b",
    ),
    RuleSpec::target(
        "CMDI-010",
        "Download piped into another command",
        "download_pipe",
        Category::CommandInjection,
        10,
        r"\b(?:wget|curl)\b[^|]*\|",
    ),
    RuleSpec::target(
        "CMDI-011",
        "$IFS field-separator obfuscation",
        "ifs_obfuscation",
        Category::CommandInjection,
        9,
        r"\$\{?ifs\}?",
    ),
    RuleSpec::target(
        "CMDI-012",
        "chmod / chown on a numeric mode",
        "chmod_chown",
        Category::CommandInjection,
        9,
        r"\b(?:chmod|chown)\s+[0-7]{3,4}\b",
    ),
    RuleSpec::target(
        "CMDI-013",
        "Netcat execute flag",
        "netcat_exec",
        Category::CommandInjection,
        10,
        r"\b(?:nc|netcat|ncat)\s+-[a-z]*e\b",
    ),
    RuleSpec::target(
        "CMDI-014",
        "Download into a temporary directory",
        "download_to_tmp",
        Category::CommandInjection,
        9,
        r"\b(?:curl|wget)\s+(?:-o|--output|-O)\s*/?(?:tmp|var/tmp|dev/shm)",
    ),
    RuleSpec::target(
        "CMDI-015",
        "Shell invoked with -c",
        "shell_dash_c",
        Category::CommandInjection,
        9,
        r"\b(?:bash|sh|zsh)\s+-[ic]\b",
    ),
];

#[cfg(test)]
mod tests {
    use super::super::test_util::{assert_clean, assert_hit, entry, entry_full};

    #[test]
    fn detects_separator_injection() {
        assert_hit(&entry("/ping?host=example.com;id"), "CMDI-001");
        assert_hit(&entry("/ping?host=1.2.3.4|whoami"), "CMDI-001");
        assert_hit(&entry("/ping?host=1.2.3.4&&cat%20/etc/passwd"), "CMDI-001");
        assert_hit(&entry("/ping?host=x%0aid"), "CMDI-008");
        assert_hit(&entry("/cgi?x=1|sh"), "CMDI-009");
    }

    /// Regression for the report's FN-4: the command alternation missed every
    /// tool outside a 15-name allowlist.
    #[test]
    fn detects_commands_outside_the_old_allowlist() {
        assert_hit(&entry("/x?q=;rm+-rf+/var/www"), "CMDI-001");
        assert_hit(&entry("/x?q=;rm+-rf+/"), "CMDI-001");
        assert_hit(&entry("/x?q=;shutdown+-h+now"), "CMDI-001");
        assert_hit(&entry("/x?q=;telnet+evil+444"), "CMDI-001");
        assert_hit(&entry("/x?q=;dd+if=/dev/zero+of=/dev/sda"), "CMDI-001");
        assert_hit(&entry("/x?q=;mkfifo+/tmp/f"), "CMDI-001");
        assert_hit(&entry("/x?q=;base64+/etc/passwd"), "CMDI-001");
        assert_hit(&entry("/x?q=;nohup+./x"), "CMDI-001");
        assert_hit(&entry("/x?q=;xargs+rm"), "CMDI-001");
        assert_hit(&entry("/x?q=%0a;shutdown+now"), "CMDI-001");
        // ${IFS} obfuscation keeps working with the wider command list.
        assert_hit(&entry("/x?q=;rm${IFS}-rf${IFS}/var/www"), "CMDI-011");
    }

    #[test]
    fn keeps_benign_matrix_parameters_clean() {
        assert_clean(&entry("/api/v1/orders;jsessionid=abc123"));
        assert_clean(&entry("/shop;jsessionid=9F2A;color=red"));
        assert_clean(&entry("/status?ping=ok&env=production"));
        // Matrix parameters can share a name with a shell command; `;env=`
        // must not look like a shell separator followed by `env`.
        assert_clean(&entry("/shop;env=prod"));
        assert_clean(&entry("/items;cp=2"));
        assert_clean(&entry("/products;id=123"));
        assert_clean(&entry("/items;rm=1"));
    }

    #[test]
    fn detects_substitution_and_shell_binaries() {
        assert_hit(&entry("/x?q=$(id)"), "CMDI-003");
        assert_hit(&entry("/x?q=`id`"), "CMDI-002");
        assert_hit(&entry("/x?f=/bin/bash"), "CMDI-004");
        assert_hit(&entry("/x?f=/usr/local/bin/zsh"), "CMDI-004");
        assert_hit(&entry("/x?f=cmd.exe"), "CMDI-005");
        assert_hit(&entry("/x?f=powershell.exe+-enc+AAA"), "CMDI-005");
    }

    #[test]
    fn detects_php_and_windows_helpers() {
        assert_hit(&entry("/x?f=system('id')"), "CMDI-006");
        assert_hit(&entry("/x?f=shell_exec($_GET['c'])"), "CMDI-006");
        assert_hit(&entry("/x?f=certutil+-urlcache+-f+x"), "CMDI-007");
        assert_hit(&entry("/x?f=chmod+777+/tmp/x"), "CMDI-012");
        assert_hit(&entry("/x?f=nc+-e+/bin/sh"), "CMDI-013");
    }

    #[test]
    fn ignores_benign_parameters() {
        assert_clean(&entry("/api/v1/orders;jsessionid=abc123"));
        assert_clean(&entry("/docs/shell-scripting-guide"));
        assert_clean(&entry("/products?system=online"));
        assert_clean(&entry_full("GET", "/status?ping=ok", "Mozilla/5.0", 200));
    }
}

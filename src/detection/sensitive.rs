//! Sensitive file access: VCS metadata, dotfiles, credentials, editor backups,
//! database dumps and framework configuration.

use super::rule::{excerpt, InspectionContext, RuleSpec};
use crate::model::threat::{Category, RuleHit};

const BACKUP_EXTENSION: RuleSpec = RuleSpec::custom(
    "SENS-015",
    "Editor or backup copy of a file",
    Category::SensitiveFileAccess,
    4,
);

pub const SPECS: &[RuleSpec] = &[
    RuleSpec::target(
        "SENS-001",
        "Environment file",
        "dotenv",
        Category::SensitiveFileAccess,
        5,
        r"(?:^|/)\.env(?:\.[a-z0-9_-]{1,20})?\b",
    ),
    RuleSpec::target(
        "SENS-002",
        "Git metadata file",
        "git_metadata",
        Category::SensitiveFileAccess,
        5,
        r"(?:^|/)\.git/(?:config|head|index|packed-refs|refs|logs|objects|description|info)",
    ),
    RuleSpec::target(
        "SENS-003",
        "Legacy VCS directory",
        "vcs_directory",
        Category::SensitiveFileAccess,
        4,
        r"(?:^|/)\.(?:svn|hg|bzr|cvs)(?:/|$)",
    ),
    RuleSpec::target(
        "SENS-004",
        "SSH private key or key material",
        "ssh_key_material",
        Category::SensitiveFileAccess,
        6,
        r"(?:^|/)\.ssh/(?:id_rsa|id_dsa|id_ecdsa|id_ed25519|authorized_keys|known_hosts|config)",
    ),
    RuleSpec::target(
        "SENS-005",
        "Cloud or tool credentials",
        "credentials_file",
        Category::SensitiveFileAccess,
        6,
        r"(?:^|/)\.aws/credentials|(?:^|/)\.(?:npmrc|netrc|pgpass|my\.cnf)\b",
    ),
    RuleSpec::target(
        "SENS-006",
        "WordPress configuration",
        "wordpress_config",
        Category::SensitiveFileAccess,
        6,
        r"wp-config\.php(?:~|\.(?:bak|old|orig|save|swp|txt|zip))?(?:$|[?#])",
    ),
    RuleSpec::target(
        "SENS-007",
        "Configuration file backup",
        "config_backup",
        Category::SensitiveFileAccess,
        5,
        r"(?:^|/)(?:config|configuration|settings|database|db|web|app|local|prod|secret|secrets)\.(?:php|inc|json|ya?ml|xml|ini|conf)\.(?:bak|old|orig|save|swp|tmp|txt|zip|tar\.gz|gz)",
    ),
    RuleSpec::target(
        "SENS-008",
        "Database dump or archive",
        "sql_dump",
        Category::SensitiveFileAccess,
        5,
        r"(?:^|/)(?:db|dump|database|backup|data|mysql|wordpress|site|www)\.(?:sql|dump|sql\.gz|sql\.zip|tar|tar\.gz|tgz|zip)\b",
    ),
    RuleSpec::target(
        "SENS-009",
        "phpinfo disclosure page",
        "phpinfo",
        Category::SensitiveFileAccess,
        4,
        r"(?:^|/)phpinfo(?:\.php)?\b",
    ),
    RuleSpec::target(
        "SENS-010",
        "Apache per-directory access file",
        "apache_access_file",
        Category::SensitiveFileAccess,
        5,
        r"(?:^|/)\.htaccess\b|(?:^|/)\.htpasswd\b",
    ),
    RuleSpec::target(
        "SENS-011",
        "IIS or Java web configuration",
        "server_config",
        Category::SensitiveFileAccess,
        5,
        r"(?:^|/)web\.config\b|(?:^|/)web-inf/web\.xml\b",
    ),
    RuleSpec::target(
        "SENS-012",
        "macOS .DS_Store metadata",
        "ds_store",
        Category::SensitiveFileAccess,
        2,
        r"(?:^|/)\.ds_store\b",
    ),
    RuleSpec::target(
        "SENS-013",
        "Build and CI definition file",
        "build_definition",
        Category::SensitiveFileAccess,
        3,
        r"(?:^|/)(?:dockerfile|docker-compose\.ya?ml|docker-compose\.override\.ya?ml|\.dockerignore|\.gitlab-ci\.yml|jenkinsfile)\b",
    ),
    RuleSpec::target(
        "SENS-014",
        "Shell history file",
        "shell_history",
        Category::SensitiveFileAccess,
        6,
        r"(?:^|/)\.(?:bash_history|zsh_history|mysql_history|psql_history)\b",
    ),
    RuleSpec::target(
        "SENS-016",
        "Private key file outside .ssh",
        "private_key_file",
        Category::SensitiveFileAccess,
        6,
        r"(?:^|/)id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?\b",
    ),
    BACKUP_EXTENSION,
];

const BACKUP_SUFFIXES: &[&str] = &[
    ".bak",
    ".old",
    ".orig",
    ".save",
    ".swp",
    ".backup",
    ".copy",
    ".tmp",
];

/// Source/config extensions whose backup copies leak code or credentials.
/// A backup suffix on anything else (`release-notes.old`, `report.tmp`) is a
/// routine release artefact, not an exposed backup.
const BACKUP_SOURCE_EXTENSIONS: &[&str] = &[
    "php", "phtml", "jsp", "jspx", "asp", "aspx", "inc", "yml", "yaml", "json", "conf", "env",
    "ini", "config", "bak", "sql",
];

/// Manual checks for this family: backup / editor-copy suffixes on the path or
/// on a source/config query parameter value (e.g. `?download=config.php~`).
pub fn check(ctx: &InspectionContext<'_>) -> Vec<RuleHit> {
    let path = ctx.entry.path_only();
    if path.len() > 1 && is_backup_name(path) {
        return vec![BACKUP_EXTENSION.hit(format!("backup suffix in '{}'", excerpt(path)))];
    }
    if !ctx.query_decoded.is_empty() {
        for pair in ctx.query_decoded.split('&') {
            let value = pair.split_once('=').map(|(_, value)| value).unwrap_or(pair);
            if value.len() > 1 && is_source_backup(value) {
                return vec![BACKUP_EXTENSION.hit(format!(
                    "backup suffix in '{}'",
                    excerpt(value)
                ))];
            }
        }
    }
    Vec::new()
}

/// Allocation-free suffix test, so the common (clean) line pays nothing.
fn is_backup_name(value: &str) -> bool {
    value.ends_with('~')
        || BACKUP_SUFFIXES
            .iter()
            .any(|suffix| ends_with_ignore_ascii_case(value, suffix))
}

/// Query-value variant of [`is_backup_name`]: only fires when the file behind
/// the backup suffix is source or configuration.
fn is_source_backup(value: &str) -> bool {
    let stem = if let Some(stem) = value.strip_suffix('~') {
        stem
    } else {
        match BACKUP_SUFFIXES
            .iter()
            .find(|suffix| ends_with_ignore_ascii_case(value, suffix))
        {
            Some(suffix) => &value[..value.len() - suffix.len()],
            None => return false,
        }
    };
    let extension = stem.rsplit_once('.').map(|(_, ext)| ext).unwrap_or("");
    BACKUP_SOURCE_EXTENSIONS
        .iter()
        .any(|known| extension.eq_ignore_ascii_case(known))
}

fn ends_with_ignore_ascii_case(haystack: &str, suffix: &str) -> bool {
    let start = match haystack.len().checked_sub(suffix.len()) {
        Some(start) => start,
        None => return false,
    };
    haystack.is_char_boundary(start) && haystack[start..].eq_ignore_ascii_case(suffix)
}

#[cfg(test)]
mod tests {
    use super::super::test_util::{assert_clean, assert_hit, entry};

    #[test]
    fn detects_vcs_and_dotfiles() {
        assert_hit(&entry("/.env"), "SENS-001");
        assert_hit(&entry("/.env.production"), "SENS-001");
        assert_hit(&entry("/.git/config"), "SENS-002");
        assert_hit(&entry("/.git/HEAD"), "SENS-002");
        assert_hit(&entry("/.svn/entries"), "SENS-003");
        assert_hit(&entry("/.ssh/id_rsa"), "SENS-004");
        assert_hit(&entry("/.aws/credentials"), "SENS-005");
    }

    #[test]
    fn detects_config_and_dump_files() {
        assert_hit(&entry("/wp-config.php"), "SENS-006");
        assert_hit(&entry("/wp-config.php.bak"), "SENS-006");
        assert_hit(&entry("/config.php.bak"), "SENS-007");
        assert_hit(&entry("/backup/db.sql"), "SENS-008");
        assert_hit(&entry("/phpinfo.php"), "SENS-009");
        assert_hit(&entry("/.htpasswd"), "SENS-010");
        assert_hit(&entry("/WEB-INF/web.xml"), "SENS-011");
        assert_hit(&entry("/Dockerfile"), "SENS-013");
        assert_hit(&entry("/.bash_history"), "SENS-014");
    }

    #[test]
    fn detects_backup_suffixes() {
        assert_hit(&entry("/index.php~"), "SENS-015");
        assert_hit(&entry("/app.js.old"), "SENS-015");
        assert_hit(&entry("/settings.yaml.orig"), "SENS-015");
        assert_hit(&entry("/download?file=config.php~"), "SENS-015");
        assert_hit(&entry("/download?file=config.php.bak"), "SENS-015");
        assert_hit(&entry("/download?file=settings.yaml.old"), "SENS-015");
        assert_hit(&entry("/download?file=.env~"), "SENS-015");
    }

    /// Regression for the report's FP-6: `.old` on a release artefact is not
    /// an exposed configuration backup.
    #[test]
    fn benign_release_artefacts_are_not_backups() {
        assert_clean(&entry("/download?file=release-notes.old"));
        assert_clean(&entry("/download?file=report-2026.tmp"));
        assert_clean(&entry("/download?file=manual.pdf"));
        assert_clean(&entry("/download?file=hero.jpg"));
    }

    #[test]
    fn ignores_benign_files() {
        assert_clean(&entry("/index.html"));
        assert_clean(&entry("/blog/understanding-env-variables"));
        assert_clean(&entry("/images/logo.png"));
        assert_clean(&entry("/docs/getting-started"));
    }
}

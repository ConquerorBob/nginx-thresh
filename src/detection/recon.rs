//! Reconnaissance: exposed admin, status and API surfaces plus known scanner
//! user agents and dangerous HTTP methods.

use super::rule::{excerpt, InspectionContext, RuleSpec};
use crate::model::threat::{Category, RuleHit};

const TRACING_METHOD: RuleSpec = RuleSpec::custom(
    "RECON-014",
    "Cross-site tracing or tunnelling method",
    Category::Reconnaissance,
    4,
);

const WEBDAV_METHOD: RuleSpec = RuleSpec::custom(
    "RECON-015",
    "WebDAV enumeration method",
    Category::Reconnaissance,
    4,
);

pub const SPECS: &[RuleSpec] = &[
    RuleSpec::target(
        "RECON-001",
        "security.txt probe",
        "security_txt",
        Category::Reconnaissance,
        2,
        r"(?:^|/)\.well-known/security\.txt",
    ),
    RuleSpec::target(
        "RECON-002",
        "Apache server status endpoint",
        "server_status",
        Category::Reconnaissance,
        4,
        r"(?:^|/)(?:server-status|server-info)(?:$|[?#/])",
    ),
    RuleSpec::target(
        "RECON-003",
        "Spring Boot actuator endpoint",
        "actuator_endpoint",
        Category::Reconnaissance,
        4,
        r"(?:^|/)actuator(?:$|[/?#])",
    ),
    RuleSpec::target(
        "RECON-004",
        "API documentation endpoint",
        "api_docs",
        Category::Reconnaissance,
        3,
        r"(?:^|/)(?:swagger-ui|swagger\.json|swagger-resources|v2/api-docs|v3/api-docs|openapi\.json|redoc)",
    ),
    RuleSpec::target(
        "RECON-005",
        "GraphQL endpoint probe",
        "graphql_endpoint",
        Category::Reconnaissance,
        3,
        r"(?:^|/)graphql(?:$|[/?#])",
    ),
    RuleSpec::target(
        "RECON-006",
        "Application server console",
        "server_console",
        Category::Reconnaissance,
        4,
        r"(?:^|/)(?:console|jmx-console|web-console|manager/html|host-manager/html|admin-console|solr/admin)(?:$|[/?#])",
    ),
    RuleSpec::target(
        "RECON-007",
        "Database admin interface",
        "db_admin_interface",
        Category::Reconnaissance,
        4,
        r"(?:^|/)(?:phpmyadmin|pma|adminer(?:\.php)?|myadmin|mysqladmin)(?:$|[/?#])",
    ),
    RuleSpec::target(
        "RECON-008",
        "Administrative panel path",
        "admin_panel",
        Category::Reconnaissance,
        3,
        r"(?:^|/)(?:admin|administrator|adminpanel|admin_area|adminarea|manage|management)(?:$|/|\.php|[?#])",
    ),
    RuleSpec::target(
        "RECON-009",
        "WordPress surface probe",
        "wordpress_surface",
        Category::Reconnaissance,
        3,
        r"(?:^|/)(?:wp-admin|wp-login\.php|xmlrpc\.php|wp-json/wp/v2/users|wp-content/plugins/|wp-cron\.php)",
    ),
    RuleSpec::target(
        "RECON-010",
        "CGI directory probe",
        "cgi_bin",
        Category::Reconnaissance,
        3,
        r"(?:^|/)cgi-bin/",
    ),
    RuleSpec::target(
        "RECON-011",
        "DevOps or search cluster surface",
        "devops_surface",
        Category::Reconnaissance,
        3,
        r"(?:^|/)(?:jenkins|hudson|solr/|elasticsearch|kibana|_cat/indices|_nodes|_cluster/health|zabbix|grafana|prometheus)",
    ),
    RuleSpec::user_agent(
        "RECON-012",
        "Known vulnerability scanner user agent",
        "scanner_user_agent",
        Category::Reconnaissance,
        4,
        r"\b(?:nikto|sqlmap|nmap|masscan|zmap|gobuster|ffuf|dirb|dirbuster|wpscan|nuclei|acunetix|nessus|openvas|whatweb|hydra|feroxbuster|zgrab|wfuzz|joomscan|droopescan|skipfish|arachni|netsparker|w3af|commix|xsstrike|dalfox|gospider|hakrawler|katana)\b",
    ),
    TRACING_METHOD,
    WEBDAV_METHOD,
];

/// Manual checks for this family: dangerous HTTP methods.
pub fn check(ctx: &InspectionContext<'_>) -> Vec<RuleHit> {
    let method = ctx.entry.method.trim();
    if method.is_empty() || method == "-" {
        return Vec::new();
    }
    let evidence = || format!("method {} on '{}'", excerpt(method), excerpt(&ctx.path_lower));
    if method.eq_ignore_ascii_case("TRACE")
        || method.eq_ignore_ascii_case("TRACK")
        || method.eq_ignore_ascii_case("DEBUG")
        || method.eq_ignore_ascii_case("CONNECT")
    {
        return vec![TRACING_METHOD.hit(evidence())];
    }
    if method.eq_ignore_ascii_case("PROPFIND")
        || method.eq_ignore_ascii_case("PROPPATCH")
        || method.eq_ignore_ascii_case("MKCOL")
    {
        return vec![WEBDAV_METHOD.hit(evidence())];
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::super::test_util::{assert_clean, assert_hit, entry, entry_full, entry_ua};

    #[test]
    fn detects_admin_and_status_surfaces() {
        assert_hit(&entry("/server-status"), "RECON-002");
        assert_hit(&entry("/server-status?auto"), "RECON-002");
        assert_hit(&entry("/actuator/env"), "RECON-003");
        assert_hit(&entry("/wp-login.php"), "RECON-009");
        assert_hit(&entry("/wp-admin/"), "RECON-009");
        assert_hit(&entry("/phpmyadmin/"), "RECON-007");
        assert_hit(&entry("/admin/login"), "RECON-008");
        assert_hit(&entry("/swagger-ui/index.html"), "RECON-004");
        assert_hit(&entry("/.well-known/security.txt"), "RECON-001");
        assert_hit(&entry("/cgi-bin/test.cgi"), "RECON-010");
        assert_hit(&entry("/jenkins/"), "RECON-011");
        assert_hit(&entry("/graphql"), "RECON-005");
    }

    #[test]
    fn detects_scanner_user_agents() {
        assert_hit(&entry_ua("/", "Mozilla/5.00 (Nikto/2.1.6)"), "RECON-012");
        assert_hit(
            &entry_ua("/", "sqlmap/1.7.2#stable (https://sqlmap.org)"),
            "RECON-012",
        );
        assert_hit(
            &entry_ua("/", "Mozilla/5.0 (compatible; Nuclei - Open-source project)"),
            "RECON-012",
        );
        assert_hit(&entry_ua("/", "gobuster/3.6"), "RECON-012");
        assert_hit(&entry_ua("/", "masscan/1.3"), "RECON-012");
    }

    #[test]
    fn detects_dangerous_methods() {
        assert_hit(&entry_full("PROPFIND", "/dav/", "Mozilla/5.0", 207), "RECON-015");
        assert_hit(&entry_full("TRACE", "/", "Mozilla/5.0", 200), "RECON-014");
        assert_hit(&entry_full("trace", "/", "Mozilla/5.0", 200), "RECON-014");
        assert_hit(&entry_full("DEBUG", "/", "Mozilla/5.0", 200), "RECON-014");
    }

    #[test]
    fn ignores_benign_paths_and_agents() {
        assert_clean(&entry("/"));
        assert_clean(&entry("/api/v1/users/42"));
        assert_clean(&entry("/admin-dashboard/report"));
        assert_clean(&entry_ua("/", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0"));
    }
}

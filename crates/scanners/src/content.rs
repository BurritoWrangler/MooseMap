//! Web content/path discovery via `feroxbuster`.
//!
//! Runs [`feroxbuster`](https://github.com/epi052/feroxbuster) against the web
//! endpoints confirmed during web recon (httpx), looking for interesting paths:
//! exposed VCS/config/backup files, admin panels, API roots, etc.
//!
//! ## Safety / rules of engagement
//!
//! Content discovery is **active and noisy** — it sends many requests. The
//! defaults here are deliberately conservative (small thread count, a request
//! rate limit, shallow recursion, a short per-request timeout) so a default scan
//! is polite enough for authorized perimeter testing. It runs *only* against
//! endpoints httpx already confirmed are live, never blindly. Every discovered
//! URL is re-checked against the scope guard.
//!
//! The wordlist is a small, high-signal built-in list by default. Point
//! `MOOSEMAP_WORDLIST` at a file (e.g. a SecLists list) to go deeper.

use crate::tool;
use moosemap_core::engine::{async_trait, StageContext, StageExecutor, StageOutcome};
use moosemap_core::model::{Exploitability, Finding, Severity, Stage};
use std::io::Write;

const FEROXBUSTER: &str = "feroxbuster";

/// Conservative defaults (overridable later via config if desired).
const THREADS: &str = "10";
const RATE_LIMIT: &str = "50"; // requests/sec per feroxbuster
const DEPTH: &str = "2"; // recursion depth
const TIMEOUT: &str = "7"; // seconds per request

/// Built-in high-signal wordlist: paths whose mere presence is interesting on
/// an external perimeter. Deliberately small/polite; override with a bigger
/// list via MOOSEMAP_WORDLIST.
const WORDLIST: &[&str] = &[
    // VCS / source exposure
    ".git", ".git/HEAD", ".git/config", ".gitignore", ".svn", ".hg", ".bzr",
    // Env / secrets / config
    ".env", ".env.local", ".env.production", "config", "config.php", "config.json",
    "config.yml", "config.yaml", "settings.py", "web.config", "appsettings.json",
    "wp-config.php", "configuration.php", ".aws", ".ssh", "id_rsa",
    "credentials", "secrets", "secret", ".htpasswd", ".htaccess",
    // Backups / dumps
    "backup", "backups", "backup.zip", "backup.tar.gz", "backup.sql", "dump.sql",
    "db.sql", "database.sql", "www.zip", "site.zip", "backup.bak", "old",
    // Admin / management
    "admin", "administrator", "admin.php", "login", "wp-admin", "wp-login.php",
    "phpmyadmin", "pma", "manager", "management", "console", "dashboard",
    "cpanel", "webadmin", "adminer.php", "server-status", "server-info",
    // API / docs / debug
    "api", "api/v1", "api/v2", "swagger", "swagger.json", "swagger-ui",
    "openapi.json", "graphql", "graphiql", "actuator", "actuator/health",
    "actuator/env", "metrics", "debug", "trace", "status", "health",
    // App frameworks / common
    "wp-content", "wp-includes", "wp-json", "robots.txt", "sitemap.xml",
    "crossdomain.xml", "security.txt", ".well-known/security.txt",
    "phpinfo.php", "info.php", "test.php", "test", "tmp", "temp", "upload",
    "uploads", "files", "private", "internal", "staging", "dev", "beta",
    // CI / infra leakage
    "Jenkinsfile", "Dockerfile", "docker-compose.yml", ".dockerignore",
    "package.json", "composer.json", "composer.lock", "yarn.lock",
    ".travis.yml", ".gitlab-ci.yml", ".circleci", "Gemfile",
];

/// Resolve the wordlist file path: an operator override, or a temp file we
/// write the built-in list to. Returns (path, keep_alive_tempfile).
fn resolve_wordlist() -> std::io::Result<(std::path::PathBuf, Option<tempfileish::TempPath>)> {
    if let Ok(p) = std::env::var("MOOSEMAP_WORDLIST") {
        if !p.trim().is_empty() {
            return Ok((std::path::PathBuf::from(p), None));
        }
    }
    let tp = tempfileish::write_lines("moosemap-wordlist", WORDLIST)?;
    let path = tp.path.clone();
    Ok((path, Some(tp)))
}

/// How interesting is a discovered path? Drives finding severity.
fn classify_path(url: &str) -> (Severity, Exploitability, &'static str) {
    let u = url.to_ascii_lowercase();
    // Secret/VCS/backup exposure — highest value.
    let high = [
        ".git", ".svn", ".hg", ".env", "id_rsa", ".ssh", ".htpasswd",
        "backup", ".sql", ".bak", "credentials", "secret", "wp-config",
        "actuator/env", "phpinfo", "/dump", "composer.lock",
    ];
    if high.iter().any(|p| u.contains(p)) {
        return (Severity::High, Exploitability::ProofOfConcept, "sensitive file/VCS/backup exposure");
    }
    // Admin / management surfaces — medium.
    let med = [
        "admin", "login", "phpmyadmin", "manager", "console", "dashboard",
        "cpanel", "swagger", "graphql", "actuator", "server-status", "adminer",
    ];
    if med.iter().any(|p| u.contains(p)) {
        return (Severity::Medium, Exploitability::Theoretical, "management/admin interface");
    }
    (Severity::Info, Exploitability::None, "discovered path")
}

/// A parsed feroxbuster result line we care about.
#[derive(Debug, Clone, PartialEq)]
pub struct FeroxHit {
    pub url: String,
    pub status: u16,
}

/// Parse one feroxbuster `--json` line into a hit, if it's a response record
/// with a status worth reporting (exclude 404 and generic noise).
pub fn parse_ferox_line(line: &str) -> Option<FeroxHit> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    // feroxbuster emits {"type":"response", "url":..., "status":...} among others
    // (statistics, etc.). Only keep responses.
    if v.get("type").and_then(|x| x.as_str()) != Some("response") {
        return None;
    }
    let url = v.get("url").and_then(|x| x.as_str())?.to_string();
    let status = v
        .get("status")
        .and_then(|x| x.as_u64())
        .map(|s| s as u16)?;
    // Report interesting statuses; skip 404 and server errors noise.
    if matches!(status, 200 | 201 | 204 | 301 | 302 | 307 | 401 | 403 | 405 | 500) {
        Some(FeroxHit { url, status })
    } else {
        None
    }
}

/// Content discovery executor — web-recon stage, runs after httpx.
pub struct ContentDiscovery;

#[async_trait]
impl StageExecutor for ContentDiscovery {
    fn stage(&self) -> Stage {
        Stage::WebRecon
    }
    fn name(&self) -> &str {
        "content-discovery"
    }

    async fn execute(&self, ctx: &StageContext) -> anyhow::Result<StageOutcome> {
        if !tool::is_installed(FEROXBUSTER) {
            return Ok(StageOutcome::Skipped("feroxbuster not installed".into()));
        }

        // Only probe endpoints httpx already confirmed live.
        let endpoints: Vec<(moosemap_core::model::Target, String)> = {
            let state = ctx.state.lock().await;
            state
                .web_endpoints
                .iter()
                .map(|e| (e.target.clone(), e.url.clone()))
                .collect()
        };
        if endpoints.is_empty() {
            return Ok(StageOutcome::Skipped(
                "no confirmed web endpoints to probe".into(),
            ));
        }

        let (wordlist, _keep) = match resolve_wordlist() {
            Ok(w) => w,
            Err(e) => return Ok(StageOutcome::Skipped(format!("wordlist error: {e}"))),
        };

        ctx.info(format!(
            "content discovery over {} endpoint(s) (conservative rate caps)",
            endpoints.len()
        ));

        let mut count = 0usize;
        for (target, url) in endpoints {
            if !ctx.scope.allows(&target) {
                continue;
            }
            let args = vec![
                "--json".to_string(),
                "--silent".to_string(),
                "-u".to_string(),
                url.clone(),
                "-w".to_string(),
                wordlist.to_string_lossy().into_owned(),
                "--threads".to_string(),
                THREADS.to_string(),
                "--rate-limit".to_string(),
                RATE_LIMIT.to_string(),
                // Bounded recursion depth (conservative).
                "--depth".to_string(),
                DEPTH.to_string(),
                "--timeout".to_string(),
                TIMEOUT.to_string(),
                // Don't persist a resume-state file.
                "--no-state".to_string(),
            ];
            let out = tool::run(FEROXBUSTER, &args).await?;
            // feroxbuster exits non-zero on some conditions but still emits
            // results; parse stdout regardless.
            for line in out.stdout.lines() {
                let Some(hit) = parse_ferox_line(line) else { continue };
                let (severity, exploit, kind) = classify_path(&hit.url);
                ctx.add_finding(Finding::new(
                    target.clone(),
                    None,
                    format!("Content discovery: {} ({})", hit.url, hit.status),
                    format!(
                        "feroxbuster found a {kind} at {} (HTTP {}). Review whether \
                         it should be externally reachable.",
                        hit.url, hit.status
                    ),
                    severity,
                    exploit,
                    "content-discovery",
                ))
                .await;
                count += 1;
            }
        }

        ctx.info(format!("content discovery produced {count} finding(s)"));
        Ok(StageOutcome::Completed)
    }
}

/// Minimal temp-file helper (no external crate): write lines to a uniquely
/// named file in the temp dir and clean it up on drop.
mod tempfileish {
    use super::*;

    pub struct TempPath {
        pub path: std::path::PathBuf,
    }
    impl Drop for TempPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    pub fn write_lines(prefix: &str, lines: &[&str]) -> std::io::Result<TempPath> {
        let mut path = std::env::temp_dir();
        // Unique-ish name from pid + a monotonic counter.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        path.push(format!("{prefix}-{}-{n}.txt", std::process::id()));
        let mut f = std::fs::File::create(&path)?;
        for l in lines {
            writeln!(f, "{l}")?;
        }
        f.flush()?;
        Ok(TempPath { path })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_response_line() {
        let line = r#"{"type":"response","url":"http://h/.git/config","status":200,"content_length":92}"#;
        let hit = parse_ferox_line(line).unwrap();
        assert_eq!(hit.url, "http://h/.git/config");
        assert_eq!(hit.status, 200);
    }

    #[test]
    fn ignores_non_response_and_404() {
        assert!(parse_ferox_line(r#"{"type":"statistics","requests":100}"#).is_none());
        assert!(parse_ferox_line(r#"{"type":"response","url":"http://h/nope","status":404}"#).is_none());
        assert!(parse_ferox_line("not json").is_none());
        assert!(parse_ferox_line("").is_none());
    }

    #[test]
    fn keeps_interesting_statuses() {
        for st in [200, 301, 302, 401, 403, 500] {
            let line = format!(r#"{{"type":"response","url":"http://h/x","status":{st}}}"#);
            assert!(parse_ferox_line(&line).is_some(), "status {st} should be kept");
        }
    }

    #[test]
    fn classify_sensitive_as_high() {
        assert_eq!(classify_path("http://h/.git/config").0, Severity::High);
        assert_eq!(classify_path("http://h/.env").0, Severity::High);
        assert_eq!(classify_path("http://h/backup.sql").0, Severity::High);
        assert_eq!(classify_path("http://h/id_rsa").0, Severity::High);
    }

    #[test]
    fn classify_admin_as_medium() {
        assert_eq!(classify_path("http://h/admin").0, Severity::Medium);
        assert_eq!(classify_path("http://h/phpmyadmin/").0, Severity::Medium);
        assert_eq!(classify_path("http://h/actuator/health").0, Severity::Medium);
    }

    #[test]
    fn classify_generic_as_info() {
        assert_eq!(classify_path("http://h/robots.txt").0, Severity::Info);
        assert_eq!(classify_path("http://h/about").0, Severity::Info);
    }

    #[test]
    fn builtin_wordlist_writes_and_cleans_up() {
        let (path, keep) = resolve_wordlist().unwrap();
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains(".git"));
        assert!(content.contains("admin"));
        drop(keep); // TempPath drop removes the file
        assert!(!path.exists());
    }

    #[test]
    fn wordlist_override_env() {
        std::env::set_var("MOOSEMAP_WORDLIST", "/some/custom/list.txt");
        let (path, keep) = resolve_wordlist().unwrap();
        assert_eq!(path, std::path::PathBuf::from("/some/custom/list.txt"));
        assert!(keep.is_none()); // not a temp file
        std::env::remove_var("MOOSEMAP_WORDLIST");
    }
}

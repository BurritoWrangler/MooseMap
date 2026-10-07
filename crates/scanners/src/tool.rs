//! Helpers for locating and running external command-line tools.
//!
//! Every adapter that shells out to a binary (nmap, masscan, nuclei, ...) uses
//! these helpers so behavior is consistent: tools that aren't installed cause a
//! graceful *skip*, not a crash, and command execution is centralized.

use std::process::Stdio;
use tokio::process::Command;

/// Is a binary available on `PATH`?
pub fn is_installed(bin: &str) -> bool {
    which(bin).is_some()
}

/// Resolve a binary to its full path by scanning `PATH`. Returns `None` if not
/// found. (Avoids a dependency on the `which` crate for a tiny bit of logic.)
pub fn which(bin: &str) -> Option<std::path::PathBuf> {
    // Absolute/relative path given directly.
    if bin.contains('/') {
        let p = std::path::Path::new(bin);
        return if p.is_file() { Some(p.to_path_buf()) } else { None };
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Resolve a tool's binary name, honoring an environment override.
///
/// Each adapter can let the operator point MooseMap at a specific binary — handy
/// on Kali where the default `httpx` on `PATH` may be the unrelated Python HTTP
/// client rather than ProjectDiscovery's `httpx`. For a tool `foo`, the override
/// variable is `MOOSEMAP_FOO` (uppercased, non-alphanumerics -> `_`).
///
/// Returns the configured override if set, else the default name unchanged.
pub fn resolve_binary(default_name: &str) -> String {
    let var = format!(
        "MOOSEMAP_{}",
        default_name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            })
            .collect::<String>()
    );
    match std::env::var(&var) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => default_name.to_string(),
    }
}

/// Outcome of checking whether a binary is the expected ProjectDiscovery tool.
#[derive(Debug, PartialEq, Eq)]
pub enum ToolCheck {
    /// Binary isn't on `PATH` / not found.
    Missing,
    /// Found and looks like the expected ProjectDiscovery tool.
    Ok,
    /// Found, but doesn't look like the expected tool (e.g. the Python `httpx`
    /// shadowing ProjectDiscovery's on Kali). Carries a human-readable reason.
    Wrong(String),
}

/// Verify that `bin` is really the ProjectDiscovery tool named `expected`
/// (e.g. "httpx", "nuclei", "subfinder").
///
/// ProjectDiscovery tools accept `-version` and print a banner that mentions
/// `projectdiscovery` and/or the tool name. The Python `httpx` CLI does not
/// understand `-version` and errors out, which lets us tell them apart. This is
/// best-effort: if we can't run the binary at all we report it missing.
pub async fn verify_projectdiscovery(bin: &str, expected: &str) -> ToolCheck {
    if which(bin).is_none() {
        return ToolCheck::Missing;
    }
    // `-version` is cheap and side-effect-free for PD tools.
    let out = match run(bin, &["-version".to_string()]).await {
        Ok(o) => o,
        Err(_) => return ToolCheck::Missing,
    };
    let combined = format!("{}\n{}", out.stdout, out.stderr).to_ascii_lowercase();

    // PD tools print e.g. "httpx version vX.Y.Z" and/or "projectdiscovery.io".
    let looks_pd = combined.contains("projectdiscovery")
        || combined.contains(&format!("{expected} version"))
        || combined.contains(&format!("current {expected} version"));

    // The Python httpx CLI reacts very differently to `-version`: it treats `-v`
    // style flags as a URL/argument error, or prints its own usage.
    let looks_like_python_httpx = expected == "httpx"
        && (combined.contains("usage: httpx")
            || combined.contains("httpcore")
            || combined.contains("the requested url"));

    if looks_pd && !looks_like_python_httpx {
        ToolCheck::Ok
    } else if looks_like_python_httpx {
        ToolCheck::Wrong(format!(
            "`{bin}` appears to be the Python httpx client, not ProjectDiscovery \
             httpx. Install the PD tool and/or set MOOSEMAP_HTTPX to its path."
        ))
    } else {
        // Couldn't positively identify it. Be conservative: allow it but say so.
        // Many PD builds still print a usable banner; treat unknown as Ok unless
        // it clearly matched the Python tool above.
        ToolCheck::Ok
    }
}

/// Captured result of running a command.
pub struct Output {
    pub status: std::process::ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn success(&self) -> bool {
        self.status.success()
    }
}

/// Run a command to completion, capturing stdout/stderr as UTF-8 (lossy).
///
/// Returns an error only if the process could not be spawned or awaited; a
/// non-zero exit is reported via [`Output::status`] so callers can decide.
pub async fn run(bin: &str, args: &[String]) -> anyhow::Result<Output> {
    let out = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("failed to spawn `{bin}`: {e}"))?;

    Ok(Output {
        status: out.status,
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Like [`run`], but feeds `stdin_data` to the child's standard input. Used for
/// tools that accept a list of targets on stdin (e.g. httpx, nuclei).
pub async fn run_with_stdin(
    bin: &str,
    args: &[String],
    stdin_data: &str,
) -> anyhow::Result<Output> {
    use tokio::io::AsyncWriteExt;

    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn `{bin}`: {e}"))?;

    // Write stdin in a scope so it's closed (EOF) before we await output.
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(stdin_data.as_bytes()).await?;
        stdin.shutdown().await.ok();
        drop(stdin);
    }

    let out = child
        .wait_with_output()
        .await
        .map_err(|e| anyhow::anyhow!("failed to await `{bin}`: {e}"))?;

    Ok(Output {
        status: out.status,
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_a_known_binary() {
        // `sh` exists on any unix CI/dev box.
        assert!(is_installed("sh"));
        assert!(!is_installed("definitely-not-a-real-binary-xyz"));
    }

    #[tokio::test]
    async fn runs_echo() {
        let out = run("sh", &["-c".into(), "printf hello".into()])
            .await
            .unwrap();
        assert!(out.success());
        assert_eq!(out.stdout, "hello");
    }

    #[tokio::test]
    async fn feeds_stdin() {
        // `cat` echoes stdin back to stdout.
        let out = run_with_stdin("cat", &[], "line1\nline2").await.unwrap();
        assert!(out.success());
        assert_eq!(out.stdout, "line1\nline2");
    }

    #[test]
    fn resolve_binary_default_and_override() {
        // No override -> default name.
        std::env::remove_var("MOOSEMAP_HTTPX");
        assert_eq!(resolve_binary("httpx"), "httpx");

        // Override is honored.
        std::env::set_var("MOOSEMAP_HTTPX", "/opt/pd/httpx");
        assert_eq!(resolve_binary("httpx"), "/opt/pd/httpx");
        std::env::remove_var("MOOSEMAP_HTTPX");

        // Non-alphanumerics in the tool name map to underscores in the var.
        std::env::set_var("MOOSEMAP_MY_TOOL", "custom");
        assert_eq!(resolve_binary("my-tool"), "custom");
        std::env::remove_var("MOOSEMAP_MY_TOOL");
    }

    #[tokio::test]
    async fn verify_reports_missing_for_absent_binary() {
        let check = verify_projectdiscovery("definitely-not-real-xyz", "httpx").await;
        assert_eq!(check, ToolCheck::Missing);
    }

    #[tokio::test]
    async fn verify_detects_projectdiscovery_banner() {
        // Fake a PD-style `-version` banner via a tiny shell script.
        let dir = std::env::temp_dir().join(format!("mm-pd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("fakehttpx");
        std::fs::write(
            &bin,
            "#!/bin/sh\necho 'httpx version v1.6.0 (projectdiscovery.io)'\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let check = verify_projectdiscovery(bin.to_str().unwrap(), "httpx").await;
        assert_eq!(check, ToolCheck::Ok);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn verify_flags_python_httpx() {
        // Simulate the Python httpx CLI reacting to `-version`.
        let dir = std::env::temp_dir().join(format!("mm-py-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("pyhttpx");
        std::fs::write(
            &bin,
            "#!/bin/sh\necho 'Usage: httpx [OPTIONS] URL' >&2\nexit 2\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let check = verify_projectdiscovery(bin.to_str().unwrap(), "httpx").await;
        assert!(matches!(check, ToolCheck::Wrong(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

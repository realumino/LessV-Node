//! Xray binary helpers: config test, version, platform, detected address.
//!
//! WHAT: thin wrappers around `xray` itself.
//! WHY Xray is the authority: the agent has no opinion about config
//! validity; a non-zero `run -test` must stop the apply before the live
//! config is touched. Missing binaries are failures to report, never panics.

use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::supervisor::Supervisor;
use crate::util::{run_command, tail};

pub const TEST_TIMEOUT_SECS: u64 = 15;
pub const VERIFY_GRACE_SECS: u64 = 3;

/// WHAT: test a config file with Xray's own checker.
///
/// WHY the fallback: modern Xray (>= 1.8) moved testing into `run -test`;
/// older binaries only know `-test -config`. Dispatch on the "unknown"
/// output so a pinned old binary keeps working.
pub fn test_config(binary: &str, path: &str) -> (bool, i32, String) {
    let result = run_command(
        binary,
        &["run", "-test", "-c", path],
        Duration::from_secs(TEST_TIMEOUT_SECS),
    );
    let output = tail(&result.output, 2000);
    if result.code == 0 {
        return (true, 0, output);
    }
    if output.to_lowercase().contains("unknown") {
        let legacy = run_command(
            binary,
            &["-test", "-config", path],
            Duration::from_secs(TEST_TIMEOUT_SECS),
        );
        return (
            legacy.code == 0,
            legacy.code,
            tail(&legacy.output, 2000),
        );
    }
    (false, result.code, output)
}

/// WHAT: resolve the configured binary name to a path.
///
/// WHY PATH search: `xray_binary` may be a bare `xray` (the default) or an
/// absolute path. A replacement must target the same file the unit runs, so
/// a bare name is looked up once, here, instead of trusting the caller's
/// working directory.
pub fn binary_path(configured: &str) -> Result<PathBuf, String> {
    let path = Path::new(configured);
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let search = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&search) {
        let candidate = dir.join(configured);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(format!(
        "xray binary {configured:?} not found on PATH"
    ))
}

/// WHAT: the version number of one binary (`26.11.9`), or None.
///
/// WHY the bare number: the plane compares it against a release tag to decide
/// whether an update is still needed, and shows it in the fleet view.
pub fn version_number(binary: &Path) -> Option<String> {
    let result = run_command(
        &binary.to_string_lossy(),
        &["version"],
        Duration::from_secs(10),
    );
    if result.code != 0 {
        return None;
    }
    first_version_token(&result.output)
}

/// WHAT: the version-shaped token of `xray version` output.
pub fn first_version_token(output: &str) -> Option<String> {
    let line = output.lines().next()?.trim();
    if line.is_empty() {
        return None;
    }
    let token = line
        .split_whitespace()
        .find(|token| {
            token.contains('.') && token.chars().all(|ch| ch.is_ascii_digit() || ch == '.')
        })
        .unwrap_or(line);
    Some(token.to_string())
}

/// WHAT: `linux/<arch>` as reported at enroll.
pub fn platform() -> String {
    format!("linux/{}", std::env::consts::ARCH)
}

/// WHAT: the node's public egress address, guessed without sending packets.
///
/// WHY best effort: enroll accepts no address, and the UDP connect trick only
/// observes the kernel's chosen source address. Offline nodes report null.
pub fn detected_ip() -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket
        .local_addr()
        .ok()
        .map(|addr| addr.ip().to_string())
}

/// WHAT: restart the unit, wait out the grace period, confirm it survived.
///
/// WHY a grace period: a config can pass `test` yet die on bind (port in
/// use, unreadable certificate). Only a live process counts as success.
pub fn restart_and_verify(supervisor: &Supervisor, service: &str) -> Result<(), String> {
    supervisor.restart(service)?;
    std::thread::sleep(Duration::from_secs(VERIFY_GRACE_SECS));
    if supervisor.status(service).0 {
        Ok(())
    } else {
        Err("xray failed to stay up after restart".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_is_linux_prefixed() {
        assert!(platform().starts_with("linux/"));
    }

    #[test]
    fn missing_binary_is_a_failure_not_a_panic() {
        let (ok, code, output) = test_config("lessv-node-no-xray", "/tmp/x.json");
        assert!(!ok);
        assert_eq!(code, 127);
        assert!(output.contains("command not found"));
        assert_eq!(version_number(Path::new("/nonexistent/lessv-node-no-xray")), None);
    }

    #[test]
    fn extracts_the_version_number_from_xray_output() {
        assert_eq!(
            first_version_token("Xray 26.11.9 (Xray, Penetrates Everything.) 676eaf6 (go1.27.3)"),
            Some("26.11.9".to_string())
        );
        assert_eq!(first_version_token(""), None);
        assert_eq!(
            first_version_token("custom build"),
            Some("custom build".to_string())
        );
    }
}

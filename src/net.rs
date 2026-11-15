//! Outbound HTTP for the node's own downloads.
//!
//! WHAT: one agent, one bounded GET, a SHA-256 helper, and GitHub's latest
//! release tag. The control-plane client has its own agent (its poll timeout
//! is seconds); a geodata release is 16 MB and needs minutes.
//!
//! WHY this module exists separately from the reconciler: the same helpers
//! serve the weekly geodata refresh and an admin-triggered one, and neither
//! has anything to do with the plane's wire contract.

use std::time::Duration;

use serde_json::Value;
use sha2::{Digest, Sha256};

/// WHAT: lowercase hex SHA-256 of a byte slice.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// WHAT: a download agent with a long timeout for vendor releases.
///
/// WHY separate from the control-plane client: 16 MB from GitHub does not
/// fit the 10 s poll timeout, and a slow archive must never look like a
/// plane failure.
pub fn download_agent() -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(300)))
        .http_status_as_error(false)
        .user_agent(format!("vela-server/{}", crate::http::VERSION))
        .build();
    ureq::Agent::new_with_config(config)
}

/// WHAT: one bounded GET; non-2xx and transport errors are strings.
pub fn fetch(agent: &ureq::Agent, url: &str, limit: u64) -> Result<Vec<u8>, String> {
    let mut response = agent
        .get(url)
        .header("Accept", "application/octet-stream, application/json")
        .call()
        .map_err(|error| format!("GET {url}: {error}"))?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(format!("GET {url}: HTTP {status}"));
    }
    response
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .map_err(|error| format!("GET {url}: {error}"))
}

/// WHAT: the `tag_name` of a repository's latest GitHub release.
pub fn latest_tag(agent: &ureq::Agent, repo: &str) -> Result<String, String> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let body = fetch(agent, &url, 1 << 20)?;
    let value: Value = serde_json::from_slice(&body)
        .map_err(|error| format!("{url}: malformed JSON ({error})"))?;
    value
        .get("tag_name")
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|tag| !tag.is_empty())
        .ok_or_else(|| format!("{url}: no tag_name"))
}

//! Reconcile state: `/var/lib/lessv/state.json`.
//!
//! WHAT: the facts the loop needs across restarts (applied hash, last result,
//! certificate ETag, nginx health, Xray boot id).
//! WHY atomic writes: a half-written state is worse than none — the startup
//! rule could then believe a broken live config was verified.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::util::atomic_write;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub applied_hash: String,
    #[serde(default)]
    pub applied_at: i64,
    #[serde(default = "default_true")]
    pub last_apply_ok: bool,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub xray_boot_id: String,
    #[serde(default)]
    pub cert_etag: String,
    #[serde(default)]
    pub cert_synced_at: Option<i64>,
    #[serde(default)]
    pub last_nginx_ok: Option<bool>,
    /// The XTLS/Xray-rules-dat release the geodata files came from, and when
    /// they were installed. `None` version means the node has never fetched
    /// them, which triggers a one-time bootstrap on the next cycle.
    #[serde(default)]
    pub geodata_version: Option<String>,
    #[serde(default)]
    pub geodata_synced_at: Option<i64>,
    /// When a failed geodata refresh may be retried; keeps a broken download
    /// from being re-attempted every poll.
    #[serde(default)]
    pub geodata_retry_at: Option<i64>,
    /// The certificate set the decoy config was rendered from.
    ///
    /// WHY remembered: the nginx file is generated from the manifest, and a
    /// 304 (unchanged certificates) must still be able to detect that the
    /// file no longer matches what this version of the renderer writes — for
    /// example after a binary upgrade. Without the list the node cannot
    /// render, and would need a certificate change to converge.
    ///
    /// WHY optional: `None` is a state written before this record existed
    /// (fetch the manifest once); `Some([])` is a node that legitimately has
    /// no certificates, where a 304 stays a 304.
    #[serde(default)]
    pub certs: Option<Vec<StoredCert>>,
}

/// WHAT: one manifest certificate as the decoy renderer needs it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredCert {
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub path: String,
}

fn default_true() -> bool {
    true
}

impl Default for State {
    fn default() -> Self {
        State {
            applied_hash: String::new(),
            applied_at: 0,
            last_apply_ok: true,
            last_error: None,
            xray_boot_id: String::new(),
            cert_etag: String::new(),
            cert_synced_at: None,
            last_nginx_ok: None,
            geodata_version: None,
            geodata_synced_at: None,
            geodata_retry_at: None,
            certs: None,
        }
    }
}

/// WHAT: load state, falling back to defaults when missing or corrupt.
///
/// WHY never fail: first boot has no state, and corrupt state must converge
/// from defaults rather than crash the daemon; the next heartbeat re-syncs
/// reality from the plane anyway.
pub fn load(path: &Path) -> State {
    let Ok(bytes) = std::fs::read(path) else {
        return State::default();
    };
    let Ok(text) = String::from_utf8(bytes) else {
        return State::default();
    };
    let Ok(state) = serde_json::from_str::<State>(&text) else {
        return State::default();
    };
    state
}

/// WHAT: write state atomically (0600, it names the live hash/ETag).
pub fn save(path: &Path, state: &State) -> Result<(), std::io::Error> {
    let mut text = serde_json::to_string_pretty(state)?;
    text.push('\n');
    atomic_write(path, text.as_bytes(), 0o600)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_path(dir: &Path) -> PathBuf {
        dir.join("state.json")
    }

    #[test]
    fn defaults_when_missing_and_corrupt() {
        let dir = std::env::temp_dir().join(format!("lessv-state-{}", crate::util::random_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = temp_path(&dir);
        assert_eq!(load(&path), State::default());
        std::fs::write(&path, b"{not json").unwrap();
        assert_eq!(load(&path), State::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn round_trip_keeps_fields() {
        let dir = std::env::temp_dir().join(format!("lessv-state-{}", crate::util::random_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = temp_path(&dir);
        let state = State {
            applied_hash: "abc".to_string(),
            cert_etag: "\"deadbeef\"".to_string(),
            cert_synced_at: Some(42),
            last_nginx_ok: Some(false),
            ..State::default()
        };
        save(&path, &state).unwrap();
        assert_eq!(load(&path), state);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let json = r#"{"applied_hash":"h","future_field":1}"#;
        let state: State = serde_json::from_str(json).unwrap();
        assert_eq!(state.applied_hash, "h");
    }
}

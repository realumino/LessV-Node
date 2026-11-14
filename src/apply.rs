//! The apply pipeline: fetch, test, snapshot, swap, restart, roll back.
//!
//! WHAT: the only code path allowed to touch the live Xray config.
//! WHY this order: a tested candidate is staged beside the live file, the
//! previous healthy config is snapshotted before the swap, and a process
//! that dies after the swap restores the snapshot. Kill -9 anywhere in here
//! leaves either the old config or a tested new one on disk.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::config::Config;
use crate::util::random_hex;

#[derive(Debug, Clone, PartialEq)]
pub struct ApplyResult {
    pub ok: bool,
    pub stage: &'static str,
    pub error: Option<String>,
    pub xray_exit_code: Option<i32>,
}

impl ApplyResult {
    fn failure(stage: &'static str, error: impl Into<String>, code: Option<i32>) -> Self {
        let text: String = error.into();
        ApplyResult {
            ok: false,
            stage,
            error: Some(text.chars().take(500).collect()),
            xray_exit_code: code,
        }
    }
}

/// WHAT: the live config path as configured.
pub fn live_path(cfg: &Config) -> PathBuf {
    cfg.config_path.clone()
}

/// WHAT: derive the last-good snapshot path from the live path.
///
/// WHY deterministic: rollback and startup repair must always agree on the
/// fallback file, so the rule is `config.json` -> `config.last_good`.
pub fn last_good_path(cfg: &Config) -> PathBuf {
    let live = live_path(cfg);
    match live.extension().and_then(|value| value.to_str()) {
        Some("json") => live.with_extension("last_good"),
        _ => {
            let mut name = live.file_name().unwrap_or_default().to_os_string();
            name.push(".last_good");
            live.with_file_name(name)
        }
    }
}

/// WHAT: stage a candidate config beside the live file.
///
/// WHY the `.json` suffix: Xray picks its parser from the extension and
/// refuses an extensionless temp file ("Failed to get format of").
fn write_temp_config(cfg: &Config, config: &Value) -> Result<PathBuf, String> {
    let live = live_path(cfg);
    let parent = live.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| format!("mkdir {}: {error}", parent.display()))?;
    let tmp = parent.join(format!(".config.next.{}.json", random_hex(6)));
    let payload = serde_json::to_vec_pretty(config).map_err(|error| error.to_string())?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|error| format!("create {}: {error}", tmp.display()))?;
    let write = file
        .write_all(&payload)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("write {}: {error}", tmp.display()));
    if let Err(error) = write {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    Ok(tmp)
}

/// WHAT: copy the live config to last-good when the last apply succeeded.
///
/// WHY conditional: snapshotting a broken config would preserve the breakage
/// as the fallback. First boot (no live file) has nothing to snapshot.
pub fn snapshot_if_ok(cfg: &Config, last_apply_ok: bool) -> Result<bool, String> {
    if !last_apply_ok {
        return Ok(false);
    }
    let live = live_path(cfg);
    if !live.exists() {
        return Ok(false);
    }
    let dest = last_good_path(cfg);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("mkdir {}: {error}", parent.display()))?;
    }
    fs::copy(&live, &dest).map_err(|error| format!("snapshot {}: {error}", dest.display()))?;
    Ok(true)
}

/// WHAT: restore the last-good snapshot over the live config.
pub fn restore_last_good(cfg: &Config) -> bool {
    let source = last_good_path(cfg);
    if !source.exists() {
        return false;
    }
    let live = live_path(cfg);
    if let Some(parent) = live.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::copy(&source, &live).is_ok()
}

fn drop_file(path: &Path) {
    let _ = fs::remove_file(path);
}

/// WHAT: remove temp files a previous run left behind (e.g. killed mid-apply).
///
/// WHY only our own dot-prefixed temp names: the live directory belongs to
/// the operator as much as to this daemon; deleting anything else would be
/// an unrequested destructive act.
pub fn cleanup_temp_files(cfg: &Config) {
    let live = live_path(cfg);
    if let Some(parent) = live.parent() {
        if let Ok(entries) = fs::read_dir(parent) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with(".config.next.") && name.ends_with(".json") {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }
    if let Some(parent) = cfg.state_path.parent() {
        if let Ok(entries) = fs::read_dir(parent) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with(".state.json.tmp.") {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }
}

/// WHAT: run steps 2-8 for one desired hash with injected Xray/HTTP seams.
///
/// WHY closures: the pipeline's ordering is the property under test; unit
/// tests drive every failure stage without a daemon or a network.
pub fn apply<F, T, R, V>(
    cfg: &Config,
    last_apply_ok: bool,
    desired_hash: &str,
    fetch: F,
    test: T,
    restart: R,
    verify: V,
) -> ApplyResult
where
    F: Fn(&str) -> Result<Value, String>,
    T: Fn(&Path) -> (bool, i32, String),
    R: Fn() -> Result<(), String>,
    V: Fn() -> bool,
{
    let config = match fetch(desired_hash) {
        Ok(value) => value,
        Err(error) => return ApplyResult::failure("fetched", error, None),
    };
    if !config.is_object() || config.as_object().map(|map| map.is_empty()).unwrap_or(true) {
        return ApplyResult::failure(
            "fetched",
            format!("empty config for hash {desired_hash}"),
            None,
        );
    }
    let tmp = match write_temp_config(cfg, &config) {
        Ok(path) => path,
        Err(error) => return ApplyResult::failure("fetched", error, None),
    };
    let (tested, code, output) = test(&tmp);
    if !tested {
        drop_file(&tmp);
        let message = if output.trim().is_empty() {
            "config test failed".to_string()
        } else {
            output
        };
        return ApplyResult::failure("test", message, Some(code));
    }
    if let Err(error) = snapshot_if_ok(cfg, last_apply_ok) {
        drop_file(&tmp);
        return ApplyResult::failure("test", format!("snapshot failed: {error}"), None);
    }
    if let Err(error) = fs::rename(&tmp, live_path(cfg)) {
        drop_file(&tmp);
        return ApplyResult::failure("applied", format!("swap failed: {error}"), None);
    }
    if let Err(error) = restart() {
        return ApplyResult::failure("applied", error, None);
    }
    if verify() {
        return ApplyResult {
            ok: true,
            stage: "started",
            error: None,
            xray_exit_code: None,
        };
    }
    let rolled_back = restore_last_good(cfg);
    if rolled_back {
        let _ = restart();
    }
    let message = if rolled_back {
        "xray failed to stay up after restart (rolled back to last-good)"
    } else {
        "xray failed to stay up after restart (no last-good to restore)"
    };
    ApplyResult::failure("started", message, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg(dir: &Path) -> Config {
        Config {
            config_path: dir.join("config.json"),
            ..Config::default()
        }
    }

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("lessv-apply-{}", random_hex(6)));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn good_config() -> Value {
        json!({"inbounds": [], "outbounds": [{"tag": "direct", "protocol": "freedom"}]})
    }

    #[test]
    fn success_writes_live_and_returns_started() {
        let dir = temp_dir();
        let config = cfg(&dir);
        let result = apply(
            &config,
            true,
            "h1",
            |_| Ok(good_config()),
            |_| (true, 0, String::new()),
            || Ok(()),
            || true,
        );
        assert_eq!(result.stage, "started");
        assert!(result.ok);
        let live = fs::read_to_string(live_path(&config)).unwrap();
        assert!(live.contains("freedom"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_failure_leaves_live_untouched() {
        let dir = temp_dir();
        let config = cfg(&dir);
        fs::write(live_path(&config), "{\"old\":true}").unwrap();
        let result = apply(
            &config,
            true,
            "h1",
            |_| Ok(good_config()),
            |_| (false, 23, "bad config".to_string()),
            || panic!("restart must not run"),
            || panic!("verify must not run"),
        );
        assert_eq!(result.stage, "test");
        assert_eq!(result.error.as_deref(), Some("bad config"));
        assert_eq!(
            fs::read_to_string(live_path(&config)).unwrap(),
            "{\"old\":true}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_only_follows_healthy_apply_and_dead_start_restores_it() {
        let dir = temp_dir();
        let config = cfg(&dir);
        fs::write(live_path(&config), "{\"healthy\":true}").unwrap();
        // First apply with last_apply_ok=false: no snapshot is taken, so the
        // fallback still does not exist after a dead start.
        let result = apply(
            &config,
            false,
            "h1",
            |_| Ok(good_config()),
            |_| (true, 0, String::new()),
            || Ok(()),
            || false,
        );
        assert_eq!(result.stage, "started");
        assert!(!last_good_path(&config).exists());
        assert!(result
            .error
            .as_deref()
            .unwrap()
            .contains("no last-good to restore"));

        // Second apply with a healthy previous state snapshots that state,
        // then a dead start restores exactly it.
        fs::write(live_path(&config), "{\"healthy\":true}").unwrap();
        let result = apply(
            &config,
            true,
            "h2",
            |_| Ok(good_config()),
            |_| (true, 0, String::new()),
            || Ok(()),
            || false,
        );
        assert!(result.stage == "started");
        assert!(result.error.as_deref().unwrap().contains("rolled back"));
        assert_eq!(
            fs::read_to_string(live_path(&config)).unwrap(),
            "{\"healthy\":true}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fetch_failures_are_not_applies() {
        let dir = temp_dir();
        let config = cfg(&dir);
        let result = apply(
            &config,
            true,
            "h1",
            |_| Err("boom".to_string()),
            |_| panic!("test must not run"),
            || panic!("restart must not run"),
            || panic!("verify must not run"),
        );
        assert_eq!(result.stage, "fetched");
        assert!(!live_path(&config).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn restart_failure_is_an_applied_stage_failure() {
        let dir = temp_dir();
        let config = cfg(&dir);
        let result = apply(
            &config,
            true,
            "h1",
            |_| Ok(good_config()),
            |_| (true, 0, String::new()),
            || Err("systemctl restart exited 1".to_string()),
            || true,
        );
        assert_eq!(result.stage, "applied");
        assert!(result.error.as_deref().unwrap().contains("systemctl"));
        let _ = fs::remove_dir_all(&dir);
    }
}

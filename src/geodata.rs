//! Geodata: install and refresh `geoip.dat`/`geosite.dat` from XTLS.
//!
//! WHAT: download the latest XTLS/Xray-rules-dat release, verify the
//! publisher's SHA-256, decompress, and swap the two asset files Xray reads
//! from `XRAY_LOCATION_ASSET`.
//! WHY the node manages them: a routing rule that names `geoip:` or
//! `geosite:` is only meaningful with current data, and asking the operator
//! to copy two files onto every host would make every routing preset a
//! manual step. Xray reads the files at startup, so a successful swap
//! restarts it and a failed one restores the previous pair.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::Config;
use crate::util::random_hex;
use crate::xray::VERIFY_GRACE_SECS;

/// WHAT: the data repository and the two assets the node installs.
///
/// WHY `geoip-full`: the full edition carries per-country IP sets, which is
/// what a "block destinations in country X" rule needs; the lite edition
/// only has regional whitelists. `geosite.dat` is the standard domain list.
pub const RULES_REPO: &str = "XTLS/Xray-rules-dat";
pub const ASSETS: [(&str, &str); 2] = [
    ("geoip-full.dat.gz", "geoip.dat"),
    ("geosite.dat.gz", "geosite.dat"),
];
pub const DOWNLOAD_LIMIT: u64 = 64 * 1024 * 1024;
pub const INFLATE_LIMIT: usize = 512 * 1024 * 1024;
pub const REFRESH_SECS: i64 = 7 * 24 * 3600;
pub const RETRY_SECS: i64 = 24 * 3600;

/// WHAT: the decompressed bytes of a gzip stream.
///
/// WHY hand-rolled: the same reason the zip reader exists — no runtime tools
/// and no decompression crate beyond miniz_oxide. The gzip trailer's CRC is
/// not checked because the publisher's SHA-256 over the compressed bytes
/// already anchors them.
pub fn gunzip(data: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    if data.len() < 18 || data[0] != 0x1f || data[1] != 0x8b {
        return Err("gzip: bad magic".to_string());
    }
    let method = data[2];
    if method != 8 {
        return Err(format!("gzip: unsupported method {method}"));
    }
    let flags = data[3];
    let mut cursor = 10;
    if flags & 0x04 != 0 {
        let extra = data
            .get(cursor..cursor + 2)
            .ok_or("gzip: truncated extra length")?;
        cursor += 2 + u16::from_le_bytes([extra[0], extra[1]]) as usize;
    }
    for bit in [0x08u8, 0x10u8] {
        if flags & bit != 0 {
            let end = data[cursor..]
                .iter()
                .position(|byte| *byte == 0)
                .ok_or("gzip: unterminated string field")?;
            cursor += end + 1;
        }
    }
    if flags & 0x02 != 0 {
        cursor += 2;
    }
    let body = data
        .get(cursor..)
        .ok_or("gzip: truncated header")?;
    miniz_oxide::inflate::decompress_to_vec_with_limit(body, limit)
        .map_err(|error| format!("gzip: inflate failed ({error:?})"))
}

/// WHAT: `<hex>  <name>` → the lowercase hex digest.
pub fn parse_sha256(text: &str) -> Option<String> {
    let token = text.trim().split_whitespace().next()?;
    if token.len() == 64 && token.chars().all(|ch| ch.is_ascii_hexdigit()) {
        Some(token.to_ascii_lowercase())
    } else {
        None
    }
}

/// WHAT: remove staging files a previous run left in the asset directory.
pub fn cleanup_staged(cfg: &Config) {
    let Ok(entries) = fs::read_dir(&cfg.geodata_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') && name.contains(".next.") {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// WHAT: the installed asset paths for one config.
pub fn asset_paths(cfg: &Config) -> [PathBuf; 2] {
    [
        cfg.geodata_dir.join(ASSETS[0].1),
        cfg.geodata_dir.join(ASSETS[1].1),
    ]
}

/// WHAT: download, verify, and inflate one release asset.
pub fn fetch_asset(
    agent: &ureq::Agent,
    tag: &str,
    name: &str,
    limit: u64,
) -> Result<Vec<u8>, String> {
    let base =
        format!("https://github.com/{RULES_REPO}/releases/download/{tag}/{name}");
    let compressed = crate::net::fetch(agent, &base, limit)?;
    let sums = crate::net::fetch(agent, &format!("{base}.sha256sum"), 1 << 16)?;
    let expected = parse_sha256(&String::from_utf8_lossy(&sums))
        .ok_or_else(|| format!("{name}.sha256sum: no digest"))?;
    let actual = crate::net::sha256_hex(&compressed);
    if expected != actual {
        return Err(format!(
            "{name}: sha256 mismatch (expected {expected}, got {actual})"
        ));
    }
    gunzip(&compressed, INFLATE_LIMIT)
}

/// WHAT: write both assets, restart Xray, and roll back on a dead process.
///
/// WHY stage-then-rename: Xray may be starting concurrently (a restart from
/// the config path), and a half-written `.dat` would make it fail. The old
/// pair is kept as `.prev` until the new one proves itself.
pub fn install(
    cfg: &Config,
    geoip: &[u8],
    geosite: &[u8],
    restart: impl Fn() -> Result<(), String>,
    verify: impl Fn() -> bool,
) -> Result<(), String> {
    fs::create_dir_all(&cfg.geodata_dir).map_err(|error| {
        format!("mkdir {}: {error}", cfg.geodata_dir.display())
    })?;
    let paths = asset_paths(cfg);
    let payloads: [&[u8]; 2] = [geoip, geosite];
    let mut staged: Vec<PathBuf> = Vec::new();
    for (index, (asset, _)) in ASSETS.iter().enumerate() {
        let temp = cfg
            .geodata_dir
            .join(format!(".{asset}.next.{}", random_hex(6)));
        let written = fs::write(&temp, payloads[index])
            .and_then(|_| fs::set_permissions(&temp, fs::Permissions::from_mode(0o644)));
        if let Err(error) = written {
            let _ = fs::remove_file(&temp);
            for temp in &staged {
                let _ = fs::remove_file(temp);
            }
            return Err(format!("cannot stage {}: {error}", temp.display()));
        }
        staged.push(temp);
    }
    let mut backups: Vec<Option<PathBuf>> = Vec::new();
    for (index, path) in paths.iter().enumerate() {
        let backup = path.with_file_name(format!("{}.prev", ASSETS[index].1));
        let had_previous = path.exists();
        if had_previous {
            if let Err(error) = fs::copy(path, &backup) {
                for temp in &staged {
                    let _ = fs::remove_file(temp);
                }
                return Err(format!("cannot back up {}: {error}", path.display()));
            }
        }
        if let Err(error) = fs::rename(&staged[index], path) {
            for temp in &staged[index..] {
                let _ = fs::remove_file(temp);
            }
            return Err(format!("cannot install {}: {error}", path.display()));
        }
        backups.push(if had_previous { Some(backup) } else { None });
    }
    let restore = || {
        for (index, path) in paths.iter().enumerate() {
            if let Some(backup) = &backups[index] {
                let _ = fs::rename(backup, path);
            }
        }
    };
    if let Err(error) = restart() {
        restore();
        let _ = restart();
        return Err(format!("Xray restart after geodata update failed: {error}"));
    }
    std::thread::sleep(Duration::from_secs(VERIFY_GRACE_SECS));
    if verify() {
        return Ok(());
    }
    let restorable = backups.iter().any(Option::is_some);
    restore();
    let _ = restart();
    if restorable {
        Err("Xray did not stay up after the geodata update; rolled back".to_string())
    } else {
        Err("Xray did not stay up after the geodata update; no previous assets to restore"
            .to_string())
    }
}

/// WHAT: fetch and install the latest geodata release; returns its tag.
pub fn sync(
    agent: &ureq::Agent,
    cfg: &Config,
    restart: impl Fn() -> Result<(), String>,
    verify: impl Fn() -> bool,
) -> Result<String, String> {
    let tag = crate::net::latest_tag(agent, RULES_REPO)?;
    let [geoip, geosite] = [
        fetch_asset(agent, &tag, ASSETS[0].0, DOWNLOAD_LIMIT)?,
        fetch_asset(agent, &tag, ASSETS[1].0, DOWNLOAD_LIMIT)?,
    ];
    install(cfg, &geoip, &geosite, restart, verify)?;
    Ok(tag)
}

/// WHAT: should the automatic refresh run now?
///
/// WHY a fresh node installs once regardless of its config: the first
/// routing rule that needs `geoip:`/`geosite:` should not have to wait for
/// an admin action or fail its config test first. Later refreshes are
/// weekly, and only while a config actually references the data.
pub fn due(
    state: &crate::state::State,
    uses_geodata: bool,
    now: i64,
) -> bool {
    // A failure (including a failed first bootstrap) suppresses every attempt
    // until its backoff elapses, so a broken download is not retried on every
    // 30s poll.
    if let Some(retry_at) = state.geodata_retry_at {
        return now >= retry_at;
    }
    if state.geodata_version.is_none() {
        return true;
    }
    if !uses_geodata {
        return false;
    }
    match state.geodata_synced_at {
        Some(at) => now - at >= REFRESH_SECS,
        None => true,
    }
}

/// WHAT: true when the live config names a geodata category.
///
/// WHY a text search: the authored config is opaque JSON and the node has no
/// schema for it; `geoip:`/`geosite:` appear only as matcher strings, and a
/// false positive (a comment, a tag name) costs one extra weekly download at
/// worst.
pub fn config_uses_geodata(config_path: &Path) -> bool {
    match fs::read_to_string(config_path) {
        Ok(text) => text.contains("\"geoip:") || text.contains("\"geosite:"),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WHAT: gzip of "hello world\n" (mtime 0, deflate), fixed for the test.
    fn hello_gzip() -> Vec<u8> {
        vec![
            0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xcb, 0x48, 0xcd, 0xc9,
            0xc9, 0x57, 0x28, 0xcf, 0x2f, 0xca, 0x49, 0xe1, 0x02, 0x00, 0x2d, 0x3b, 0x08, 0xaf,
            0x0c, 0x00, 0x00, 0x00,
        ]
    }

    fn temp_cfg() -> Config {
        let dir = std::env::temp_dir().join(format!("lessv-geo-{}", random_hex(6)));
        fs::create_dir_all(&dir).unwrap();
        Config {
            geodata_dir: dir,
            ..Config::default()
        }
    }

    #[test]
    fn inflates_gzip_with_optional_fields() {
        assert_eq!(gunzip(&hello_gzip(), 1024).unwrap(), b"hello world\n");
        let mut named = hello_gzip();
        named[3] |= 0x08; // FNAME
        let mut with_name = named[..10].to_vec();
        with_name.extend_from_slice(b"geoip.dat\0");
        with_name.extend_from_slice(&named[10..]);
        assert_eq!(gunzip(&with_name, 1024).unwrap(), b"hello world\n");
        assert!(gunzip(b"not gzip", 1024).is_err());
    }

    #[test]
    fn parses_sha256sum_files() {
        let line = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  geoip.dat.gz\n";
        assert_eq!(
            parse_sha256(line).as_deref(),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        assert_eq!(parse_sha256("not a hash"), None);
    }

    #[test]
    fn installs_and_rolls_back_the_asset_pair() {
        let cfg = temp_cfg();
        let paths = asset_paths(&cfg);
        fs::write(&paths[0], b"old-geoip").unwrap();
        fs::write(&paths[1], b"old-geosite").unwrap();

        install(&cfg, b"new-geoip", b"new-geosite", || Ok(()), || true).unwrap();
        assert_eq!(fs::read(&paths[0]).unwrap(), b"new-geoip");
        assert_eq!(fs::read(&paths[1]).unwrap(), b"new-geosite");
        assert_eq!(fs::read(&paths[0].with_file_name("geoip.dat.prev")).unwrap(), b"old-geoip");

        let error = install(&cfg, b"bad-geoip", b"bad-geosite", || Ok(()), || false)
            .unwrap_err();
        assert!(error.contains("rolled back"));
        assert_eq!(fs::read(&paths[0]).unwrap(), b"new-geoip");
        assert_eq!(fs::read(&paths[1]).unwrap(), b"new-geosite");
        let _ = fs::remove_dir_all(&cfg.geodata_dir);
    }

    #[test]
    fn first_install_has_nothing_to_roll_back_to() {
        let cfg = temp_cfg();
        let error = install(&cfg, b"a", b"b", || Ok(()), || false).unwrap_err();
        assert!(error.contains("no previous assets"));
        let _ = fs::remove_dir_all(&cfg.geodata_dir);
    }

    #[test]
    fn due_schedule_follows_the_contract() {
        use crate::state::State;
        let mut state = State::default();
        assert!(due(&state, false, 0));
        state.geodata_version = Some("20261110".to_string());
        state.geodata_synced_at = Some(1_000_000);
        assert!(!due(&state, false, 1_000_001));
        assert!(!due(&state, true, 1_000_001));
        assert!(due(&state, true, 1_000_000 + REFRESH_SECS));
        state.geodata_retry_at = Some(1_000_100);
        assert!(!due(&state, true, 1_000_050));
        assert!(due(&state, true, 1_000_100));
        // A failed first bootstrap also waits for its backoff.
        let mut fresh = State::default();
        fresh.geodata_retry_at = Some(500);
        assert!(!due(&fresh, true, 400));
        assert!(due(&fresh, true, 500));
    }

    #[test]
    fn detects_geodata_references_in_a_config() {
        let dir = std::env::temp_dir().join(format!("lessv-geo-cfg-{}", random_hex(6)));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        fs::write(&path, br#"{"routing":{"rules":[{"ip":["geoip:cn"]}]}}"#).unwrap();
        assert!(config_uses_geodata(&path));
        fs::write(&path, br#"{"outbounds":[{"tag":"geoip"}]}"#).unwrap();
        assert!(!config_uses_geodata(&path));
        assert!(!config_uses_geodata(&dir.join("missing.json")));
        let _ = fs::remove_dir_all(&dir);
    }
}

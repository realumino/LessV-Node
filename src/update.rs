//! Xray binary updates: resolve a release, verify it, swap it, roll back.
//!
//! WHAT: fetch an Xray release archive from GitHub, verify the vendor's
//! published SHA-256, extract the `xray` executable without external tools,
//! test it against the live config, and swap it in only after the new
//! process survives.
//! WHY the node and not the plane: the node is the party that runs the
//! binary and can test it against its own live config; the plane records the
//! request and the reported outcome. Every step here either leaves the old
//! binary in place or restores it.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::util::random_hex;

/// WHAT: the release repository and the cap for one archive download.
pub const RELEASE_REPO: &str = "XTLS/Xray-core";
pub const DOWNLOAD_LIMIT: u64 = 128 * 1024 * 1024;

/// WHAT: the asset name for this machine's architecture.
///
/// WHY this table and not the raw triple: Xray names Linux archives by
/// architecture with a vendor suffix (`Xray-linux-arm64-v8a.zip`), which is
/// not the Rust target triple.
pub fn asset_name(arch: &str) -> Option<&'static str> {
    match arch {
        "x86_64" => Some("Xray-linux-64.zip"),
        "aarch64" => Some("Xray-linux-arm64-v8a.zip"),
        "arm" => Some("Xray-linux-arm32-v7a.zip"),
        "x86" => Some("Xray-linux-32.zip"),
        _ => None,
    }
}

/// WHAT: strip a leading `v` from a release tag (`v26.11.9` → `26.11.9`).
pub fn version_number(tag: &str) -> &str {
    tag.trim().trim_start_matches('v')
}

/// WHAT: true when `current` names the release `target`.
///
/// WHY not strict equality: the node's reported value is the bare version
/// (`26.11.9`), an operator may type the tag with or without the `v`, and a
/// vendor build may append a revision. The version number is the identity.
pub fn version_matches(current: &str, target: &str) -> bool {
    let wanted = version_number(target);
    if wanted.is_empty() || current.trim().is_empty() {
        return false;
    }
    current
        .split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .any(|token| token == wanted)
}

/// WHAT: parse a `.dgst` body or a `.sha256sum` body into a lowercase hex
/// digest.
///
/// WHY a token scan and not a prefix match: Xray's sidecar changed shape
/// between releases (`SHA256=<hex>` in current releases, `SHA2-256= <hex>`
/// in older ones), and the rules-dat release publishes `<hex>  <name>` in
/// `.sha256sum`. A 64-hex token is the digest in every one of them.
pub fn parse_digest(text: &str) -> Option<String> {
    for line in text.lines() {
        let value = line.split_once('=').map(|(_, rest)| rest).unwrap_or(line);
        for token in value.split_whitespace() {
            if token.len() == 64 && token.chars().all(|ch| ch.is_ascii_hexdigit()) {
                return Some(token.to_ascii_lowercase());
            }
        }
    }
    None
}

/// WHAT: lowercase hex SHA-256 of a byte slice.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// WHAT: a download agent with a long timeout for vendor archives.
///
/// WHY separate from the control-plane client: 16 MB from GitHub does not
/// fit the 10 s poll timeout, and a slow archive must never look like a
/// plane failure.
pub fn download_agent() -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(300)))
        .http_status_as_error(false)
        .user_agent(format!("lessv-node/{}", crate::http::VERSION))
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

/// WHAT: resolve `latest` to a concrete tag; pass a concrete tag through.
///
/// WHY validate the operator's tag: it becomes part of a download URL, so
/// anything but a release-looking tag is refused before any request.
pub fn resolve_target(agent: &ureq::Agent, requested: &str) -> Result<String, String> {
    let requested = requested.trim();
    if requested.is_empty() || requested == "latest" {
        return latest_tag(agent, RELEASE_REPO);
    }
    let bare = version_number(requested);
    let valid = !bare.is_empty()
        && bare.split('.').count() == 3
        && bare
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit()));
    if !valid {
        return Err(format!("invalid Xray version {requested:?}"));
    }
    Ok(requested.to_string())
}

/// WHAT: download and verify one release archive, returning the zip bytes.
pub fn download_archive(agent: &ureq::Agent, tag: &str) -> Result<Vec<u8>, String> {
    let asset = asset_name(std::env::consts::ARCH)
        .ok_or_else(|| format!("no Xray archive for architecture {}", std::env::consts::ARCH))?;
    let base = format!(
        "https://github.com/{RELEASE_REPO}/releases/download/{tag}/{asset}"
    );
    let archive = fetch(agent, &base, DOWNLOAD_LIMIT)?;
    let digest_url = format!("{base}.dgst");
    let digest_body = fetch(agent, &digest_url, 1 << 16)?;
    let expected = parse_digest(&String::from_utf8_lossy(&digest_body))
        .ok_or_else(|| format!("{digest_url}: no SHA256 line"))?;
    let actual = sha256_hex(&archive);
    if expected != actual {
        return Err(format!(
            "Xray archive sha256 mismatch (expected {expected}, got {actual})"
        ));
    }
    Ok(archive)
}

/// WHAT: read a little-endian u16/u32 at an offset, or None when short.
fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// WHAT: the offset of the ZIP end-of-central-directory record.
fn eocd_offset(zip: &[u8]) -> Option<usize> {
    if zip.len() < 22 {
        return None;
    }
    let start = zip.len().saturating_sub(22 + 0xFFFF);
    for offset in (start..=zip.len() - 22).rev() {
        if zip.get(offset..offset + 4) == Some(b"PK\x05\x06") {
            return Some(offset);
        }
    }
    None
}

/// WHAT: extract one stored-or-deflated entry from a ZIP archive.
///
/// WHY a hand-rolled reader: the release ships a zip and the node must stay
/// one static binary with no `unzip` runtime dependency. Only what Xray's
/// archives use is supported (stored and deflate, no encryption, no zip64),
/// and the archive's SHA-256 has already anchored every byte.
pub fn extract_entry(zip: &[u8], wanted: &str) -> Result<Vec<u8>, String> {
    let eocd = eocd_offset(zip).ok_or("zip: end of central directory not found")?;
    let entries = u16_at(zip, eocd + 10).ok_or("zip: truncated EOCD")? as usize;
    let mut cursor = u32_at(zip, eocd + 16).ok_or("zip: truncated EOCD")? as usize;
    for _ in 0..entries {
        if zip.get(cursor..cursor + 4) != Some(b"PK\x01\x02") {
            return Err("zip: bad central directory entry".to_string());
        }
        let flags = u16_at(zip, cursor + 8).ok_or("zip: truncated entry")?;
        let method = u16_at(zip, cursor + 10).ok_or("zip: truncated entry")?;
        let compressed = u32_at(zip, cursor + 20).ok_or("zip: truncated entry")? as usize;
        let name_len = u16_at(zip, cursor + 28).ok_or("zip: truncated entry")? as usize;
        let extra_len = u16_at(zip, cursor + 30).ok_or("zip: truncated entry")? as usize;
        let comment_len = u16_at(zip, cursor + 32).ok_or("zip: truncated entry")? as usize;
        let local_offset = u32_at(zip, cursor + 42).ok_or("zip: truncated entry")? as usize;
        let name = zip
            .get(cursor + 46..cursor + 46 + name_len)
            .ok_or("zip: truncated name")?;
        let is_wanted = name == wanted.as_bytes();
        cursor += 46 + name_len + extra_len + comment_len;
        if !is_wanted {
            continue;
        }
        if flags & 0x1 != 0 {
            return Err("zip: encrypted entries are not supported".to_string());
        }
        if zip.get(local_offset..local_offset + 4) != Some(b"PK\x03\x04") {
            return Err("zip: bad local header".to_string());
        }
        let local_name = u16_at(zip, local_offset + 26).ok_or("zip: truncated header")? as usize;
        let local_extra = u16_at(zip, local_offset + 28).ok_or("zip: truncated header")? as usize;
        let start = local_offset + 30 + local_name + local_extra;
        let data = zip
            .get(start..start + compressed)
            .ok_or("zip: truncated entry data")?;
        return match method {
            0 => Ok(data.to_vec()),
            8 => miniz_oxide::inflate::decompress_to_vec_with_limit(data, 256 * 1024 * 1024)
                .map_err(|error| format!("zip: inflate failed ({error:?})")),
            other => Err(format!("zip: unsupported compression method {other}")),
        };
    }
    Err(format!("zip: entry {wanted:?} not found"))
}

/// WHAT: remove staging files a previous run left in the binary directory.
///
/// WHY only our own dot-prefixed names: the directory belongs to the
/// operator as much as to this daemon; deleting anything else would be an
/// unrequested destructive act.
pub fn cleanup_staged(cfg: &crate::config::Config) {
    let Ok(target) = crate::xray::binary_path(&cfg.xray_binary) else {
        return;
    };
    let Some(parent) = target.parent() else {
        return;
    };
    let prefix = format!(
        ".{}.next.",
        target
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "xray".to_string())
    );
    if let Ok(entries) = fs::read_dir(parent) {
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(prefix.as_str())
            {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

/// WHAT: install one archive beside `target`, test it, swap, restart, verify.
///
/// WHY every seam is a parameter: the failure ordering (bad binary, failing
/// config test, dead process) is the property under test, and unit tests
/// drive all of it without a network, systemd, or a real Xray.
pub fn install(
    target: &Path,
    tag: &str,
    zip: &[u8],
    live_config: &Path,
    probe: impl Fn(&Path) -> Option<String>,
    test_config: impl Fn(&Path, &Path) -> (bool, i32, String),
    restart: impl Fn() -> Result<(), String>,
    verify: impl Fn() -> bool,
) -> Result<String, String> {
    let bytes = extract_entry(zip, "xray")?;
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| format!("mkdir {}: {error}", parent.display()))?;
    let staged = parent.join(format!(
        ".{}.next.{}",
        target
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "xray".to_string()),
        random_hex(6)
    ));
    let write = (|| -> std::io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .open(&staged)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o755))
    })();
    if let Err(error) = write {
        let _ = fs::remove_file(&staged);
        return Err(format!("cannot stage {}: {error}", staged.display()));
    }
    let installed = probe(&staged).ok_or_else(|| {
        let _ = fs::remove_file(&staged);
        "downloaded Xray does not report a version".to_string()
    })?;
    if !version_matches(&installed, tag) {
        let _ = fs::remove_file(&staged);
        return Err(format!(
            "downloaded Xray reports {installed}, expected {}",
            version_number(tag)
        ));
    }
    if live_config.exists() {
        let (ok, code, output) = test_config(&staged, live_config);
        if !ok {
            let _ = fs::remove_file(&staged);
            return Err(format!(
                "config test with the new Xray failed (exit {code}): {}",
                crate::util::tail(&output, 300)
            ));
        }
    }
    let backup = target.with_file_name(format!(
        "{}.lessv-backup",
        target
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "xray".to_string())
    ));
    let had_previous = target.exists();
    if had_previous {
        fs::copy(target, &backup).map_err(|error| {
            let _ = fs::remove_file(&staged);
            format!("cannot back up {}: {error}", target.display())
        })?;
    }
    fs::rename(&staged, target).map_err(|error| {
        let _ = fs::remove_file(&staged);
        format!("cannot replace {}: {error}", target.display())
    })?;
    if let Err(error) = restart() {
        if had_previous {
            let _ = fs::rename(&backup, target);
            let _ = restart();
            return Err(format!(
                "restart with the new Xray failed ({error}); rolled back to the previous binary"
            ));
        }
        return Err(format!("restart with the new Xray failed: {error}"));
    }
    std::thread::sleep(Duration::from_secs(crate::xray::VERIFY_GRACE_SECS));
    if verify() {
        return Ok(installed);
    }
    if had_previous {
        let restored = fs::rename(&backup, target);
        let _ = restart();
        match restored {
            Ok(()) => Err(format!(
                "Xray {installed} did not stay up; rolled back to the previous binary"
            )),
            Err(error) => Err(format!(
                "Xray {installed} did not stay up and the rollback failed: {error}"
            )),
        }
    } else {
        Err(format!(
            "Xray {installed} did not stay up; no previous binary to restore"
        ))
    }
}

/// WHAT: download and install one already-resolved release tag.
///
/// WHY the tag is resolved by the caller: `latest` resolution is a separate
/// network call, and the caller reports which version it decided to install
/// before the (large) archive download starts.
pub fn install_tag(
    agent: &ureq::Agent,
    target: &Path,
    tag: &str,
    live_config: &Path,
    test_config: impl Fn(&Path, &Path) -> (bool, i32, String),
    restart: impl Fn() -> Result<(), String>,
    verify: impl Fn() -> bool,
) -> Result<String, String> {
    let archive = download_archive(agent, tag)?;
    install(
        target,
        tag,
        &archive,
        live_config,
        crate::xray::version_number,
        test_config,
        restart,
        verify,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("lessv-update-{}", random_hex(6)));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// WHAT: build a minimal zip containing one entry.
    ///
    /// WHY stored entries: the parser's structure (EOCD, central directory,
    /// local header) is what this fixture must exercise; inflate has its own
    /// test below. Sizes and offsets are correct for a method-0 entry.
    fn zip_with(name: &str, data: &[u8], method: u16) -> Vec<u8> {
        let payload = if method == 8 {
            miniz_oxide::deflate::compress_to_vec(data, 9)
        } else {
            data.to_vec()
        };
        let mut out = Vec::new();
        // Local file header.
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&[0u8; 4]); // time + date
        out.extend_from_slice(&0u32.to_le_bytes()); // crc (unused)
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&payload);
        let cd_offset = out.len();
        // Central directory entry.
        out.extend_from_slice(b"PK\x01\x02");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        out.extend_from_slice(name.as_bytes());
        let cd_size = out.len() - cd_offset;
        // End of central directory.
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&(cd_size as u32).to_le_bytes());
        out.extend_from_slice(&(cd_offset as u32).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn reads_the_asset_table_and_version_numbers() {
        assert_eq!(asset_name("x86_64"), Some("Xray-linux-64.zip"));
        assert_eq!(asset_name("aarch64"), Some("Xray-linux-arm64-v8a.zip"));
        assert_eq!(asset_name("mips"), None);
        assert_eq!(version_number("v26.11.9"), "26.11.9");
        assert!(version_matches("26.11.9", "v26.11.9"));
        assert!(version_matches("v26.11.9", "26.11.9"));
        assert!(!version_matches("26.11.8", "v26.11.9"));
        assert!(!version_matches("", "latest"));
    }

    #[test]
    fn parses_both_digest_sidecar_shapes() {
        let dgst = "MD5=abc\nSHA1=def\nSHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
        assert_eq!(
            parse_digest(dgst).as_deref(),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        let sum = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210  geoip.dat.gz\n";
        assert_eq!(
            parse_digest(sum).as_deref(),
            Some("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
        );
        assert_eq!(parse_digest("not a digest"), None);
    }

    #[test]
    fn sha256_matches_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn extracts_stored_and_deflated_entries() {
        let stored = zip_with("xray", b"binary-bytes", 0);
        assert_eq!(extract_entry(&stored, "xray").unwrap(), b"binary-bytes");
        let deflated = zip_with("xray", b"binary-bytes", 8);
        assert_eq!(extract_entry(&deflated, "xray").unwrap(), b"binary-bytes");
        assert!(extract_entry(&stored, "README")
            .unwrap_err()
            .contains("not found"));
        assert!(extract_entry(&stored[..10], "xray").is_err());
    }

    #[test]
    fn installs_then_rolls_back_when_the_new_binary_dies() {
        let dir = temp_dir();
        let target = dir.join("xray");
        fs::write(&target, b"old").unwrap();
        let config = dir.join("config.json");
        fs::write(&config, b"{}").unwrap();
        let zip = zip_with("xray", b"new", 0);

        // The new binary stays up: replaced, backup kept.
        let version = install(
            &target,
            "v26.11.9",
            &zip,
            &config,
            |_| Some("26.11.9".to_string()),
            |_, _| (true, 0, String::new()),
            || Ok(()),
            || true,
        )
        .unwrap();
        assert_eq!(version, "26.11.9");
        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert_eq!(
            fs::read(dir.join("xray.lessv-backup")).unwrap(),
            b"old"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_dead_new_binary_restores_the_previous_one() {
        let dir = temp_dir();
        let target = dir.join("xray");
        fs::write(&target, b"old").unwrap();
        let config = dir.join("config.json");
        fs::write(&config, b"{}").unwrap();
        let zip = zip_with("xray", b"new", 0);

        let error = install(
            &target,
            "v26.11.9",
            &zip,
            &config,
            |_| Some("26.11.9".to_string()),
            |_, _| (true, 0, String::new()),
            || Ok(()),
            || false,
        )
        .unwrap_err();
        assert!(error.contains("rolled back"));
        assert_eq!(fs::read(&target).unwrap(), b"old");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failing_config_test_keeps_the_old_binary_and_runs_nothing() {
        let dir = temp_dir();
        let target = dir.join("xray");
        fs::write(&target, b"old").unwrap();
        let config = dir.join("config.json");
        fs::write(&config, b"{}").unwrap();
        let zip = zip_with("xray", b"new", 0);

        let error = install(
            &target,
            "v26.11.9",
            &zip,
            &config,
            |_| Some("26.11.9".to_string()),
            |_, _| (false, 23, "bad config".to_string()),
            || panic!("restart must not run"),
            || panic!("verify must not run"),
        )
        .unwrap_err();
        assert!(error.contains("bad config"));
        assert_eq!(fs::read(&target).unwrap(), b"old");
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".xray.next"))
            .collect();
        assert!(leftovers.is_empty(), "staged file left behind: {leftovers:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuses_a_download_that_reports_another_version() {
        let dir = temp_dir();
        let target = dir.join("xray");
        let zip = zip_with("xray", b"new", 0);
        let error = install(
            &target,
            "v26.11.9",
            &zip,
            &dir.join("missing.json"),
            |_| Some("26.11.10".to_string()),
            |_, _| (true, 0, String::new()),
            || Ok(()),
            || true,
        )
        .unwrap_err();
        assert!(error.contains("expected 26.11.9"));
        assert!(!target.exists());
        let _ = fs::remove_dir_all(&dir);
    }
}

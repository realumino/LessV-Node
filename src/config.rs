//! Node configuration: `/etc/lessv/node.toml`.
//!
//! WHAT: parse, validate, and atomically write the one file an operator may
//! edit by hand (the token is written by `enroll` and shown once).
//! WHY a hand-rolled flat parser: the file is a fixed set of scalar keys, so
//! a TOML crate would buy nothing and the whitelist here is what keeps a
//! typo from silently changing behavior. The file is never sourced and never
//! `eval`ed; values are data.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::util::atomic_write;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/lessv/node.toml";
pub const DEFAULT_STATE_PATH: &str = "/var/lib/lessv/state.json";
pub const DEFAULT_XRAY_CONFIG: &str = "/var/lib/lessv/config.json";
pub const DEFAULT_CERT_DIR: &str = "/etc/lessv/certs";
pub const DEFAULT_DECOY_ROOT: &str = "/var/www/lessv-decoy";
pub const DEFAULT_NGINX_CONF: &str = "/etc/nginx/conf.d/lessv-decoy.conf";
pub const DEFAULT_DECOY_SOCKET: &str = "/dev/shm/lessv-decoy.sock";
pub const DEFAULT_GEODATA_DIR: &str = "/var/lib/lessv/assets";

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub cp_url: String,
    pub node_id: String,
    pub token: String,
    pub poll_interval: u64,
    pub xray_binary: String,
    pub config_path: PathBuf,
    pub xray_service: String,
    /// `systemd`, `openrc`, `s6`, or `auto` (detect the running supervisor).
    pub restart_mode: String,
    pub auth: String,
    pub stats_interval: u64,
    pub manage_nginx: bool,
    pub cert_dir: PathBuf,
    pub nginx_service: String,
    pub nginx_conf_path: PathBuf,
    pub nginx_root: PathBuf,
    /// Unix socket the decoy listens on; REALITY's `dest` points here.
    pub nginx_socket: PathBuf,
    /// Directory Xray reads `geoip.dat`/`geosite.dat` from (the unit exports
    /// `XRAY_LOCATION_ASSET` with this path).
    pub geodata_dir: PathBuf,
    pub cert_group: String,
    pub state_path: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            cp_url: String::new(),
            node_id: String::new(),
            token: String::new(),
            poll_interval: 30,
            xray_binary: "xray".to_string(),
            config_path: PathBuf::from(DEFAULT_XRAY_CONFIG),
            xray_service: "xray".to_string(),
            restart_mode: "auto".to_string(),
            auth: "bearer-v1".to_string(),
            stats_interval: 60,
            manage_nginx: true,
            cert_dir: PathBuf::from(DEFAULT_CERT_DIR),
            nginx_service: "nginx".to_string(),
            nginx_conf_path: PathBuf::from(DEFAULT_NGINX_CONF),
            nginx_root: PathBuf::from(DEFAULT_DECOY_ROOT),
            nginx_socket: PathBuf::from(DEFAULT_DECOY_SOCKET),
            geodata_dir: PathBuf::from(DEFAULT_GEODATA_DIR),
            cert_group: String::new(),
            state_path: PathBuf::from(DEFAULT_STATE_PATH),
        }
    }
}

#[derive(Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ConfigError {}

/// WHAT: the config path, honoring an explicit flag then the env override.
///
/// WHY an env override: install scripts and tests need to point at a temp
/// copy without rewriting the unit file.
pub fn default_config_path(explicit: Option<&Path>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    std::env::var_os("LESSV_NODE_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))
}

fn unquote(value: &str) -> Result<String, ConfigError> {
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        let inner = &value[1..value.len() - 1];
        let mut out = String::new();
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            if ch != '\\' {
                out.push(ch);
                continue;
            }
            match chars.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some(other) => {
                    return Err(ConfigError(format!("unsupported escape \\{other}")))
                }
                None => return Err(ConfigError("trailing backslash".to_string())),
            }
        }
        return Ok(out);
    }
    if value.starts_with('"') {
        return Err(ConfigError("unterminated string".to_string()));
    }
    if value.len() >= 2 && value.starts_with('\'') && value.ends_with('\'') {
        return Ok(value[1..value.len() - 1].to_string());
    }
    Err(ConfigError(format!(
        "expected a quoted string, got {value:?}"
    )))
}

/// WHAT: parse the flat `key = value` subset this file uses.
///
/// WHY reject unknown keys: `pol_interval = 5` must fail loudly, not leave
/// the default in place while the operator believes otherwise.
pub fn parse(text: &str, path: &Path) -> Result<Config, ConfigError> {
    let mut raw: BTreeMap<String, String> = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        let lineno = index + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(ConfigError(format!("line {lineno}: expected `key = value`")));
        };
        let key = key.trim().replace('-', "_");
        let value = value.trim();
        if key.is_empty() || value.is_empty() {
            return Err(ConfigError(format!("line {lineno}: empty key or value")));
        }
        if raw.insert(key.clone(), value.to_string()).is_some() {
            return Err(ConfigError(format!("line {lineno}: duplicate key {key}")));
        }
    }

    let mut cfg = Config::default();
    for (key, value) in &raw {
        let as_string = |value: &str| -> Result<String, ConfigError> {
            unquote(value).map_err(|error| ConfigError(format!("key {key}: {}", error.0)))
        };
        match key.as_str() {
            "cp_url" => cfg.cp_url = as_string(value)?,
            "node_id" => cfg.node_id = as_string(value)?,
            "token" => cfg.token = as_string(value)?,
            "xray_binary" => cfg.xray_binary = as_string(value)?,
            "config_path" => cfg.config_path = PathBuf::from(as_string(value)?),
            "xray_service" => cfg.xray_service = as_string(value)?,
            "restart_mode" => cfg.restart_mode = as_string(value)?,
            "auth" => cfg.auth = as_string(value)?,
            "cert_dir" => cfg.cert_dir = PathBuf::from(as_string(value)?),
            "nginx_service" => cfg.nginx_service = as_string(value)?,
            "nginx_conf_path" => cfg.nginx_conf_path = PathBuf::from(as_string(value)?),
            "nginx_root" => cfg.nginx_root = PathBuf::from(as_string(value)?),
            "nginx_socket" => cfg.nginx_socket = PathBuf::from(as_string(value)?),
            "geodata_dir" => cfg.geodata_dir = PathBuf::from(as_string(value)?),
            "cert_group" => cfg.cert_group = as_string(value)?,
            "state_path" => cfg.state_path = PathBuf::from(as_string(value)?),
            "manage_nginx" => {
                cfg.manage_nginx = match value.as_str() {
                    "true" => true,
                    "false" => false,
                    _ => {
                        return Err(ConfigError(format!(
                            "key manage_nginx: expected true or false"
                        )))
                    }
                }
            }
            "poll_interval" => cfg.poll_interval = parse_int(key, value)?,
            "stats_interval" => cfg.stats_interval = parse_int(key, value)?,
            other => {
                return Err(ConfigError(format!(
                    "unsupported key {other:?} in {}",
                    path.display()
                )))
            }
        }
    }
    validate(cfg, path)
}

fn parse_int(key: &str, value: &str) -> Result<u64, ConfigError> {
    value
        .parse::<u64>()
        .map_err(|_| ConfigError(format!("key {key}: expected a non-negative integer")))
}

/// WHAT: apply every cross-field invariant, with enroll pointed to by name.
pub fn validate(mut cfg: Config, path: &Path) -> Result<Config, ConfigError> {
    for (field, value) in [
        ("cp_url", &cfg.cp_url),
        ("node_id", &cfg.node_id),
        ("token", &cfg.token),
    ] {
        if value.is_empty() {
            return Err(ConfigError(format!(
                "missing {field} in {} (run `lessv-node enroll` to create it)",
                path.display()
            )));
        }
    }
    if !cfg.cp_url.starts_with("http://") && !cfg.cp_url.starts_with("https://") {
        return Err(ConfigError(format!(
            "cp_url must start with http:// or https:// in {}",
            path.display()
        )));
    }
    cfg.cp_url = cfg.cp_url.trim_end_matches('/').to_string();
    if !(5..=600).contains(&cfg.poll_interval) {
        return Err(ConfigError(format!(
            "poll_interval must be 5..600 in {}",
            path.display()
        )));
    }
    if cfg.stats_interval == 0 || cfg.stats_interval > 86_400 {
        return Err(ConfigError(format!(
            "stats_interval must be 1..86400 in {}",
            path.display()
        )));
    }
    if !["systemd", "openrc", "s6", "auto"].contains(&cfg.restart_mode.as_str()) {
        return Err(ConfigError(format!(
            "restart_mode must be \"systemd\", \"openrc\", \"s6\", or \"auto\" in {}",
            path.display()
        )));
    }
    if cfg.auth != "bearer-v1" {
        return Err(ConfigError(format!(
            "auth {:?} not supported (only \"bearer-v1\") in {}",
            cfg.auth,
            path.display()
        )));
    }
    for (field, path_value) in [
        ("config_path", &cfg.config_path),
        ("cert_dir", &cfg.cert_dir),
        ("nginx_conf_path", &cfg.nginx_conf_path),
        ("nginx_root", &cfg.nginx_root),
        ("nginx_socket", &cfg.nginx_socket),
        ("geodata_dir", &cfg.geodata_dir),
        ("state_path", &cfg.state_path),
    ] {
        if !path_value.is_absolute() {
            return Err(ConfigError(format!(
                "{field} must be an absolute path in {}",
                path.display()
            )));
        }
    }
    if cfg.nginx_service.is_empty() || cfg.xray_service.is_empty() {
        return Err(ConfigError(format!(
            "service names must not be empty in {}",
            path.display()
        )));
    }
    Ok(cfg)
}

/// WHAT: load and validate `node.toml`.
pub fn load(explicit: Option<&Path>) -> Result<Config, ConfigError> {
    let path = default_config_path(explicit);
    let bytes = std::fs::read(&path).map_err(|_| {
        ConfigError(format!(
            "config not found at {} (run `lessv-node enroll --cp <url> --node <id>`)",
            path.display()
        ))
    })?;
    let text = String::from_utf8(bytes)
        .map_err(|_| ConfigError(format!("{} is not UTF-8", path.display())))?;
    parse(&text, &path)
}

fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// WHAT: render the canonical file (fixed key order, one key per line).
pub fn to_toml(cfg: &Config) -> String {
    let mut out = String::new();
    for (key, value) in [
        ("cp_url", cfg.cp_url.as_str()),
        ("node_id", cfg.node_id.as_str()),
        ("token", cfg.token.as_str()),
        ("xray_binary", cfg.xray_binary.as_str()),
        ("config_path", &cfg.config_path.to_string_lossy()),
        ("xray_service", cfg.xray_service.as_str()),
        ("restart_mode", cfg.restart_mode.as_str()),
        ("auth", cfg.auth.as_str()),
        ("cert_dir", &cfg.cert_dir.to_string_lossy()),
        ("nginx_service", cfg.nginx_service.as_str()),
        ("nginx_conf_path", &cfg.nginx_conf_path.to_string_lossy()),
        ("nginx_root", &cfg.nginx_root.to_string_lossy()),
        ("nginx_socket", &cfg.nginx_socket.to_string_lossy()),
        ("geodata_dir", &cfg.geodata_dir.to_string_lossy()),
        ("cert_group", cfg.cert_group.as_str()),
        ("state_path", &cfg.state_path.to_string_lossy()),
    ] {
        out.push_str(&format!("{key} = \"{}\"\n", escape(value)));
    }
    out.push_str(&format!("manage_nginx = {}\n", cfg.manage_nginx));
    out.push_str(&format!("poll_interval = {}\n", cfg.poll_interval));
    out.push_str(&format!("stats_interval = {}\n", cfg.stats_interval));
    out
}

/// WHAT: validate then atomically write the file with mode 0600.
///
/// WHY 0600: the token grants the fully rendered Xray config, which carries
/// every UUID and the REALITY private key.
pub fn save(path: &Path, cfg: &Config) -> Result<Config, ConfigError> {
    let cfg = validate(cfg.clone(), path)?;
    atomic_write(path, to_toml(&cfg).as_bytes(), 0o600)
        .map_err(|error| ConfigError(format!("cannot write {}: {error}", path.display())))?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn sample() -> Config {
        Config {
            cp_url: "https://cp.example.org/".to_string(),
            node_id: "tokyo01".to_string(),
            token: "secret".to_string(),
            ..Config::default()
        }
    }

    #[test]
    fn round_trips_every_field() {
        let dir = std::env::temp_dir().join(format!("lessv-cfg-{}", crate::util::random_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.toml");
        let mut cfg = sample();
        cfg.cert_group = "www-data".to_string();
        cfg.manage_nginx = false;
        cfg.restart_mode = "openrc".to_string();
        cfg.geodata_dir = PathBuf::from("/srv/lessv-assets");
        save(&path, &cfg).unwrap();
        let loaded = load(Some(&path)).unwrap();
        assert_eq!(loaded.geodata_dir, PathBuf::from("/srv/lessv-assets"));
        assert_eq!(loaded.cert_group, "www-data");
        assert!(!loaded.manage_nginx);
        assert_eq!(loaded.restart_mode, "openrc");
        assert_eq!(loaded.cp_url, "https://cp.example.org");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_unknown_keys_and_bad_values() {
        let path = Path::new("/tmp/node.toml");
        let err = parse("pol_interval = 5\n", path).unwrap_err();
        assert!(err.0.contains("unsupported key"));
        let err = parse(
            "cp_url = \"https://x\"\nnode_id = \"n\"\ntoken = \"t\"\npoll_interval = 1\n",
            path,
        )
        .unwrap_err();
        assert!(err.0.contains("poll_interval"));
        let err = parse(
            "cp_url = \"https://x\"\nnode_id = \"n\"\ntoken = \"t\"\nrestart_mode = \"docker\"\n",
            path,
        )
        .unwrap_err();
        assert!(err.0.contains("restart_mode"));
        let err = parse("token = \"unterminated\n", path).unwrap_err();
        assert!(err.0.contains("unterminated"));
    }

    #[test]
    fn missing_identity_points_at_enroll() {
        let err = parse("", Path::new("/tmp/node.toml")).unwrap_err();
        assert!(err.0.contains("enroll"));
    }

    #[test]
    fn accepts_s6_as_a_restart_mode() {
        let path = Path::new("/tmp/node.toml");
        let parsed = parse(
            "cp_url = \"https://x\"\nnode_id = \"n\"\ntoken = \"t\"\nrestart_mode = \"s6\"\n",
            path,
        )
        .unwrap();
        assert_eq!(parsed.restart_mode, "s6");
        // Misspellings stay loud: `s6-svc` is not the mode name.
        assert!(parse(
            "cp_url = \"https://x\"\nnode_id = \"n\"\ntoken = \"t\"\nrestart_mode = \"s6-svc\"\n",
            path,
        )
        .is_err());
    }

    #[test]
    fn escapes_quotes_and_backslashes() {
        let mut cfg = sample();
        cfg.token = "a\"b\\c".to_string();
        let text = to_toml(&cfg);
        let parsed = parse(&text, Path::new("/tmp/node.toml")).unwrap();
        assert_eq!(parsed.token, "a\"b\\c");
    }
}

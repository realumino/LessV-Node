//! `vela-server`: node-side reconciler for Vela.
//!
//! WHAT: `enroll` writes `/etc/vela/node.toml` and first-contacts the plane;
//! `run` is the daemon that converges Xray, certificates, and nginx.
//! WHY one static binary: no interpreter, no site-packages, no virtualenv.
//! It is built into the image, where s6 owns the three processes.

mod apply;
mod certs;
mod config;
mod geodata;
mod http;
mod net;
mod nginx;
mod reconcile;
mod state;
mod stats;
mod supervisor;
mod util;
mod xray;

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::json;

use crate::config::Config;
use crate::http::NodeClient;
use crate::util::{format_time, now_unix};

/// WHAT: set by SIGTERM/SIGINT; the loop checks it between 1s sleep slices.
static STOP: AtomicBool = AtomicBool::new(false);

pub fn log_info(message: &str) {
    println!("{} INFO {message}", format_time(now_unix()));
}

pub fn log_warn(message: &str) {
    println!("{} WARN {message}", format_time(now_unix()));
}

pub fn log_error(message: &str) {
    eprintln!("{} ERROR {message}", format_time(now_unix()));
}

fn usage() {
    println!(
        "vela-server {}\n\
         \n\
         usage:\n\
         \x20 vela-server enroll --cp <control-plane-url> --node <node-id> [options]\n\
         \x20 vela-server run [--config <path>] [--state <path>] [--verbose]\n\
         \x20 vela-server version\n\
         \n\
         enroll options: --config PATH, --poll-interval N, --xray-binary PATH,\n\
         \x20 --config-path PATH, --no-manage-nginx, --cert-dir PATH,\n\
         \x20 --nginx-conf-path PATH, --nginx-root PATH, --cert-group NAME, --state PATH,\n\
         \x20 --geodata-dir PATH\n\
         \n\
         The node token is read from stdin (hidden on a TTY); it is never an argument.",
        http::VERSION
    );
}

/// WHAT: value and boolean flags as written on the command line.
struct Flags {
    values: HashMap<String, String>,
    switches: Vec<String>,
}

impl Flags {
    fn value(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    fn switch(&self, name: &str) -> bool {
        self.switches.iter().any(|flag| flag == name)
    }
}

/// WHAT: parse `--key value` pairs and bare `--switch` flags.
///
/// WHY hand-rolled: the surface is a dozen options with no nesting,
/// completion, or help rendering worth a dependency in a static binary.
fn parse_flags(args: &[String], switches: &[&str]) -> Result<Flags, String> {
    let mut flags = Flags {
        values: HashMap::new(),
        switches: Vec::new(),
    };
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        let Some(name) = arg.strip_prefix("--") else {
            return Err(format!("unexpected argument {arg:?}"));
        };
        if switches.contains(&name) {
            flags.switches.push(name.to_string());
            index += 1;
            continue;
        }
        let Some(value) = args.get(index + 1) else {
            return Err(format!("--{name} needs a value"));
        };
        flags.values.insert(name.to_string(), value.clone());
        index += 2;
    }
    Ok(flags)
}

#[cfg(unix)]
fn install_signal_handlers() {
    extern "C" fn handler(_signal: libc::c_int) {
        STOP.store(true, Ordering::SeqCst);
    }
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        let function: extern "C" fn(libc::c_int) = handler;
        action.sa_sigaction = function as usize;
        action.sa_flags = 0;
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut());
    }
}

/// WHAT: read the node token from stdin, hiding it when stdin is a TTY.
///
/// WHY never a flag and never the environment: argv lands in `ps` and shell
/// history, the environment in `/proc/<pid>/environ`; stdin lands nowhere.
fn read_token() -> Result<String, String> {
    let is_tty = unsafe { libc::isatty(0) } == 1;
    if is_tty {
        eprint!("Node token (input hidden): ");
        let _ = std::io::stderr().flush();
    }
    let mut saved: Option<libc::termios> = None;
    if is_tty {
        unsafe {
            let mut term: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut term) == 0 {
                saved = Some(term);
                let mut hidden = term;
                hidden.c_lflag &= !(libc::ECHO as libc::tcflag_t);
                libc::tcsetattr(0, libc::TCSANOW, &hidden);
            }
        }
    }
    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line);
    if let Some(term) = saved {
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &term);
        }
        eprintln!();
    }
    match read {
        Ok(0) => Err("empty token; enroll aborted".to_string()),
        Ok(_) => {
            let token = line.trim().to_string();
            if token.is_empty() {
                Err("empty token; enroll aborted".to_string())
            } else {
                Ok(token)
            }
        }
        Err(error) => Err(format!("cannot read the token: {error}")),
    }
}

fn cmd_enroll(args: &[String]) -> i32 {
    let flags = match parse_flags(
        args,
        &["no-manage-nginx", "verbose"],
    ) {
        Ok(flags) => flags,
        Err(error) => {
            eprintln!("error: {error}");
            usage();
            return 2;
        }
    };
    let (Some(cp), Some(node)) = (flags.value("cp"), flags.value("node")) else {
        eprintln!("error: enroll needs --cp and --node");
        return 2;
    };
    let config_path = config::default_config_path(flags.value("config").map(PathBuf::from).as_deref());

    let token = match read_token() {
        Ok(token) => token,
        Err(error) => {
            eprintln!("error: {error}");
            return 2;
        }
    };

    let mut cfg = Config {
        cp_url: cp.to_string(),
        node_id: node.to_string(),
        token,
        ..Config::default()
    };
    if let Some(value) = flags.value("poll-interval") {
        match value.parse::<u64>() {
            Ok(interval) => cfg.poll_interval = interval,
            Err(_) => {
                eprintln!("error: --poll-interval must be an integer");
                return 2;
            }
        }
    }
    for (flag, field) in [
        ("xray-binary", &mut cfg.xray_binary),
        ("cert-group", &mut cfg.cert_group),
    ] {
        if let Some(value) = flags.value(flag) {
            *field = value.to_string();
        }
    }
    for (flag, field) in [
        ("config-path", &mut cfg.config_path),
        ("cert-dir", &mut cfg.cert_dir),
        ("nginx-conf-path", &mut cfg.nginx_conf_path),
        ("nginx-root", &mut cfg.nginx_root),
        ("geodata-dir", &mut cfg.geodata_dir),
        ("state", &mut cfg.state_path),
    ] {
        if let Some(value) = flags.value(flag) {
            *field = PathBuf::from(value);
        }
    }
    if flags.switch("no-manage-nginx") {
        cfg.manage_nginx = false;
    }

    // Validate and persist before any network call: a bad flag combination
    // must fail while nothing has been contacted yet.
    let cfg = match config::save(&config_path, &cfg) {
        Ok(cfg) => cfg,
        Err(error) => {
            eprintln!("error: {error}");
            return 2;
        }
    };
    log_info(&format!(
        "wrote {} (mode 0600)",
        config_path.display()
    ));

    let client = NodeClient::new(&cfg);
    let info = json!({
        "agent_version": http::VERSION,
        "xray_version": xray::binary_path(&cfg.xray_binary)
            .ok()
            .and_then(|path| xray::version_number(&path))
            .unwrap_or_else(|| "unknown".to_string()),
        "platform": xray::platform(),
    });
    match client.enroll(&info) {
        Ok(meta) => {
            let label = meta
                .get("label")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let address = meta
                .get("address")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            println!("enrolled node {} (label {label:?}, address {address:?})", cfg.node_id);
            0
        }
        Err(error) => {
            eprintln!("enroll request failed: {error}");
            eprintln!("(node.toml was still written; fix the plane and re-run enroll)");
            1
        }
    }
}

fn cmd_run(args: &[String]) -> i32 {
    let flags = match parse_flags(args, &["verbose"]) {
        Ok(flags) => flags,
        Err(error) => {
            eprintln!("error: {error}");
            usage();
            return 2;
        }
    };
    let cfg = match config::load(flags.value("config").map(PathBuf::from).as_deref()) {
        Ok(cfg) => cfg,
        Err(error) => {
            eprintln!("error: {error}");
            return 2;
        }
    };
    let state_path = flags
        .value("state")
        .map(PathBuf::from)
        .unwrap_or_else(|| cfg.state_path.clone());
    // The Xray unit exports XRAY_LOCATION_ASSET for the service itself; this
    // daemon also runs `xray run -test` and `xray version` as child
    // processes, and a child inherits only our environment. Without this a
    // config naming `geoip:`/`geosite:` fails its test even though the data
    // is installed.
    std::env::set_var("XRAY_LOCATION_ASSET", &cfg.geodata_dir);
    install_signal_handlers();
    apply::cleanup_temp_files(&cfg);
    geodata::cleanup_staged(&cfg);
    reconcile::run(&cfg, state_path, &STOP, flags.switch("verbose"))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("enroll") => cmd_enroll(&args[1..]),
        Some("run") => cmd_run(&args[1..]),
        Some("version") | Some("--version") | Some("-V") => {
            println!("vela-server {}", http::VERSION);
            0
        }
        Some("-h") | Some("--help") => {
            usage();
            0
        }
        Some(other) => {
            eprintln!("error: unknown command {other:?}");
            usage();
            2
        }
        None => {
            usage();
            2
        }
    };
    std::process::exit(code);
}

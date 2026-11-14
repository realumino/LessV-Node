//! Service supervision: systemd, OpenRC, and s6 behind one interface.
//!
//! WHAT: liveness, PID, restart, start, and reload for the Xray and nginx
//! units, whichever init system is running.
//! WHY an abstraction: the reconcile logic is identical on all three; only
//! the command vocabulary differs. OpenRC with supervise-daemon keeps its own
//! pidfile, and when that file is unreadable the honest answer is PID 0 —
//! never somebody else's PID. s6 answers the same questions through
//! `s6-svstat`, so no pidfile is involved there at all.

use std::path::Path;
use std::time::Duration;

use crate::util::run_command;

/// WHAT: where s6-overlay's supervision tree keeps one directory per service.
///
/// WHY this path: s6-svscan scans `/run/service` and s6-rc-init links every
/// compiled service directory into it, so `/run/service/<name>` is the
/// stable path a control command can address.
pub const S6_RUN_DIR: &str = "/run/service";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitSystem {
    Systemd,
    OpenRc,
    S6,
}

impl InitSystem {
    /// WHAT: detect the init system that owns this boot.
    ///
    /// WHY /run/systemd/system: it exists only when systemd is PID 1, which
    /// is the reliable test on containers and chroots where `systemctl`
    /// may be installed but not running.
    ///
    /// WHY s6 last: a host that has both `/sbin/rc-service` and an s6 tree
    /// must keep behaving exactly as it did before this backend existed.
    pub fn detect() -> Option<InitSystem> {
        if Path::new("/run/systemd/system").is_dir() {
            return Some(InitSystem::Systemd);
        }
        if Path::new("/sbin/rc-service").exists() || Path::new("/sbin/openrc-run").exists() {
            return Some(InitSystem::OpenRc);
        }
        if Path::new(S6_RUN_DIR).is_dir()
            && (Path::new("/command/s6-svstat").exists() || on_path("s6-svstat"))
        {
            return Some(InitSystem::S6);
        }
        None
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            InitSystem::Systemd => "systemd",
            InitSystem::OpenRc => "openrc",
            InitSystem::S6 => "s6",
        }
    }
}

/// WHAT: is `name` an entry on PATH?
///
/// WHY PATH rather than one fixed path: s6-overlay installs its binaries
/// under `/command` and exports that directory, while a distribution package
/// puts them in `/usr/bin`; both are legitimate s6 hosts.
fn on_path(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).any(|dir| dir.join(name).exists()))
        .unwrap_or(false)
}

pub struct Supervisor {
    pub init: InitSystem,
}

/// WHAT: the process name reported by /proc/<pid>/comm, trimmed.
fn process_name(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|text| text.trim().to_string())
}

/// WHAT: the real PID of `service`, or 0 when it cannot be established.
///
/// WHY not the pidfile alone: OpenRC's `supervise-daemon` writes its own PID
/// there, not the supervised child's. Reporting that as `xray_pid` would
/// name the wrong process, so the pidfile is only trusted when /proc says it
/// belongs to the service; otherwise /proc is scanned for a process with the
/// service's name (smallest PID wins, which is the nginx master).
fn service_pid(service: &str) -> u32 {
    if let Ok(text) = std::fs::read_to_string(format!("/run/{service}.pid")) {
        if let Ok(pid) = text.trim().parse::<u32>() {
            if pid > 0 && process_name(pid).as_deref() == Some(service) {
                return pid;
            }
        }
    }
    let mut matches: Vec<u32> = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            if pid > 0 && process_name(pid).as_deref() == Some(service) {
                matches.push(pid);
            }
        }
    }
    matches.sort_unstable();
    matches.first().copied().unwrap_or(0)
}

/// WHAT: parse `s6-svstat -o up,pid,updownfor` output into
/// (active, pid, seconds since the last up/down transition).
///
/// WHY this shape: s6-svstat prints the requested fields on one line,
/// space-separated, and ends with a newline — `true 1234 38` while the service
/// runs (`updownfor`: how long it has been in this state), `false -1 12` while
/// it does not, because the pid printer emits `-1` for "no live process"
/// rather than 0.
fn parse_svstat(text: &str) -> Option<(bool, u32, u64)> {
    let mut fields = text.split_whitespace();
    let up = match fields.next()? {
        "true" => true,
        "false" => false,
        _ => return None,
    };
    let pid = fields.next()?.parse::<i64>().ok()?;
    let since = fields.next()?.parse::<u64>().unwrap_or(0);
    Some((up, if pid > 0 { pid as u32 } else { 0 }, since))
}

/// WHAT: the shortest run of one supervised process that counts as "up".
///
/// WHY: s6-supervise restarts a dead longrun immediately, while systemd waits
/// `RestartSec=5` and reports `activating` in between. Without the settle
/// window a crash-looping Xray is "up" at almost every sample, so the agent's
/// "did it stay up after the restart?" would answer yes and never roll back —
/// measured on a real host: a config that passes `xray -test` but cannot bind
/// :80 was reported `stage: started, ok: true` while 443 was dead. The agent
/// samples 3 s after a restart, so 2 s still admits every healthy start.
const S6_SETTLE_SECS: u64 = 2;

/// WHAT: is this s6 sample a live, settled instance of `service`?
///
/// WHY the name check: the run scripts may be wrappers, and a supervised shell
/// that is waiting for the first config is not Xray. Reporting its pid as
/// `xray_pid` would name a process that serves nothing.
fn svstat_live(text: &str, service: &str) -> Option<(bool, u32)> {
    let (up, pid, since) = parse_svstat(text)?;
    let live = up && since >= S6_SETTLE_SECS && pid > 0 && process_name(pid).as_deref() == Some(service);
    Some((live, if live { pid } else { 0 }))
}

impl Supervisor {
    /// WHAT: resolve `restart_mode` (`systemd`, `openrc`, `s6`, `auto`) to a
    /// backend.
    ///
    /// WHY explicit modes still work: a unit file may pin the backend even
    /// when detection is ambiguous (e.g. running the binary inside a
    /// container that borrowed another init's filesystem).
    pub fn from_mode(mode: &str) -> Result<Supervisor, String> {
        let init = match mode {
            "systemd" => InitSystem::Systemd,
            "openrc" => InitSystem::OpenRc,
            "s6" => InitSystem::S6,
            "auto" => InitSystem::detect().ok_or_else(|| {
                "cannot detect an init system (no systemd, no OpenRC, no s6)".to_string()
            })?,
            other => return Err(format!("unknown restart_mode {other:?}")),
        };
        Ok(Supervisor { init })
    }

    fn program(&self) -> &'static str {
        match self.init {
            InitSystem::Systemd => "systemctl",
            InitSystem::OpenRc => "rc-service",
            InitSystem::S6 => "s6-svc",
        }
    }

    /// WHAT: the argv for one unit verb.
    ///
    /// WHY the shape differs: systemd takes the verb first
    /// (`systemctl restart xray`), OpenRC takes the service first
    /// (`rc-service xray restart`), and s6 takes a control letter before the
    /// service directory (`s6-svc -r /run/service/xray`). Getting this
    /// backwards is a silent "unknown command verb" at the restart stage, so
    /// the mapping lives in one tested function.
    fn command_args(&self, verb: &str, service: &str) -> Result<Vec<String>, String> {
        match self.init {
            InitSystem::Systemd => Ok(vec![verb.to_string(), service.to_string()]),
            InitSystem::OpenRc => Ok(vec![service.to_string(), verb.to_string()]),
            InitSystem::S6 => {
                // s6 has no word verbs: the control letter is the command.
                // `-h` is SIGHUP, which is exactly what `nginx -s reload`
                // sends, so the reload verb stays honest.
                let flag = match verb {
                    "start" => "-u",
                    "restart" => "-r",
                    "reload" => "-h",
                    other => {
                        return Err(format!(
                            "s6 has no {other:?} verb (start, restart, reload only)"
                        ))
                    }
                };
                Ok(vec![flag.to_string(), format!("{S6_RUN_DIR}/{service}")])
            }
        }
    }

    fn command(&self, verb: &str, service: &str, timeout: Duration) -> Result<String, String> {
        let program = self.program();
        let args = self.command_args(verb, service)?;
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        let result = run_command(program, &borrowed, timeout);
        if result.code == 0 {
            Ok(result.output)
        } else if result.timed_out {
            Err(format!("{program} {} timed out", args.join(" ")))
        } else {
            Err(if result.output.trim().is_empty() {
                format!("{program} {} exited {}", args.join(" "), result.code)
            } else {
                result.output.trim().to_string()
            })
        }
    }

    /// WHAT: is the unit active, and what is its main PID (0 when unknown)?
    ///
    /// WHY 0 rather than a guess: the heartbeat's `xray_pid` is display data;
    /// reporting a supervisor or unrelated PID would mislead the operator.
    pub fn status(&self, service: &str) -> (bool, u32) {
        match self.init {
            InitSystem::Systemd => {
                let active = run_command(
                    "systemctl",
                    &["is-active", "--quiet", service],
                    Duration::from_secs(10),
                );
                if active.code != 0 {
                    return (false, 0);
                }
                let show = run_command(
                    "systemctl",
                    &["show", service, "-p", "MainPID"],
                    Duration::from_secs(10),
                );
                let pid = if show.code == 0 {
                    show.output
                        .lines()
                        .find_map(|line| line.strip_prefix("MainPID="))
                        .and_then(|value| value.trim().parse::<u32>().ok())
                        .unwrap_or(0)
                } else {
                    0
                };
                (true, pid)
            }
            InitSystem::OpenRc => {
                let status = run_command(
                    "rc-service",
                    &[service, "status"],
                    Duration::from_secs(10),
                );
                if status.code != 0 {
                    return (false, 0);
                }
                (true, service_pid(service))
            }
            InitSystem::S6 => {
                let dir = format!("{S6_RUN_DIR}/{service}");
                let stat = run_command(
                    "s6-svstat",
                    &["-o", "up,pid,updownfor", &dir],
                    Duration::from_secs(10),
                );
                // WHY the printed fields and not the exit code: s6-svstat
                // exits 1 both for a down service and for a missing
                // s6-supervise, so only the fields tell them apart — and an
                // unparsable answer must read as down, never as up.
                svstat_live(&stat.output, service).unwrap_or((false, 0))
            }
        }
    }

    pub fn restart(&self, service: &str) -> Result<(), String> {
        self.command("restart", service, Duration::from_secs(30))
            .map(|_| ())
    }

    pub fn start(&self, service: &str) -> Result<(), String> {
        self.command("start", service, Duration::from_secs(30))
            .map(|_| ())
    }

    pub fn reload(&self, service: &str) -> Result<(), String> {
        self.command("reload", service, Duration::from_secs(30))
            .map(|_| ())
    }

    /// WHAT: reload when active, start when not.
    ///
    /// WHY the union: `reload` on an inactive unit fails, and "nginx was
    /// stopped and came back" is an acceptance case. Returns whether it had
    /// to start (so the caller can note it).
    pub fn reload_or_start(&self, service: &str) -> Result<bool, String> {
        if self.status(service).0 {
            self.reload(service)?;
            Ok(false)
        } else {
            self.start(service)?;
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_modes() {
        assert!(Supervisor::from_mode("bogus").is_err());
        assert_eq!(
            Supervisor::from_mode("systemd").unwrap().init,
            InitSystem::Systemd
        );
        assert_eq!(
            Supervisor::from_mode("openrc").unwrap().init,
            InitSystem::OpenRc
        );
        assert_eq!(Supervisor::from_mode("s6").unwrap().init, InitSystem::S6);
    }

    #[test]
    fn detection_never_panics() {
        // Whatever this host runs (or does not run), detection answers with
        // an Option rather than dying on a missing /run/service.
        let _ = InitSystem::detect();
    }

    #[test]
    fn unknown_service_has_no_pid() {
        assert_eq!(service_pid("lessv-node-does-not-exist"), 0);
    }

    #[test]
    fn argv_order_matches_each_init_system() {
        let systemd = Supervisor { init: InitSystem::Systemd };
        assert_eq!(
            systemd.command_args("restart", "xray"),
            Ok(vec!["restart".to_string(), "xray".to_string()])
        );
        let openrc = Supervisor { init: InitSystem::OpenRc };
        assert_eq!(
            openrc.command_args("restart", "xray"),
            Ok(vec!["xray".to_string(), "restart".to_string()])
        );
    }

    #[test]
    fn argv_for_s6_uses_control_letters() {
        let s6 = Supervisor { init: InitSystem::S6 };
        assert_eq!(s6.program(), "s6-svc");
        assert_eq!(
            s6.command_args("restart", "xray"),
            Ok(vec!["-r".to_string(), "/run/service/xray".to_string()])
        );
        assert_eq!(
            s6.command_args("start", "nginx"),
            Ok(vec!["-u".to_string(), "/run/service/nginx".to_string()])
        );
        assert_eq!(
            s6.command_args("reload", "nginx"),
            Ok(vec!["-h".to_string(), "/run/service/nginx".to_string()])
        );
        // A word verb is a bug here, not something to pass through.
        assert!(s6.command_args("stop", "xray").is_err());
    }

    #[test]
    fn parses_s6_svstat_output() {
        // Bytes as s6-svstat emits them (src/supervision/s6-svstat.c: one
        // space between the requested fields, one trailing newline, and pid
        // `-1` while the service is down). Captured from a live container:
        // `true 135 38` for a running service, `false -1 12` for a stopped one.
        assert_eq!(parse_svstat("true 4242 38\n"), Some((true, 4242, 38)));
        assert_eq!(parse_svstat("false -1 12\n"), Some((false, 0, 12)));
        // s6-svstat exits 1 with nothing on stdout when s6-supervise is not
        // running; that must read as down, and so must any other surprise.
        assert_eq!(parse_svstat(""), None);
        assert_eq!(parse_svstat("s6-svstat: fatal: error\n"), None);
    }

    #[test]
    fn a_freshly_restarted_service_is_not_yet_trusted() {
        // The crash-loop case: s6 restarted it a moment ago, so it reads `up`
        // but must not count as survived. The parser is pure, the process-name
        // check needs /proc, so this pins the settle rule alone.
        assert_eq!(parse_svstat("true 4242 0\n").unwrap().2, 0);
        assert!(S6_SETTLE_SECS >= 2);
        assert_eq!(parse_svstat("true 4242 3\n").unwrap().2 >= S6_SETTLE_SECS, true);
    }
}

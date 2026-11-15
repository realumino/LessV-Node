//! Service supervision through s6-overlay.
//!
//! WHAT: liveness, PID, restart, start, and reload for the Xray and nginx
//! services in the image's supervision tree.
//! WHY only s6: the server ships as one OCI image whose supervision tree owns
//! all three processes. A bare-metal install is not a delivery path, so there
//! is no init system to detect and no second command vocabulary to keep in
//! step. s6 answers every question through `s6-svstat`/`s6-svc`, with no
//! pidfile anywhere.

use std::time::Duration;

use crate::util::run_command;

/// WHAT: where s6-overlay's supervision tree keeps one directory per service.
///
/// WHY this path: s6-svscan scans `/run/service` and s6-rc-init links every
/// compiled service directory into it, so `/run/service/<name>` is the stable
/// path a control command can address.
pub const S6_RUN_DIR: &str = "/run/service";

/// WHAT: the shortest run of one supervised process that counts as "up".
///
/// WHY: s6-supervise restarts a dead longrun immediately, so without a settle
/// window a crash-looping Xray is "up" at almost every sample and the agent's
/// "did it stay up after the restart?" would answer yes and never roll back —
/// measured on a real host: a config that passes `xray -test` but cannot bind
/// :80 was reported `stage: started, ok: true` while 443 was dead. The agent
/// samples 3 s after a restart, so 2 s still admits every healthy start.
const S6_SETTLE_SECS: u64 = 2;

pub struct Supervisor;

/// WHAT: the process name reported by /proc/<pid>/comm, trimmed.
fn process_name(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|text| text.trim().to_string())
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

/// WHAT: is this s6 sample a live, settled instance of `service`?
///
/// WHY the name check: the run scripts are wrappers, and a supervised shell
/// that is waiting for the first config is not Xray. Reporting its pid as
/// `xray_pid` would name a process that serves nothing.
fn svstat_live(text: &str, service: &str) -> Option<(bool, u32)> {
    let (up, pid, since) = parse_svstat(text)?;
    let live =
        up && since >= S6_SETTLE_SECS && pid > 0 && process_name(pid).as_deref() == Some(service);
    Some((live, if live { pid } else { 0 }))
}

impl Supervisor {
    /// WHAT: send one s6 control letter to a service directory.
    ///
    /// WHY a letter and not a verb: s6-svc has no word verbs — `-u` starts,
    /// `-r` restarts, `-h` sends SIGHUP (which is what an nginx reload is).
    fn command(&self, flag: &str, service: &str, timeout: Duration) -> Result<String, String> {
        let dir = format!("{S6_RUN_DIR}/{service}");
        let result = run_command("s6-svc", &[flag, &dir], timeout);
        if result.code == 0 {
            Ok(result.output)
        } else if result.timed_out {
            Err(format!("s6-svc {flag} {dir} timed out"))
        } else if result.output.trim().is_empty() {
            Err(format!("s6-svc {flag} {dir} exited {}", result.code))
        } else {
            Err(result.output.trim().to_string())
        }
    }

    /// WHAT: is the service up, and what is its PID (0 when unknown)?
    ///
    /// WHY 0 rather than a guess: the heartbeat's `xray_pid` is display data;
    /// reporting a supervisor or unrelated PID would mislead the operator.
    pub fn status(&self, service: &str) -> (bool, u32) {
        let dir = format!("{S6_RUN_DIR}/{service}");
        let stat = run_command(
            "s6-svstat",
            &["-o", "up,pid,updownfor", &dir],
            Duration::from_secs(10),
        );
        // WHY the printed fields and not the exit code: s6-svstat exits 1 both
        // for a down service and for a missing s6-supervise, so only the
        // fields tell them apart — and an unparsable answer must read as down,
        // never as up.
        svstat_live(&stat.output, service).unwrap_or((false, 0))
    }

    pub fn restart(&self, service: &str) -> Result<(), String> {
        self.command("-r", service, Duration::from_secs(30))
            .map(|_| ())
    }

    pub fn start(&self, service: &str) -> Result<(), String> {
        self.command("-u", service, Duration::from_secs(30))
            .map(|_| ())
    }

    pub fn reload(&self, service: &str) -> Result<(), String> {
        self.command("-h", service, Duration::from_secs(30))
            .map(|_| ())
    }

    /// WHAT: reload when active, start when not.
    ///
    /// WHY the union: `-h` on an inactive service does nothing useful, and
    /// "nginx was stopped and came back" is an acceptance case. Returns
    /// whether it had to start (so the caller can note it).
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
    fn an_unknown_service_reads_as_down() {
        // No such service directory, and on a machine without s6 the command
        // is missing altogether; both must come back as (false, 0).
        assert_eq!(Supervisor.status("vela-server-does-not-exist"), (false, 0));
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

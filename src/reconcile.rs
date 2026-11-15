//! Reconcile loop: startup repair, heartbeat, apply, certificates, backoff.
//!
//! WHAT: the daemon's whole job — compare hashes, apply what differs, keep
//! certificates and nginx converged, and back off when the plane is away.
//! WHY content hashes: convergence needs no ordering. Equality plus a good
//! last apply means stop; anything else means fetch-and-apply. The plane
//! being down costs staleness and nothing else.

use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::json;

use crate::apply;
use crate::certs::{CertSyncer, SystemNginx};
use crate::config::Config;
use crate::geodata;
use crate::http::{bound_error, Action, HttpError, NodeClient};
use crate::state::{self, State};
use crate::stats;
use crate::supervisor::Supervisor;
use crate::net;
use crate::util::{now_unix, random_bytes};
use crate::xray;
use crate::{log_error, log_info, log_warn};

pub const BASE_BACKOFF_S: u64 = 5;
pub const MAX_BACKOFF_S: u64 = 300;

/// WHAT: capped exponential backoff (5s .. 300s) plus up to 10% jitter.
///
/// WHY jitter: a fleet that reconnects in lockstep would hammer a recovering
/// plane; the jitter spreads the first retries without delaying them much.
pub fn compute_backoff(attempt: u32) -> u64 {
    let exponent = attempt.min(16);
    let delay = BASE_BACKOFF_S
        .saturating_mul(1u64 << exponent)
        .min(MAX_BACKOFF_S) as f64;
    let jitter_cap = (delay * 0.1).min(5.0);
    let seed = random_bytes(4);
    let fraction = u32::from_be_bytes([seed[0], seed[1], seed[2], seed[3]]) as f64
        / u32::MAX as f64;
    (delay + fraction * jitter_cap) as u64
}

/// WHAT: does this heartbeat require an apply?
///
/// WHY not hash equality alone: a failed last apply means the node runs
/// something other than the hash it recorded.
pub fn needs_apply(state: &State, desired: Option<&str>) -> bool {
    match desired {
        None | Some("") => false,
        Some(hash) => state.applied_hash != hash || !state.last_apply_ok,
    }
}

pub struct Runner<'a> {
    pub cfg: &'a Config,
    pub client: &'a NodeClient,
    pub supervisor: &'a Supervisor,
    pub state_path: PathBuf,
    pub stop: &'a AtomicBool,
    /// The version of the binary this process runs, refreshed after an
    /// update. A `RefCell` (the loop is single-threaded) keeps the reported
    /// fact current without spawning `xray version` on every 30s poll.
    pub xray_version: RefCell<String>,
}

impl Runner<'_> {
    /// WHAT: the supervision-tree name of Xray.
    ///
    /// WHY a constant: the image's s6 tree names its services, and the server
    /// is only ever run from that image.
    fn service(&self) -> &'static str {
        "xray"
    }

    fn save(&self, state: &State) {
        if let Err(error) = state::save(&self.state_path, state) {
            log_error(&format!(
                "cannot write state {}: {error}",
                self.state_path.display()
            ));
        }
    }

    fn mark_broken(&self, state: &mut State, message: &str) {
        state.last_apply_ok = false;
        state.last_error = Some(bound_error(message));
    }

    /// WHAT: test the live config on every start; repair from last-good.
    ///
    /// WHY one rule makes kill -9 safe: no bad config survives a restart,
    /// including a kill between the swap and the report.
    pub fn startup(&self, state: &mut State) {
        let live = apply::live_path(self.cfg);
        if !live.exists() {
            log_warn(&format!(
                "startup: no live config at {}",
                live.display()
            ));
            self.mark_broken(state, "live config missing at startup; awaiting plane");
            self.save(state);
            return;
        }
        let (ok, code, output) = xray::test_config(&self.cfg.xray_binary, &live.to_string_lossy());
        if ok {
            log_info("startup: live config passed the Xray test");
            return;
        }
        log_error(&format!(
            "startup: live config failed test (exit {code}); restoring last-good"
        ));
        let restored = apply::restore_last_good(self.cfg);
        if restored {
            if let Err(error) = self.supervisor.restart(self.service()) {
                log_error(&format!("startup: restart after restore failed: {error}"));
            }
            self.mark_broken(state, "startup: live config broken, restored last-good");
        } else {
            self.mark_broken(
                state,
                &format!("startup: live config broken, no last-good: {output}"),
            );
        }
        self.save(state);
    }

    /// WHAT: one heartbeat-compare-act cycle.
    fn cycle(
        &self,
        state: &mut State,
        start_time: i64,
        last_stats: &mut i64,
    ) -> Result<(), HttpError> {
        // This host exists to run Xray: a stopped unit is repaired before
        // the heartbeat reports it, so the plane sees the recovered state.
        // A new process is a new boot for the absolute-counter contract.
        if !self.supervisor.status(self.service()).0 {
            match self.supervisor.start(self.service()) {
                Ok(()) => {
                    log_info("xray was down; started it");
                    state.xray_boot_id = stats::new_boot_id();
                }
                Err(error) => log_warn(&format!("xray start failed: {error}")),
            }
        }
        let (running, pid) = self.supervisor.status(self.service());
        let xray_version = self.xray_version.borrow().clone();
        let heartbeat = json!({
            "applied_hash": state.applied_hash,
            "applied_at": state.applied_at,
            "xray_running": running,
            "xray_pid": pid,
            "agent_uptime": (now_unix() - start_time).max(0),
            "agent_version": crate::http::VERSION,
            "xray_version": if xray_version.is_empty() { None } else { Some(xray_version) },
            "geodata_version": state.geodata_version,
            "last_error": state.last_error,
        });
        let (desired, actions) = self.client.heartbeat(&heartbeat)?;

        for action in actions {
            match action {
                Action::RestartXray => self.handle_restart_action(state),
                Action::UpdateGeodata => self.handle_geodata_update(state),
                Action::Unknown(name) => {
                    log_warn(&format!("plane asked for unknown action {name:?}; ignored"))
                }
            }
        }
        self.auto_geodata(state);

        if needs_apply(state, desired.as_deref()) {
            let hash = desired.unwrap_or_default();
            self.apply_desired(state, &hash);
        }
        self.sync_certificates(state);

        if now_unix() - *last_stats >= self.cfg.stats_interval as i64 {
            match self.client.stats(&stats::collect(state)) {
                Ok(()) => *last_stats = now_unix(),
                Err(error) => log_warn(&format!("stats skipped: {error}")),
            }
        }
        Ok(())
    }

    /// WHAT: fetch, apply, record, report one desired hash.
    fn apply_desired(&self, state: &mut State, hash: &str) {
        let cfg = self.cfg;
        let client = self.client;
        let supervisor = self.supervisor;
        let service = self.service().to_string();
        let xray_binary = cfg.xray_binary.clone();
        let result = apply::apply(
            cfg,
            state.last_apply_ok,
            hash,
            |wanted| {
                client
                    .fetch_config(wanted)
                    .map_err(|error| error.message)
                    .and_then(|payload| {
                        payload.ok_or_else(|| format!("config 304 for {wanted}"))
                    })
            },
            |path| xray::test_config(&xray_binary, &path.to_string_lossy()),
            || supervisor.restart(&service),
            || {
                std::thread::sleep(Duration::from_secs(xray::VERIFY_GRACE_SECS));
                supervisor.status(&service).0
            },
        );

        if result.ok {
            state.applied_hash = hash.to_string();
            state.applied_at = now_unix();
            state.last_apply_ok = true;
            state.last_error = None;
            state.xray_boot_id = stats::new_boot_id();
            log_info(&format!("applied config {hash}"));
        } else {
            let message = result
                .error
                .clone()
                .unwrap_or_else(|| format!("apply failed at {}", result.stage));
            state.last_apply_ok = false;
            state.last_error = Some(bound_error(&message));
            if message.to_lowercase().contains("rolled back") {
                state.xray_boot_id = stats::new_boot_id();
            }
            log_error(&format!(
                "apply {hash} failed at {}: {message}",
                result.stage
            ));
        }

        let report = json!({
            "hash": hash,
            "ok": result.ok,
            "stage": result.stage,
            "xray_exit_code": result.xray_exit_code,
            "error": result.error,
        });
        if let Err(error) = self.client.report(&report) {
            log_warn(&format!(
                "report failed (will re-sync next heartbeat): {error}"
            ));
        }
    }

    /// WHAT: ask the service for the live Xray version.
    fn current_xray_version(&self) -> String {
        xray::binary_path(&self.cfg.xray_binary)
            .ok()
            .and_then(|path| xray::version_number(&path))
            .unwrap_or_default()
    }

    /// WHAT: report one action's outcome; a failed report is only a warning.
    ///
    /// WHY not retried here: the action stays pending on the plane, so the
    /// next heartbeat re-advertises it. The node's own state (installed
    /// version, geodata tag) makes that repetition a no-op when it already
    /// succeeded.
    fn report_action(
        &self,
        action: &str,
        ok: bool,
        version: Option<&str>,
        error: Option<&str>,
    ) {
        let body = json!({
            "action": action,
            "ok": ok,
            "version": version,
            "error": error.map(bound_error),
        });
        if let Err(failure) = self.client.action_report(&body) {
            log_warn(&format!(
                "action {action} result not reported (will repeat next heartbeat): {failure}"
            ));
        }
    }

    /// WHAT: fetch and install the latest geodata release.
    ///
    /// WHY the caller reports: an admin-triggered action has a plane row to
    /// finish; the weekly automatic refresh has none.
    fn update_geodata(&self, state: &mut State) -> Result<String, String> {
        let agent = net::download_agent();
        let supervisor = self.supervisor;
        let service = self.service().to_string();
        let result = geodata::sync(
            &agent,
            self.cfg,
            || supervisor.restart(&service),
            || supervisor.status(&service).0,
        );
        match result {
            Ok(tag) => {
                log_info(&format!("geodata: installed release {tag}"));
                state.geodata_version = Some(tag.clone());
                state.geodata_synced_at = Some(now_unix());
                state.geodata_retry_at = None;
                Ok(tag)
            }
            Err(error) => {
                log_error(&format!("geodata update failed: {error}"));
                state.geodata_retry_at = Some(now_unix() + geodata::RETRY_SECS);
                Err(error)
            }
        }
    }

    /// WHAT: honor an admin `update_geodata` request (always refetches).
    fn handle_geodata_update(&self, state: &mut State) {
        match self.update_geodata(state) {
            Ok(tag) => self.report_action("update_geodata", true, Some(&tag), None),
            Err(error) => self.report_action("update_geodata", false, None, Some(&error)),
        }
    }

    /// WHAT: the weekly geodata refresh (and the one-time bootstrap).
    fn auto_geodata(&self, state: &mut State) {
        let uses = geodata::config_uses_geodata(&apply::live_path(self.cfg));
        if !geodata::due(state, uses, now_unix()) {
            return;
        }
        if let Err(error) = self.update_geodata(state) {
            log_warn(&format!("automatic geodata refresh skipped: {error}"));
        }
    }

    /// WHAT: run the certificate state machine in its own failure domain.
    ///
    /// WHY: a certificate or nginx problem must not disturb the Xray loop;
    /// the cert stage reports its own status and the next poll retries.
    fn sync_certificates(&self, state: &mut State) {
        let system = SystemNginx {
            supervisor: self.supervisor,
            service: "nginx".to_string(),
        };
        let client = self.client;
        let fetch = |etag: Option<&str>| {
            client
                .fetch_certs(etag)
                .map_err(|error| error.message)
        };
        let report = |body: serde_json::Value| client.report(&body).map_err(|error| error.message);
        let syncer = CertSyncer {
            cfg: self.cfg,
            nginx: &system,
            fetch: &fetch,
            report: &report,
            now: now_unix(),
        };
        syncer.run(state);
    }

    /// WHAT: honor a `restart_xray` action (restart unchanged, verify).
    fn handle_restart_action(&self, state: &mut State) {
        match xray::restart_and_verify(self.supervisor, self.service()) {
            Ok(()) => {
                state.xray_boot_id = stats::new_boot_id();
                log_info("action restart_xray: xray is running");
            }
            Err(error) => log_warn(&format!("action restart_xray failed: {error}")),
        }
    }

    /// WHAT: when Xray is down and the plane is away, still serve last-good.
    fn maybe_start_last_good(&self, state: &mut State) {
        if self.supervisor.status(self.service()).0 {
            return;
        }
        let live = apply::live_path(self.cfg);
        if !live.exists() && apply::last_good_path(self.cfg).exists() {
            apply::restore_last_good(self.cfg);
        }
        match self.supervisor.start(self.service()) {
            Ok(()) => state.xray_boot_id = stats::new_boot_id(),
            Err(error) => log_warn(&format!("last-good start attempt failed: {error}")),
        }
    }

    /// WHAT: run until `stop` is raised; sleep in 1s slices so SIGTERM is
    /// honored promptly.
    pub fn run(&self) {
        let start_time = now_unix();
        let mut failures: u32 = 0;
        let mut last_stats: i64 = 0;
        loop {
            let mut state = state::load(&self.state_path);
            let outcome = self.cycle(&mut state, start_time, &mut last_stats);
            self.save(&state);
            let delay = match outcome {
                Ok(()) => {
                    failures = 0;
                    self.cfg.poll_interval
                }
                Err(error) => {
                    log_warn(&format!("heartbeat failed: {error}"));
                    if error.auth_failed {
                        log_error("token rejected; keeping serving, backing off hard");
                        failures = (failures + 2).max(4);
                    } else {
                        failures += 1;
                    }
                    self.maybe_start_last_good(&mut state);
                    compute_backoff(failures)
                }
            };
            if self.stop.load(Ordering::Relaxed) {
                log_info("stop requested; exiting");
                return;
            }
            let deadline = std::time::Instant::now() + Duration::from_secs(delay);
            while std::time::Instant::now() < deadline {
                if self.stop.load(Ordering::Relaxed) {
                    log_info("stop requested; exiting");
                    return;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

/// WHAT: startup-check the live config and then run the loop.
pub fn run(cfg: &Config, state_path: PathBuf, stop: &AtomicBool, verbose: bool) -> i32 {
    let supervisor = Supervisor;
    log_info(&format!(
        "vela-server {} starting (control plane {}, node {}, init s6)",
        crate::http::VERSION,
        cfg.cp_url,
        cfg.node_id
    ));
    let client = NodeClient::new(cfg);
    let xray_version = xray::binary_path(&cfg.xray_binary)
        .ok()
        .and_then(|path| xray::version_number(&path))
        .unwrap_or_default();
    let runner = Runner {
        cfg,
        client: &client,
        supervisor: &supervisor,
        state_path,
        stop,
        xray_version: RefCell::new(xray_version),
    };
    let mut state = state::load(&runner.state_path);
    runner.startup(&mut state);
    if verbose {
        log_info("verbose mode: per-cycle decisions are logged at info level");
    }
    runner.run();
    0
}

/// WHAT: describe the drift between local state and a desired hash.
///
/// Kept as a tiny pure function so the loop's comparison can be exercised
/// without a daemon or a network.
#[cfg(test)]
pub fn describe_drift(state: &State, desired: Option<&str>) -> String {
    let desired = desired.unwrap_or("");
    if desired.is_empty() {
        return "no desired config".to_string();
    }
    if state.applied_hash == desired && state.last_apply_ok {
        return format!("in sync ({desired})");
    }
    format!(
        "drift: applied {}, desired {desired}, last apply {}",
        if state.applied_hash.is_empty() {
            "none"
        } else {
            state.applied_hash.as_str()
        },
        if state.last_apply_ok { "ok" } else { "failed" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backoff_is_bounded_and_jittered() {
        for attempt in 0..20 {
            let delay = compute_backoff(attempt);
            assert!(delay >= BASE_BACKOFF_S);
            assert!(delay <= MAX_BACKOFF_S + 5);
        }
        assert!(compute_backoff(0) <= BASE_BACKOFF_S + 5);
        assert!(compute_backoff(10) >= 300);
    }

    #[test]
    fn apply_decision_matches_protocol_semantics() {
        let mut state = State::default();
        assert!(!needs_apply(&state, None));
        assert!(!needs_apply(&state, Some("")));
        assert!(needs_apply(&state, Some("h1")));
        state.applied_hash = "h1".to_string();
        assert!(!needs_apply(&state, Some("h1")));
        state.last_apply_ok = false;
        assert!(needs_apply(&state, Some("h1")));
    }

    #[test]
    fn drift_description_names_the_hashes() {
        let state = State {
            applied_hash: "a".to_string(),
            ..State::default()
        };
        assert!(describe_drift(&state, Some("b")).contains("desired b"));
        assert!(describe_drift(&state, Some("a")).contains("in sync"));
        assert_eq!(describe_drift(&state, None), "no desired config");
    }
}

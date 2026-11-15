//! Shared helpers: time, randomness, atomic files, bounded subprocesses.
//!
//! WHY one module: every other module needs "now", a temp-file-then-rename
//! write, or a command whose failure is data rather than a panic. Keeping
//! those four primitives here is what makes kill -9 safe and keeps the
//! reconcile loop free of std plumbing.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// WHAT: current Unix time in seconds.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// WHAT: format Unix seconds as RFC 3339 UTC without a date-time crate.
///
/// WHY hand-rolled: journald and OpenRC logs both want a timestamp, and a
/// timezone-aware crate is a large dependency for one format string. The
/// civil-from-days algorithm is Howard Hinnant's, valid for 1970..9999.
pub fn format_time(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (hour, minute, second) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    )
}

/// WHAT: lowercase hex encoding.
pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// WHAT: `n` random bytes from /dev/urandom, with a time+PID fallback.
///
/// WHY a fallback: randomness here only spreads retry jitter and mints boot
/// ids; a container without /dev/urandom must still converge rather than
/// crash. Secrets (the node token) never come from this function.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    if let Ok(mut file) = File::open("/dev/urandom") {
        if file.read_exact(&mut buf).is_ok() {
            return buf;
        }
    }
    let mut state = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        ^ (std::process::id() as u64) << 32
        ^ COUNTER.fetch_add(1, Ordering::Relaxed);
    for byte in buf.iter_mut() {
        // xorshift64*, adequate as a fallback entropy stretcher only.
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        *byte = (state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 32) as u8;
    }
    buf
}

static COUNTER: AtomicU64 = AtomicU64::new(0x9e37_79b9_7f4a_7c15);

/// WHAT: random lowercase hex string of `bytes` bytes of entropy.
pub fn random_hex(bytes: usize) -> String {
    hex_encode(&random_bytes(bytes))
}

/// WHAT: a unique sibling path for a temp file (same directory = same fs).
fn temp_sibling(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!(".{name}.tmp.{}", random_hex(6)))
}

/// WHAT: write a file atomically with an explicit POSIX mode.
///
/// WHY temp + rename: a reader (nginx, Xray, the next agent start) sees the
/// old file or the new one, never a half-written one; a crash mid-write
/// leaves only a dot-prefixed temp file behind.
pub fn atomic_write(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let tmp = temp_sibling(path);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// WHAT: one subprocess result: exit code plus merged output.
pub struct CommandResult {
    pub code: i32,
    pub output: String,
    pub timed_out: bool,
}

/// WHAT: run a command with a hard timeout, merging stdout and stderr.
///
/// WHY not `Command::output()`: it has no timeout, and a wedged Xray or
/// systemctl would hang the reconcile loop forever. Reader threads drain
/// both pipes so a chatty command cannot deadlock against the wait.
pub fn run_command(program: &str, args: &[&str], timeout: Duration) -> CommandResult {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return CommandResult {
                code: 127,
                output: format!("command not found: {program} ({error})"),
                timed_out: false,
            }
        }
    };
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = stdout {
            let _ = pipe.read_to_end(&mut buf);
        }
        buf
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = stderr {
            let _ = pipe.read_to_end(&mut buf);
        }
        buf
    });
    let deadline = Instant::now() + timeout;
    let (code, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status.code().unwrap_or(1), false),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break (124, true);
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => break (1, false),
        }
    };
    let mut out = stdout_reader.join().unwrap_or_default();
    let mut err = stderr_reader.join().unwrap_or_default();
    out.append(&mut err);
    CommandResult {
        code,
        output: String::from_utf8_lossy(&out).into_owned(),
        timed_out,
    }
}

/// WHAT: last `limit` chars of a string (UTF-8 safe).
pub fn tail(text: &str, limit: usize) -> String {
    let mut chars: Vec<char> = text.chars().collect();
    if chars.len() > limit {
        chars = chars.split_off(chars.len() - limit);
    }
    chars.into_iter().collect()
}

/// WHAT: first `limit` chars of a string (UTF-8 safe).
pub fn head(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_timestamps() {
        assert_eq!(format_time(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_time(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(format_time(1_800_000_000), "2027-01-15T08:00:00Z");
    }

    #[test]
    fn atomic_write_replaces_and_keeps_mode() {
        let dir = std::env::temp_dir().join(format!("lessv-util-{}", random_hex(6)));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("file");
        atomic_write(&path, b"one", 0o600).unwrap();
        atomic_write(&path, b"two", 0o644).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn command_timeout_and_missing_binary() {
        let missing = run_command("vela-server-no-such-binary", &[], Duration::from_secs(1));
        assert_eq!(missing.code, 127);
        let slow = run_command("sh", &["-c", "sleep 5"], Duration::from_millis(200));
        assert!(slow.timed_out);
        assert_eq!(slow.code, 124);
        let ok = run_command("sh", &["-c", "echo hi; echo err >&2"], Duration::from_secs(5));
        assert_eq!(ok.code, 0);
        assert!(ok.output.contains("hi") && ok.output.contains("err"));
    }
}

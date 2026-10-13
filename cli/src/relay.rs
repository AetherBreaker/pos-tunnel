//! The relay as an operator reaches it (design sections 6.4 and 8): `tunnelctl` as `ctl` over OpenSSH's
//! client, and the login through a session's alias.

use std::fmt;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::ninja::Device;

/// A lease as `tunnelctl` prints it; what `posctl` doesn't use is ignored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Lease {
    pub port: u16,
    pub device_id: i64,
    /// Who opened it. An operator who joined later isn't recorded (design section 9).
    pub operator: String,
    /// When it was opened, as the relay printed it. Never compared with this machine's clock (design
    /// section 5): it only tells one session on a port from the next (design section 8).
    pub started: String,
    pub idle_remaining: u64,
    pub absolute_remaining: u64,
    /// The POS's tunnel is up.
    pub listening: bool,
}

/// `tunnelctl`'s exit status while the relay's daemon isn't answering (design section 6.4).
const EX_UNAVAILABLE: i32 = 75;
/// The first login as `support` on a POS waits for Windows to create its profile (design section 7.2).
const LOGIN_WAIT: Duration = Duration::from_secs(120);
/// For one `tunnelctl` command, which a healthy relay answers in a second or two.
const TUNNELCTL_WAIT: Duration = Duration::from_secs(30);

/// The relay's daemon isn't answering yet (design section 6.4).
#[derive(Debug)]
pub struct Starting;

impl fmt::Display for Starting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "the relay is starting: POS logins are paused until its daemon is ready, and a POS retries within 2 minutes",
        )
    }
}

impl std::error::Error for Starting {}

/// What the session commands do through `ssh`; tests stand in for it.
pub trait Relay {
    /// `tunnelctl <command>` as `ctl`; its output. Fails with `Starting` while the daemon isn't
    /// answering.
    fn tunnelctl(&self, command: &str) -> Result<String>;
    /// Logs in through a session's alias once (design section 7.2, step 8).
    fn login(&self, alias: &str) -> Result<()>;
}

/// `tunnelctl <command>`, its JSON reply read as `T`.
pub fn ask<T: DeserializeOwned>(relay: &dyn Relay, command: &str) -> Result<T> {
    let reply = relay.tunnelctl(command)?;
    serde_json::from_str(&reply)
        .with_context(|| format!("tunnelctl answered something else than expected: {reply}"))
}

/// Every lease the relay holds.
pub fn leases(relay: &dyn Relay) -> Result<Vec<Lease>> {
    ask(relay, "status")
}

/// The device's tunnel port, 20000 + its NinjaOne ID (design section 4).
pub fn port(device: &Device) -> Result<u16> {
    match u16::try_from(device.id) {
        Ok(id @ 1..=45535) => Ok(20000 + id),
        _ => bail!(
            "device ID {} is outside 1..45535, so it has no tunnel port",
            device.id
        ),
    }
}

/// The real relay: OpenSSH's client with the generated config, which holds the relay's address, its
/// pinned public key and the operator key (design section 8).
pub struct SshRelay {
    pub ssh: PathBuf,
    pub config: PathBuf,
}

/// Runs `command` to its end, or kills it at `limit`: `ConnectTimeout` covers the connection only,
/// and a relay that stalls after it (design section 6.5) would hang `posctl` with nothing said.
/// What it prints is read as it comes, so a reply longer than a pipe holds can't block it.
fn run(command: &mut Command, limit: Duration, what: &str) -> Result<Output> {
    fn drain(mut pipe: impl Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = pipe.read_to_end(&mut bytes);
            bytes
        })
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("running {}", command.get_program().display()))?;
    let stdout = child.stdout.take().map(drain);
    let stderr = child.stderr.take().map(drain);
    let deadline = Instant::now() + limit;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "{what} didn't come within {}",
                humantime::format_duration(limit)
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let read = |pipe: Option<std::thread::JoinHandle<Vec<u8>>>| {
        pipe.and_then(|pipe| pipe.join().ok()).unwrap_or_default()
    };
    Ok(Output {
        status,
        stdout: read(stdout),
        stderr: read(stderr),
    })
}

impl Relay for SshRelay {
    fn tunnelctl(&self, command: &str) -> Result<String> {
        let out = run(
            Command::new(&self.ssh)
                .arg("-F")
                .arg(&self.config)
                .args(["-o", "ConnectTimeout=15", "ctl@posctl-relay", "tunnelctl"])
                .args(command.split(' ')),
            TUNNELCTL_WAIT,
            "the relay's answer",
        )?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        match out.status.code() {
            Some(0) => Ok(String::from_utf8_lossy(&out.stdout).into_owned()),
            Some(EX_UNAVAILABLE) => Err(Starting.into()),
            // tunnelctl's own refusal, printed as "error: <why>".
            Some(1) => bail!(
                "the relay refused: {}",
                stderr.trim().trim_start_matches("error: ")
            ),
            _ => bail!("couldn't reach the relay: {}", stderr.trim()),
        }
    }

    fn login(&self, alias: &str) -> Result<()> {
        let out = run(
            Command::new(&self.ssh).arg("-F").arg(&self.config).args([
                "-o",
                "ConnectTimeout=30",
                alias,
                "exit",
            ]),
            LOGIN_WAIT,
            &format!("the login through {alias}"),
        )?;
        if !out.status.success() {
            bail!(
                "the login through {alias} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_port_is_20000_plus_the_device_id_within_range() {
        let device = |id: i64| {
            serde_json::from_value::<Device>(serde_json::json!({"id": id, "organizationId": 3}))
                .unwrap()
        };
        assert_eq!(port(&device(1)).unwrap(), 20001);
        assert_eq!(port(&device(45535)).unwrap(), 65535);
        for bad in [0, -4, 45536, 70000] {
            assert!(port(&device(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_lease_reads_from_tunnelctls_view() {
        // The relay's `_view`, with the fields posctl doesn't use.
        let view = r#"{"port": 20001, "device_id": 1, "operator": "Jacob", "started": "2026-10-13T15:00:00+00:00",
            "idle_deadline": "2026-10-14T03:00:00+00:00", "absolute_deadline": "2026-10-16T15:00:00+00:00",
            "idle_remaining": 43200, "absolute_remaining": 259200, "listening": false, "connections": 0}"#;
        let lease: Lease = serde_json::from_str(view).unwrap();
        assert_eq!(
            (lease.port, lease.operator.as_str(), lease.listening),
            (20001, "Jacob", false)
        );
        assert_eq!(lease.started, "2026-10-13T15:00:00+00:00");
    }

    #[test]
    fn a_command_that_never_ends_is_cut_off() {
        // Half a minute of nothing, as a relay that stalled after the handshake.
        let mut stalled = if cfg!(windows) {
            let mut ping = Command::new("ping");
            ping.args(["-n", "30", "127.0.0.1"]);
            ping
        } else {
            let mut sleep = Command::new("sleep");
            sleep.arg("30");
            sleep
        };
        let started = Instant::now();

        let error = run(
            &mut stalled,
            Duration::from_millis(300),
            "the relay's answer",
        )
        .unwrap_err()
        .to_string();

        assert_eq!(error, "the relay's answer didn't come within 300ms");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_long_reply_is_read_whole() {
        // More than a pipe holds (4 KB on Windows): unread, it would block the child for good.
        let mut long = if cfg!(windows) {
            let mut cmd = Command::new("cmd");
            cmd.args(["/c", "for /L %i in (1,1,2000) do @echo 0123456789"]);
            cmd
        } else {
            let mut sh = Command::new("sh");
            sh.args(["-c", "for i in $(seq 2000); do echo 0123456789; done"]);
            sh
        };

        let out = run(&mut long, Duration::from_secs(30), "the reply").unwrap();

        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).lines().count(), 2000);
    }
}

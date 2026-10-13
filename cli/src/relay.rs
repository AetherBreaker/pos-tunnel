//! The relay as an operator reaches it (design sections 6.4 and 8): `tunnelctl` as `ctl` over OpenSSH's
//! client, and the login through a session's alias.

use std::fmt;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
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

impl Relay for SshRelay {
    fn tunnelctl(&self, command: &str) -> Result<String> {
        let out = Command::new(&self.ssh)
            .arg("-F")
            .arg(&self.config)
            .args(["-o", "ConnectTimeout=15", "ctl@posctl-relay", "tunnelctl"])
            .args(command.split(' '))
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("running {}", self.ssh.display()))?;
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
        let mut child = Command::new(&self.ssh)
            .arg("-F")
            .arg(&self.config)
            .args(["-o", "ConnectTimeout=30", alias, "exit"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("running {}", self.ssh.display()))?;
        let deadline = Instant::now() + LOGIN_WAIT;
        loop {
            if let Some(status) = child.try_wait()? {
                if status.success() {
                    return Ok(());
                }
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    let _ = pipe.read_to_string(&mut stderr);
                }
                bail!("the login through {alias} failed: {}", stderr.trim());
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                bail!(
                    "the login through {alias} didn't finish within {}",
                    humantime::format_duration(LOGIN_WAIT)
                );
            }
            std::thread::sleep(Duration::from_millis(200));
        }
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
}

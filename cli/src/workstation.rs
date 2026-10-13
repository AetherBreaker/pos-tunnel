//! This workstation's side of its sessions (design section 8): the session state dir, the generated
//! `ssh` files, the `Include` line, and the OpenSSH client and agent that serve them.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use ssh_key::PrivateKey;

use crate::config::{self, Config, config_home, write_private};
use crate::keys;
use crate::relay::Lease;

/// A session this workstation holds a key for: `sessions/<device id>/session.toml`, beside
/// `session_key`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Session {
    /// The directory's name; not in the file.
    #[serde(skip)]
    pub device_id: i64,
    pub name: String,
    pub alias: String,
    /// The POS's SSH server public key, pinned in the generated `known_hosts`.
    pub host_key: String,
    /// The lease's `started` when this workstation connected: the same value on the relay is the same
    /// session.
    pub started: String,
}

pub struct Workstation {
    /// `posctl/sessions` in the config dir.
    pub sessions: PathBuf,
    /// `~/.ssh`, or `POSCTL_SSH_DIR` (tests).
    pub ssh_dir: PathBuf,
    /// OpenSSH's client.
    pub ssh: PathBuf,
    pub operator_key: PathBuf,
    pub relay: config::Relay,
}

/// The display name's slug, prefixed `pos-` unless it starts so (design section 4): `POS 000 Test` is
/// `pos-000-test`. The device ID stands in for an empty slug and is appended to one in `taken`.
pub fn alias(name: &str, device_id: i64, taken: &[&str]) -> String {
    let mut slug = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug = slug.trim_end_matches('-');
    let alias = if slug.is_empty() {
        format!("pos-{device_id}")
    } else if slug.starts_with("pos-") {
        slug.to_owned()
    } else {
        format!("pos-{slug}")
    };
    if taken.contains(&alias.as_str()) {
        format!("{alias}-{device_id}")
    } else {
        alias
    }
}

impl Workstation {
    pub fn new(config: &Config) -> Result<Workstation> {
        let relay = config.relay.clone().context(
            "no relay yet: run the `posctl relay set ...` line the admin sent (the admin: `posctl-admin relay keygen`)",
        )?;
        let ssh_dir = match std::env::var_os("POSCTL_SSH_DIR") {
            Some(dir) => dir.into(),
            None => dirs::home_dir()
                .context("this platform has no home directory")?
                .join(".ssh"),
        };
        // On Windows the client Windows ships, else Win32-OpenSSH's own install, never the first `ssh`
        // on `PATH`: under Git Bash that is MSYS's, which can't reach the Windows ssh-agent.
        let mut ssh = PathBuf::from("ssh");
        #[cfg(windows)]
        for (root, rest) in [
            ("SystemRoot", r"System32\OpenSSH\ssh.exe"),
            ("ProgramFiles", r"OpenSSH\ssh.exe"),
        ] {
            let path = std::env::var_os(root).map(|root| PathBuf::from(root).join(rest));
            if let Some(path) = path.filter(|path| path.exists()) {
                ssh = path;
                break;
            }
        }
        Ok(Workstation {
            sessions: config_home()?.join("posctl").join("sessions"),
            ssh_dir,
            ssh,
            operator_key: config.operator_key.clone(),
            relay,
        })
    }

    /// The generated `ssh` config: what `posctl`'s own `ssh` calls and every alias's hop read.
    pub fn config_file(&self) -> PathBuf {
        self.ssh_dir.join("posctl").join("config")
    }

    pub fn session_key(&self, device_id: i64) -> PathBuf {
        self.sessions
            .join(device_id.to_string())
            .join("session_key")
    }

    /// Stops when the operator key has a passphrase and `ssh-agent` doesn't hold it: `ssh` runs
    /// non-interactively, so it would be refused with no hint why (design section 8).
    pub fn check_operator_key(&self) -> Result<()> {
        let key = &self.operator_key;
        let text = fs::read_to_string(key).with_context(|| format!("reading {}", key.display()))?;
        let private = PrivateKey::from_openssh(&text)
            .with_context(|| format!("{} is not an OpenSSH private key", key.display()))?;
        if !private.is_encrypted() {
            return Ok(());
        }
        let public = keys::public_line(private.public_key())?;
        let ssh_add = self.ssh.with_file_name(if cfg!(windows) {
            "ssh-add.exe"
        } else {
            "ssh-add"
        });
        // An agent that isn't running fails here and counts as not holding it.
        let held = Command::new(ssh_add).arg("-L").output().is_ok_and(|out| {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .any(|line| keys::parse_public(line).is_ok_and(|listed| listed == public))
        });
        if held {
            return Ok(());
        }
        let start_agent = if cfg!(windows) {
            "  Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile', '-Command', 'Set-Service ssh-agent -StartupType Automatic; Start-Service ssh-agent'\n"
        } else {
            ""
        };
        bail!(
            "the operator key {0} has a passphrase and ssh-agent doesn't hold it. Add it once:\n{start_agent}  ssh-add \"{0}\"",
            key.display()
        );
    }

    /// The sessions this workstation holds state for, by device ID. Anything in the dir that isn't a
    /// session `save` wrote is left alone.
    pub fn held(&self) -> Result<Vec<Session>> {
        let entries = match fs::read_dir(&self.sessions) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(e).with_context(|| format!("reading {}", self.sessions.display()));
            }
        };
        let mut sessions = Vec::new();
        for entry in entries {
            let dir = entry?.path();
            let device_id = dir
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.parse::<i64>().ok());
            let session = fs::read_to_string(dir.join("session.toml"))
                .ok()
                .and_then(|text| toml::from_str::<Session>(&text).ok());
            if let (Some(device_id), Some(session)) = (device_id, session) {
                sessions.push(Session {
                    device_id,
                    ..session
                });
            }
        }
        sessions.sort_by_key(|session| session.device_id);
        Ok(sessions)
    }

    pub fn save(&self, session: &Session, key: &PrivateKey) -> Result<()> {
        keys::write_private_key(&self.session_key(session.device_id), key, None)?;
        let path = self
            .sessions
            .join(session.device_id.to_string())
            .join("session.toml");
        write_private(&path, toml::to_string(session)?.as_bytes())
    }

    /// Deletes a session's state, key included; no error if there is none.
    pub fn remove(&self, device_id: i64) -> Result<()> {
        let dir = self.sessions.join(device_id.to_string());
        match fs::remove_dir_all(&dir) {
            Err(e) if e.kind() != ErrorKind::NotFound => {
                Err(e).with_context(|| format!("deleting {}", dir.display()))
            }
            _ => Ok(()),
        }
    }

    /// Drops the state of every session the relay no longer holds as this workstation knew it (ended,
    /// or reopened elsewhere), rewrites the generated files, and returns the sessions still held.
    pub fn reconcile(&self, leases: &[Lease]) -> Result<Vec<Session>> {
        let (live, stale): (Vec<Session>, Vec<Session>) =
            self.held()?.into_iter().partition(|session| {
                leases
                    .iter()
                    .any(|l| l.device_id == session.device_id && l.started == session.started)
            });
        for session in &stale {
            self.remove(session.device_id)?;
        }
        self.write_ssh_files()?;
        Ok(live)
    }

    /// Rewrites the generated `config` and `known_hosts` whole from the config and the session state;
    /// nothing edits them in place (design section 8).
    pub fn write_ssh_files(&self) -> Result<()> {
        // Forward-slashed and quoted: a profile path may hold a space, and `ssh_config` reads a
        // backslash before a quote as an escape.
        let quoted = |path: &Path| format!("\"{}\"", path.to_string_lossy().replace('\\', "/"));
        let dir = self.ssh_dir.join("posctl");
        let known_hosts = quoted(&dir.join("known_hosts"));
        let mut config = format!(
            "# Generated by posctl and rewritten by every session command: edits are lost.\n\
             Host posctl-relay\n  HostName {}\n  Port {}\n  User jump\n  IdentityFile {}\n  IdentitiesOnly yes\n  \
             HostKeyAlias posctl-relay\n  UserKnownHostsFile {known_hosts}\n  StrictHostKeyChecking yes\n  BatchMode yes\n",
            self.relay.host,
            self.relay.port,
            quoted(&self.operator_key),
        );
        let mut hosts = format!("posctl-relay {}\n", self.relay.public_key);
        for session in self.held()? {
            // ProxyCommand, not ProxyJump: Windows' client hands its own -F to the jump unquoted, and
            // naming the client keeps the hop in it (and its agent) when Git Bash's ssh runs the alias.
            config.push_str(&format!(
                "\nHost {}\n  HostName localhost\n  Port {}\n  User support\n  \
                 ProxyCommand {} -F {} -W \"[%h]:%p\" posctl-relay\n  IdentityFile {}\n  IdentitiesOnly yes\n  \
                 HostKeyAlias pos-{}\n  UserKnownHostsFile {known_hosts}\n  StrictHostKeyChecking yes\n  BatchMode yes\n",
                session.alias,
                20000 + session.device_id,
                quoted(&self.ssh),
                quoted(&self.config_file()),
                quoted(&self.session_key(session.device_id)),
                session.device_id,
            ));
            hosts.push_str(&format!("pos-{} {}\n", session.device_id, session.host_key));
        }
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        fs::write(self.config_file(), config)?;
        fs::write(dir.join("known_hosts"), hosts)?;
        Ok(())
    }

    /// Makes `~/.ssh/config` read the generated file: adds `Include posctl/config` as its first line
    /// unless that line already precedes every `Host` and `Match` block (inside one it would apply to
    /// that block only). Returns whether it changed the file.
    pub fn ensure_include(&self) -> Result<bool> {
        let path = self.ssh_dir.join("config");
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        for line in text.lines() {
            // `Keyword value` or `Keyword=value`.
            let mut words = line
                .split(|c: char| c.is_whitespace() || c == '=')
                .filter(|word| !word.is_empty());
            let keyword = words.next().unwrap_or_default();
            if keyword.eq_ignore_ascii_case("Host") || keyword.eq_ignore_ascii_case("Match") {
                break;
            }
            if keyword.eq_ignore_ascii_case("Include") && words.any(|word| word == "posctl/config")
            {
                return Ok(false);
            }
        }
        fs::create_dir_all(&self.ssh_dir)?;
        fs::write(&path, format!("Include posctl/config\n\n{text}"))
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::workstation;

    const HOST_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBxRa3sySInLyRMMVSWz76+abOp7xOibpSn1v7vw1k4x";

    fn session(device_id: i64, alias: &str, started: &str) -> Session {
        Session {
            device_id,
            name: format!("POS {device_id}"),
            alias: alias.into(),
            host_key: HOST_KEY.into(),
            started: started.into(),
        }
    }

    fn lease(device_id: i64, started: &str) -> Lease {
        Lease {
            port: 20000 + device_id as u16,
            device_id,
            operator: "Jacob".into(),
            started: started.into(),
            idle_remaining: 100,
            absolute_remaining: 1000,
            listening: true,
        }
    }

    #[test]
    fn an_alias_is_the_names_slug_with_one_pos_prefix() {
        assert_eq!(alias("POS 000 Test", 1, &[]), "pos-000-test");
        assert_eq!(alias("  Front  Till #2 ", 7, &[]), "pos-front-till-2");
        assert_eq!(alias("POS", 7, &[]), "pos-pos");
        // Nothing usable in the name: the device ID.
        assert_eq!(alias("!!!", 7, &[]), "pos-7");
        // Another session on this workstation has the alias already.
        assert_eq!(alias("pos 001", 9, &["pos-001"]), "pos-001-9");
    }

    #[test]
    fn a_saved_session_reads_back_and_remove_deletes_it() {
        let ws = workstation("state");
        assert!(ws.held().unwrap().is_empty());
        let key = keys::generate("test").unwrap();
        ws.save(&session(4, "pos-004", "t1"), &key).unwrap();
        ws.save(&session(1, "pos-001", "t2"), &key).unwrap();
        // Not a session: left alone and not listed.
        fs::create_dir_all(ws.sessions.join("notes")).unwrap();
        assert_eq!(
            ws.held().unwrap(),
            [session(1, "pos-001", "t2"), session(4, "pos-004", "t1")]
        );
        assert_eq!(
            keys::public_of_file(&ws.session_key(4)).unwrap(),
            keys::public_line(key.public_key()).unwrap()
        );
        ws.remove(4).unwrap();
        ws.remove(4).unwrap();
        assert_eq!(ws.held().unwrap(), [session(1, "pos-001", "t2")]);
        assert!(ws.sessions.join("notes").exists());
    }

    #[test]
    fn reconcile_drops_sessions_the_relay_no_longer_holds_as_they_were() {
        let ws = workstation("reconcile");
        let key = keys::generate("test").unwrap();
        for (id, started) in [(1, "t1"), (2, "t2"), (3, "t3")] {
            ws.save(&session(id, &format!("pos-{id}"), started), &key)
                .unwrap();
        }
        // 1 is as it was; 2 was closed and reopened by someone else; 3 has no lease.
        let held = ws.reconcile(&[lease(1, "t1"), lease(2, "later")]).unwrap();
        assert_eq!(held, [session(1, "pos-1", "t1")]);
        assert_eq!(ws.held().unwrap(), held);
        let config = fs::read_to_string(ws.config_file()).unwrap();
        assert!(
            config.contains("Host pos-1\n") && !config.contains("Host pos-2\n"),
            "{config}"
        );
    }

    #[test]
    fn the_generated_files_hold_the_relay_and_one_entry_per_session() {
        let ws = workstation("files");
        let key = keys::generate("test").unwrap();
        ws.save(&session(1, "pos-000-test", "t1"), &key).unwrap();
        ws.write_ssh_files().unwrap();
        let slashed = |path: PathBuf| path.to_string_lossy().replace('\\', "/");
        let config = fs::read_to_string(ws.config_file()).unwrap();
        let hosts = slashed(ws.ssh_dir.join("posctl").join("known_hosts"));
        let relay = format!(
            "Host posctl-relay\n  HostName relay.example.com\n  Port 2222\n  User jump\n  IdentityFile \"{}\"\n  IdentitiesOnly yes\n  HostKeyAlias posctl-relay\n  UserKnownHostsFile \"{hosts}\"\n  StrictHostKeyChecking yes\n  BatchMode yes\n",
            slashed(ws.operator_key.clone())
        );
        let pos = format!(
            "Host pos-000-test\n  HostName localhost\n  Port 20001\n  User support\n  ProxyCommand \"ssh\" -F \"{}\" -W \"[%h]:%p\" posctl-relay\n  IdentityFile \"{}\"\n  IdentitiesOnly yes\n  HostKeyAlias pos-1\n  UserKnownHostsFile \"{hosts}\"\n  StrictHostKeyChecking yes\n  BatchMode yes\n",
            slashed(ws.config_file()),
            slashed(ws.session_key(1))
        );
        assert!(config.contains(&relay), "{config}");
        assert!(config.ends_with(&format!("\n{pos}")), "{config}");
        assert!(!config.contains('\\'), "{config}");
        assert_eq!(
            fs::read_to_string(ws.ssh_dir.join("posctl").join("known_hosts")).unwrap(),
            format!("posctl-relay ssh-ed25519 AAAARELAY\npos-1 {HOST_KEY}\n")
        );
    }

    /// OpenSSH itself reads the generated config, spaces in its paths included.
    #[test]
    fn ssh_parses_the_generated_config() {
        let ws = workstation("parse");
        let key = keys::generate("test").unwrap();
        ws.save(&session(1, "pos-000-test", "t1"), &key).unwrap();
        ws.write_ssh_files().unwrap();
        let out = Command::new("ssh")
            .arg("-G")
            .arg("-F")
            .arg(ws.config_file())
            .arg("pos-000-test")
            .output()
            .unwrap();
        let parsed = String::from_utf8_lossy(&out.stdout).to_lowercase();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let slashed = |path: PathBuf| path.to_string_lossy().replace('\\', "/").to_lowercase();
        for line in [
            "hostname localhost".to_owned(),
            "port 20001".to_owned(),
            "user support".to_owned(),
            "hostkeyalias pos-1".to_owned(),
            format!("identityfile {}", slashed(ws.session_key(1))),
            format!(
                "userknownhostsfile {}",
                slashed(ws.ssh_dir.join("posctl").join("known_hosts"))
            ),
        ] {
            assert!(
                parsed.lines().any(|l| l == line),
                "no `{line}` in:\n{parsed}"
            );
        }
        assert!(parsed.contains("proxycommand \"ssh\" -f "), "{parsed}");
    }

    #[test]
    fn the_include_goes_first_once_and_keeps_the_rest_of_the_file() {
        let ws = workstation("include");
        // No file yet.
        assert!(ws.ensure_include().unwrap());
        let path = ws.ssh_dir.join("config");
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "Include posctl/config\n\n"
        );
        assert!(!ws.ensure_include().unwrap());

        // An Include inside a Host block applies to that host only, so it doesn't count.
        let existing =
            "# mine\nHost Coolify_Server\n  HostName 10.0.0.1\n  Include posctl/config\n";
        fs::write(&path, existing).unwrap();
        assert!(ws.ensure_include().unwrap());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            format!("Include posctl/config\n\n{existing}")
        );

        // Already there before the first block, in ssh_config's other spellings.
        for present in [
            "ServerAliveInterval 30\ninclude other posctl/config\nHost x\n",
            "Include=posctl/config\nMatch all\n",
        ] {
            fs::write(&path, present).unwrap();
            assert!(!ws.ensure_include().unwrap(), "{present}");
            assert_eq!(fs::read_to_string(&path).unwrap(), present);
        }
    }

    #[test]
    fn an_operator_key_without_a_passphrase_needs_no_agent() {
        let ws = workstation("plain key");
        keys::write_private_key(&ws.operator_key, &keys::generate("op").unwrap(), None).unwrap();
        ws.check_operator_key().unwrap();
    }

    #[test]
    fn an_encrypted_operator_key_the_agent_lacks_is_refused_with_the_commands() {
        let ws = workstation("encrypted key");
        keys::write_private_key(&ws.operator_key, &keys::generate("op").unwrap(), Some("pw"))
            .unwrap();
        // A key generated here can't be in any agent.
        let error = ws.check_operator_key().unwrap_err().to_string();
        assert!(
            error.contains("has a passphrase and ssh-agent doesn't hold it")
                && error.contains(&format!("ssh-add \"{}\"", ws.operator_key.display())),
            "{error}"
        );
    }
}

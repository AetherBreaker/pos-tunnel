//! `posctl-admin`'s own files (design section 7.9) and its admin check.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::config::{config_home, write_private};
use crate::keys;

/// The admin's operator public key, built into the binary: `cli/admin.pub`, or `POSCTL_ADMIN_KEY` at
/// build time, which CI's integration job uses to build with a key of its own.
pub const ADMIN_KEY: &str = match option_env!("POSCTL_ADMIN_KEY") {
    Some(key) => key,
    None => include_str!("../admin.pub"),
};

/// Runs only for the admin: keeps these commands out of reach of an agent working through another
/// operator's `posctl`. Not a security boundary; the admin's NinjaOne sign-in is what can change the
/// fleet (design section 7.9).
pub fn require_admin(operator_key: &Path) -> Result<()> {
    if keys::public_of_file(operator_key)? != keys::parse_public(ADMIN_KEY)? {
        bail!(
            "posctl-admin is for the admin only: {} is not the admin's operator key",
            operator_key.display()
        );
    }
    Ok(())
}

pub fn dir() -> Result<PathBuf> {
    Ok(config_home()?.join("posctl-admin"))
}

/// The relay's SSH server private key, as last generated (the active one).
pub fn relay_key_path() -> Result<PathBuf> {
    Ok(dir()?.join("relay_key"))
}

pub fn signing_key_path() -> Result<PathBuf> {
    Ok(dir()?.join("signing_key"))
}

/// Where the repository keeps the release signing public key, in `ssh-keygen -Y verify`'s format.
pub const ALLOWED_SIGNERS: &str = "pos/allowed_signers";

/// The signing public key in `ALLOWED_SIGNERS` at the release tag `tag` of the repository at `repo`,
/// read from git and never from the checkout: a branch, a stale tree or an uncommitted edit can't
/// become what the fleet trusts. `refs/tags/` makes git refuse a branch or commit by that name.
pub fn signer_at_tag(repo: &Path, tag: &str) -> Result<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["show", &format!("refs/tags/{tag}:{ALLOWED_SIGNERS}")])
        .output()
        .context("running git")?;
    if !out.status.success() {
        bail!(
            "git has no {ALLOWED_SIGNERS} at tag '{tag}' (run this in a clone of pos-tunnel, after `git fetch --tags` if the release was made elsewhere): {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let key = text
        .split_once("ssh-ed25519")
        .map(|(_, rest)| format!("ssh-ed25519{rest}"))
        .with_context(|| format!("no ed25519 key in {ALLOWED_SIGNERS} at tag '{tag}'"))?;
    keys::parse_public(&key)
}

/// The relay's `RELAY_SSH_PRIVATE_KEY` line: base64 of the OpenSSH private key file (design section 6.1).
pub fn relay_env_line(private_key_text: &str) -> String {
    format!(
        "RELAY_SSH_PRIVATE_KEY={}",
        STANDARD.encode(private_key_text)
    )
}

/// The operators the relay lets in, the admin included: `operators.toml`, name to public key. Only
/// public keys are kept here (design section 7.9).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Operators {
    pub operators: BTreeMap<String, String>,
}

impl Operators {
    fn path() -> Result<PathBuf> {
        Ok(dir()?.join("operators.toml"))
    }

    pub fn load() -> Result<Operators> {
        let path = Operators::path()?;
        match fs::read_to_string(&path) {
            Ok(text) => {
                toml::from_str(&text).with_context(|| format!("{} is not valid", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Operators::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self) -> Result<()> {
        write_private(&Operators::path()?, toml::to_string(self)?.as_bytes())
    }

    pub fn add(&mut self, name: &str, public_key: String) -> Result<()> {
        check_operator_name(name)?;
        if self.operators.contains_key(name) {
            bail!("there is already an operator named '{name}'");
        }
        self.operators.insert(name.to_owned(), public_key);
        Ok(())
    }

    /// Refuses to remove the admin's own key, which would lock the admin out of the relay.
    pub fn remove(&mut self, name: &str, admin_key: &str) -> Result<()> {
        match self.operators.get(name) {
            None => bail!("no operator named '{name}'"),
            Some(key) if key == admin_key => {
                bail!("'{name}' is the admin: removing it would lock you out of the relay")
            }
            Some(_) => {
                self.operators.remove(name);
                Ok(())
            }
        }
    }

    /// The relay's `OPERATOR_KEYS` line: `<name>=<ed25519 base64>`, comma-separated (design section 6.1).
    pub fn env_line(&self) -> String {
        let entries: Vec<String> = self
            .operators
            .iter()
            .map(|(name, key)| {
                format!(
                    "{name}={}",
                    key.split_whitespace().nth(1).unwrap_or_default()
                )
            })
            .collect();
        format!("OPERATOR_KEYS={}", entries.join(","))
    }
}

/// The relay's operator-name pattern (its `keys.OPERATOR_NAME`).
pub fn check_operator_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
    {
        bail!("an operator name is letters, digits, '.', '_' and '-' only, got '{name}'");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_keys_line_lists_name_and_bare_base64() {
        let mut operators = Operators::default();
        operators
            .operators
            .insert("bob".into(), "ssh-ed25519 BBBB".into());
        operators
            .operators
            .insert("alice".into(), "ssh-ed25519 AAAA".into());
        assert_eq!(operators.env_line(), "OPERATOR_KEYS=alice=AAAA,bob=BBBB");
    }

    #[test]
    fn operators_refuse_a_duplicate_a_bad_name_and_removing_the_admin() {
        let mut operators = Operators::default();
        operators.add("admin", "ssh-ed25519 AAAA".into()).unwrap();
        operators.add("bob", "ssh-ed25519 BBBB".into()).unwrap();
        assert!(operators.add("bob", "ssh-ed25519 CCCC".into()).is_err());
        assert!(operators.add("a b", "ssh-ed25519 CCCC".into()).is_err());
        let error = operators
            .remove("admin", "ssh-ed25519 AAAA")
            .unwrap_err()
            .to_string();
        assert!(error.contains("lock you out"), "{error}");
        assert!(operators.remove("carol", "ssh-ed25519 AAAA").is_err());
        operators.remove("bob", "ssh-ed25519 AAAA").unwrap();
        assert_eq!(operators.env_line(), "OPERATOR_KEYS=admin=AAAA");
    }

    #[test]
    fn relay_line_is_base64_of_the_key_file() {
        assert_eq!(
            relay_env_line("-----BEGIN-----\n"),
            "RELAY_SSH_PRIVATE_KEY=LS0tLS1CRUdJTi0tLS0tCg=="
        );
    }

    #[test]
    fn operator_names_follow_the_relay() {
        check_operator_name("jacob.ogden_2-x").unwrap();
        for bad in ["", "a b", "a=b", "a,b", "é"] {
            assert!(check_operator_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn only_the_admin_key_passes() {
        let dir = std::env::temp_dir().join(format!("posctl-admin-{}", std::process::id()));
        let other = keys::generate("other").unwrap();
        keys::write_private_key(&dir.join("other"), &other, None).unwrap();
        let error = require_admin(&dir.join("other")).unwrap_err().to_string();
        assert!(error.contains("not the admin's operator key"), "{error}");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_signer_is_read_at_a_tag_and_never_from_the_checkout() {
        let dir = std::env::temp_dir().join(format!("posctl-signer-{}", std::process::id()));
        fs::create_dir_all(dir.join("pos")).unwrap();
        let git = |args: &[&str]| {
            let out = Command::new("git")
                .arg("-C")
                .arg(&dir)
                .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
                .args(["-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"])
                .args(args)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        let key = || keys::public_line(keys::generate("").unwrap().public_key()).unwrap();
        let (released, later) = (key(), key());
        let commit = |signer: &str| {
            let line = format!("pos-tunnel-release namespaces=\"pos-tunnel-release\" {signer}\n");
            fs::write(dir.join(ALLOWED_SIGNERS), line).unwrap();
            git(&["add", "."]);
            git(&["commit", "-q", "-m", "signer"]);
        };
        git(&["init", "-q", "-b", "main"]);
        commit(&released);
        git(&["tag", "v1"]);
        commit(&later);

        assert_eq!(signer_at_tag(&dir, "v1").unwrap(), released);
        // Only a tag names a release: a branch, a commit and a tag that doesn't exist are refused.
        for not_a_tag in ["main", "HEAD", "v2"] {
            let error = signer_at_tag(&dir, not_a_tag).unwrap_err().to_string();
            assert!(error.contains(&format!("at tag '{not_a_tag}'")), "{error}");
        }
        // Git's object files are read-only, which Windows may refuse to delete.
        let _ = fs::remove_dir_all(&dir);
    }
}

//! `posctl-admin`'s own files (design section 7.9) and its admin check.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

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
}

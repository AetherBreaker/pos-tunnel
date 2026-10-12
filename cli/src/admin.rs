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

/// Where the repository keeps the release signing public key, in `ssh-keygen -Y verify`'s format.
pub const ALLOWED_SIGNERS: &str = "pos/allowed_signers";

/// Where GitHub serves this repository's files at a ref: the repository the POSes download releases
/// from (`$ReleaseUrl` in `pos/ninja/Install-PosTunnel.ps1`).
pub const GITHUB_RAW: &str = "https://raw.githubusercontent.com/AetherBreaker/pos-tunnel";

/// The signing public key in `ALLOWED_SIGNERS` at the release tag `tag`, fetched from the repository on
/// GitHub (`raw` is `GITHUB_RAW` outside tests). No checkout or local repository is read: a branch, a
/// stale tree or an uncommitted edit can't become what the fleet trusts. Under `refs/tags/` GitHub
/// answers 404 for a branch, a commit or a missing tag (design section 7.9).
pub fn signer_at_tag(raw: &str, tag: &str) -> Result<String> {
    // The tag goes into a URL path; nothing that could leave `refs/tags/` is sent.
    if !tag.starts_with(|c: char| c.is_ascii_alphanumeric())
        || tag.contains("..")
        || !tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
    {
        bail!("'{tag}' is not a release tag (letters, digits, '.', '_' and '-')");
    }
    let url = format!("{raw}/refs/tags/{tag}/{ALLOWED_SIGNERS}");
    let mut response = crate::ninja::agent()
        .get(&url)
        .call()
        .with_context(|| format!("fetching {url}"))?;
    match response.status().as_u16() {
        200 => {}
        404 => bail!("GitHub has no {ALLOWED_SIGNERS} at tag '{tag}' (404 from {url})"),
        status => bail!("GitHub answered {status} for {url}"),
    }
    let text = response.body_mut().read_to_string()?;
    // One signer a line, `#` starting a comment; this system has exactly one signer.
    let signers: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    let [signer] = signers.as_slice() else {
        bail!(
            "{ALLOWED_SIGNERS} at tag '{tag}' holds {} signers; there must be exactly one",
            signers.len()
        );
    };
    let key = signer
        .split_once("ssh-ed25519")
        .map(|(_, rest)| format!("ssh-ed25519{rest}"))
        .with_context(|| {
            format!("the signer in {ALLOWED_SIGNERS} at tag '{tag}' has no ed25519 key")
        })?;
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
    fn the_signer_is_fetched_from_github_at_a_tag_and_only_a_tag() {
        let released = keys::public_line(keys::generate("").unwrap().public_key()).unwrap();
        let file = format!("pos-tunnel-release namespaces=\"pos-tunnel-release\" {released}\n");
        // GitHub's raw file host: a file under refs/tags/<tag>/, 404 for anything that isn't a tag.
        let fake = crate::fake::Fake::start(move |_, path, _| match path {
            "/refs/tags/v1.2.3/pos/allowed_signers" => (200, file.as_str().into()),
            _ => (404, "404: Not Found".into()),
        });
        assert_eq!(signer_at_tag(&fake.url, "v1.2.3").unwrap(), released);
        let error = signer_at_tag(&fake.url, "main").unwrap_err().to_string();
        assert!(
            error.contains("at tag 'main'") && error.contains("404"),
            "{error}"
        );
        // Nothing that could leave refs/tags/ in the URL is sent.
        for not_a_tag in ["", "..", "v1/../../heads/main", "v1?ref=main", ".hidden"] {
            let error = signer_at_tag(&fake.url, not_a_tag).unwrap_err().to_string();
            assert!(
                error.contains("is not a release tag"),
                "{not_a_tag}: {error}"
            );
        }
    }

    #[test]
    fn the_signer_file_must_hold_exactly_one_signer() {
        let key = keys::public_line(keys::generate("").unwrap().public_key()).unwrap();
        let one = format!(
            "# ssh-ed25519 AAAA an old key, in a comment\n\npos-tunnel-release namespaces=\"pos-tunnel-release\" {key} release\n"
        );
        let two = format!("{one}second namespaces=\"pos-tunnel-release\" {key}\n");
        let fake = crate::fake::Fake::start(move |_, path, _| match path {
            "/refs/tags/one/pos/allowed_signers" => (200, one.as_str().into()),
            "/refs/tags/two/pos/allowed_signers" => (200, two.as_str().into()),
            "/refs/tags/none/pos/allowed_signers" => (200, "# only a comment\n".into()),
            _ => (503, "busy".into()),
        });
        assert_eq!(signer_at_tag(&fake.url, "one").unwrap(), key);
        for (tag, expected) in [
            ("two", "holds 2 signers"),
            ("none", "holds 0 signers"),
            ("v9", "GitHub answered 503"),
        ] {
            let error = signer_at_tag(&fake.url, tag).unwrap_err().to_string();
            assert!(error.contains(expected), "{tag}: {error}");
        }
    }
}

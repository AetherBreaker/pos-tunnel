//! ed25519 key pairs in OpenSSH's formats (design section 3).

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey, PublicKey};

use crate::config::write_private;

pub fn generate(comment: &str) -> Result<PrivateKey> {
    let mut key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
    key.set_comment(comment);
    Ok(key)
}

/// `ssh-ed25519 <base64>` without the comment: the form the fields, the config and `OPERATOR_KEYS` use.
pub fn public_line(key: &PublicKey) -> Result<String> {
    let text = key.to_openssh()?;
    Ok(text
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" "))
}

/// An ed25519 public key in OpenSSH's one-line form, comment allowed; returned without it.
pub fn parse_public(text: &str) -> Result<String> {
    let key = PublicKey::from_openssh(text.trim())
        .with_context(|| format!("'{text}' is not an OpenSSH public key"))?;
    if key.algorithm() != Algorithm::Ed25519 {
        bail!("'{text}' is not an ed25519 key");
    }
    public_line(&key)
}

/// The OpenSSH private key file's text, encrypted with `passphrase` if given.
pub fn private_text(key: &PrivateKey, passphrase: Option<&str>) -> Result<String> {
    let key = match passphrase {
        Some(passphrase) => key.encrypt(&mut OsRng, passphrase)?,
        None => key.clone(),
    };
    Ok(key.to_openssh(LineEnding::LF)?.to_string())
}

pub fn write_private_key(path: &Path, key: &PrivateKey, passphrase: Option<&str>) -> Result<()> {
    write_private(path, private_text(key, passphrase)?.as_bytes())
}

/// The public half of an OpenSSH private key file, readable even when the file is encrypted.
pub fn public_of_file(path: &Path) -> Result<String> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let key = PrivateKey::from_openssh(&text)
        .with_context(|| format!("{} is not an OpenSSH private key", path.display()))?;
    public_line(key.public_key())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_written_key_reads_back_with_the_same_public_key() {
        let dir = std::env::temp_dir().join(format!("posctl-keys-{}", std::process::id()));
        let key = generate("test").unwrap();
        for (name, passphrase) in [("plain", None), ("encrypted", Some("pw"))] {
            write_private_key(&dir.join(name), &key, passphrase).unwrap();
            assert_eq!(
                public_of_file(&dir.join(name)).unwrap(),
                public_line(key.public_key()).unwrap()
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn public_lines_have_no_comment() {
        let line = public_line(generate("a comment").unwrap().public_key()).unwrap();
        assert!(
            line.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"),
            "{line}"
        );
        assert_eq!(line.split(' ').count(), 2);
        assert_eq!(parse_public(&format!("{line} someone@host")).unwrap(), line);
    }

    #[test]
    fn parse_public_refuses_other_keys_and_junk() {
        let rsa = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC7";
        for bad in ["", "ssh-ed25519", "ssh-ed25519 !!!", rsa] {
            assert!(parse_public(bad).is_err(), "{bad}");
        }
    }
}

#[cfg(test)]
mod openssh {
    use super::*;

    /// OpenSSH's `ssh-keygen` (which `poe sign-pos` signs with) reads an encrypted key this crate wrote.
    #[test]
    fn ssh_keygen_reads_an_encrypted_key() {
        let dir = std::env::temp_dir().join(format!("posctl-openssh-{}", std::process::id()));
        let key = generate("test").unwrap();
        write_private_key(&dir.join("k"), &key, Some("correct horse")).unwrap();
        let out = std::process::Command::new("ssh-keygen")
            .args(["-y", "-P", "correct horse", "-f"])
            .arg(dir.join("k"))
            .output()
            .unwrap();
        fs::remove_dir_all(&dir).unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            parse_public(&String::from_utf8(out.stdout).unwrap()).unwrap(),
            public_line(key.public_key()).unwrap()
        );
    }
}

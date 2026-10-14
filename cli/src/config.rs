//! `posctl/config.toml` and where both binaries keep their files.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// The relay's published SSH port.
pub const DEFAULT_RELAY_PORT: u16 = 2222;

/// Everything `posctl` needs besides the NinjaOne login. `posctl-admin init` writes it on the admin's
/// workstation, `posctl operator import` on the others.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub operator_key: PathBuf,
    pub ninjaone: NinjaOne,
    /// Absent until `posctl-admin relay keygen` or `posctl relay set`.
    pub relay: Option<Relay>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NinjaOne {
    /// `https://<region>.ninjarmm.com`, no trailing slash.
    pub base_url: String,
    /// The tenant's Native client app: PKCE, no secret.
    pub client_id: String,
    /// The one organization this system works on: only its devices are listed, only its fleet fields
    /// written.
    pub organization_id: i64,
    /// A device of that organization whose effective policy is this one is a POS.
    pub pos_policy_id: i64,
    pub install_script_id: i64,
    pub invoke_script_id: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Relay {
    pub host: String,
    pub port: u16,
    /// `ssh-ed25519 <base64>`, pinned in the generated `known_hosts`.
    pub public_key: String,
}

/// The platform config dir, or `POSCTL_CONFIG_HOME`: tests, and a second identity on one machine.
pub fn config_home() -> Result<PathBuf> {
    match std::env::var_os("POSCTL_CONFIG_HOME") {
        Some(dir) => Ok(dir.into()),
        None => dirs::config_dir().context("this platform has no config directory"),
    }
}

impl Config {
    pub fn path() -> Result<PathBuf> {
        Ok(config_home()?.join("posctl").join("config.toml"))
    }

    pub fn load() -> Result<Config> {
        let path = Config::path()?;
        let text = fs::read_to_string(&path).with_context(|| {
            format!(
                "no posctl config at {}: run `posctl operator import` (the admin: `posctl-admin init`)",
                path.display()
            )
        })?;
        toml::from_str(&text)
            .with_context(|| {
                format!(
                    "{} is not a config this posctl can read: the admin runs `posctl-admin init` again, an operator imports a new bundle (`posctl operator import`)",
                    path.display()
                )
            })
    }

    pub fn save(&self) -> Result<()> {
        write_private(&Config::path()?, toml::to_string(self)?.as_bytes())
    }
}

/// The relay a config file's text pins, read without the rest of the file: `init` rewrites the config
/// and must keep the pin even when the old file predates a field `Config` now requires.
pub fn pinned_relay(config_text: &str) -> Result<Option<Relay>> {
    #[derive(Deserialize)]
    struct Pin {
        relay: Option<Relay>,
    }
    Ok(toml::from_str::<Pin>(config_text)?.relay)
}

/// `<host>[:<port>]`, the port defaulting to the relay's.
pub fn parse_host_port(value: &str) -> Result<(String, u16)> {
    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) => (
            host,
            port.parse()
                .with_context(|| format!("bad port in '{value}'"))?,
        ),
        None => (value, DEFAULT_RELAY_PORT),
    };
    // The same host pattern Install-PosTunnel accepts from the posTunnelRelay field.
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        || port == 0
    {
        bail!("expected <host>[:<port>], got '{value}'");
    }
    Ok((host.to_owned(), port))
}

/// Writes `bytes` to `path`, creating its directory. Unix gets mode 0600; on Windows the file is as
/// private as its dir: the per-user config dir keeps other users out, and a `POSCTL_CONFIG_HOME` is
/// the operator's to choose.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
    }
    #[cfg(not(unix))]
    fs::write(path, bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_defaults_to_the_relay_port() {
        assert_eq!(
            parse_host_port("relay.example.com").unwrap(),
            ("relay.example.com".into(), 2222)
        );
        assert_eq!(
            parse_host_port("10.0.0.5:2200").unwrap(),
            ("10.0.0.5".into(), 2200)
        );
    }

    #[test]
    fn host_port_refuses_anything_install_would() {
        for bad in [
            "",
            ":2222",
            "relay:0",
            "relay:x",
            "re lay",
            "relay:70000",
            "relay/x",
        ] {
            assert!(parse_host_port(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn config_round_trips_through_toml() {
        let config = Config {
            operator_key: "C:/keys/operator".into(),
            ninjaone: NinjaOne {
                base_url: "https://us2.ninjarmm.com".into(),
                client_id: "abc".into(),
                organization_id: 3,
                pos_policy_id: 7,
                install_script_id: 93,
                invoke_script_id: 94,
            },
            relay: Some(Relay {
                host: "relay.example.com".into(),
                port: 2222,
                public_key: "ssh-ed25519 AAAA".into(),
            }),
        };
        assert_eq!(
            toml::from_str::<Config>(&toml::to_string(&config).unwrap()).unwrap(),
            config
        );
    }

    #[test]
    fn the_pinned_relay_survives_a_config_that_predates_a_field() {
        // As written before `organization_id` existed.
        let old = "operator_key = \"k\"\n\n[ninjaone]\nbase_url = \"https://us2.ninjarmm.com\"\nclient_id = \"abc\"\npos_policy_id = 7\ninstall_script_id = 93\ninvoke_script_id = 94\n\n[relay]\nhost = \"relay.example.com\"\nport = 2222\npublic_key = \"ssh-ed25519 AAAA\"\n";
        assert!(toml::from_str::<Config>(old).is_err());
        assert_eq!(
            pinned_relay(old).unwrap(),
            Some(Relay {
                host: "relay.example.com".into(),
                port: 2222,
                public_key: "ssh-ed25519 AAAA".into(),
            })
        );
        assert_eq!(pinned_relay("operator_key = \"k\"\n").unwrap(), None);
    }
}

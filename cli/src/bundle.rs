//! The operator bundle (design section 7.9): one line `posctl-admin operator add` prints and
//! `posctl operator import` reads, base64 of a small TOML document holding the new operator's private
//! key and the admin's config. It holds a private key, so it travels like a password.

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::config::Config;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Bundle {
    /// The OpenSSH private key file's text.
    pub operator_key: String,
    /// The admin's config; `import` replaces `operator_key` with where it stores the key.
    pub config: Config,
}

impl Bundle {
    pub fn encode(&self) -> Result<String> {
        Ok(STANDARD.encode(toml::to_string(self)?))
    }

    pub fn decode(line: &str) -> Result<Bundle> {
        let bytes = STANDARD.decode(line.trim()).context("not an operator bundle (bad base64)")?;
        toml::from_str(std::str::from_utf8(&bytes)?).context("not an operator bundle")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NinjaOne, Relay};

    #[test]
    fn a_bundle_round_trips_and_junk_is_refused() {
        let bundle = Bundle {
            operator_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n".into(),
            config: Config {
                operator_key: "unused".into(),
                ninjaone: NinjaOne {
                    base_url: "https://us2.ninjarmm.com".into(),
                    client_id: "id".into(),
                    pos_policy_id: 7,
                    install_script_id: 93,
                    invoke_script_id: 94,
                },
                relay: Some(Relay { host: "relay.example.com".into(), port: 2222, public_key: "ssh-ed25519 AAAA".into() }),
            },
        };
        assert_eq!(Bundle::decode(&format!(" {}\n", bundle.encode().unwrap())).unwrap(), bundle);
        assert!(Bundle::decode("not base64!").is_err());
        assert!(Bundle::decode("aGVsbG8=").is_err());
    }
}

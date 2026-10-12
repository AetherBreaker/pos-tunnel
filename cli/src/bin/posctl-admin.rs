//! `posctl-admin`: the admin's key generation and fleet configuration (design section 7.9). Runs only
//! with the admin's operator key, so its commands stay out of other operators' and agents' way.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use posctl::admin::{self, Operators};
use posctl::bundle::Bundle;
use posctl::config::{Config, NinjaOne, Relay, parse_host_port};
use posctl::ninja::{self, Api};
use posctl::{fleet, keys};
use serde_json::json;

const ALLOWED_SIGNERS: &str = "pos/allowed_signers";
const SIGNING_NAMESPACE: &str = "pos-tunnel-release";

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Set up this workstation as the admin's: sign in to NinjaOne, find the POS policy and the two
    /// library scripts by name, write the posctl config, and list the admin as an operator.
    Init {
        /// `https://<region>.ninjarmm.com`.
        #[arg(long)]
        base_url: String,
        /// The client ID of the tenant's Native client app.
        #[arg(long)]
        client_id: String,
        /// The exact name of the NinjaOne policy whose devices are the POSes.
        #[arg(long)]
        policy: String,
        /// The admin's operator private key (made by hand, its public key built into posctl-admin).
        #[arg(long)]
        operator_key: PathBuf,
        /// The admin's operator name, as the relay logs it.
        #[arg(long)]
        name: String,
    },
    #[command(subcommand)]
    Relay(RelayCommand),
    #[command(subcommand)]
    Signing(SigningCommand),
    #[command(subcommand)]
    Operator(OperatorCommand),
}

#[derive(Subcommand)]
enum RelayCommand {
    /// Generate the relay's SSH server key pair and make it the one this workstation pins; prints the
    /// RELAY_SSH_PRIVATE_KEY line for Coolify. Then redeploy the relay, then `relay point`.
    Keygen {
        /// `<host>[:<port>]`, port 2222 if omitted.
        address: String,
    },
    /// Point the fleet at the relay: write the fleet relay fields, then run `Install-PosTunnel -Force` on
    /// every online POS at once. Open sessions end.
    Point {
        /// Run `Install-PosTunnel -Force` on this one POS only (its exact display name), to try a relay
        /// on a test device first. The fleet fields are written either way; other POSes pick them up at
        /// their next scheduled install.
        #[arg(long, value_name = "DISPLAY_NAME")]
        device: Option<String>,
    },
}

#[derive(Subcommand)]
enum SigningCommand {
    /// Generate a release signing key pair (passphrase-protected), rewrite pos/allowed_signers and
    /// publish the public key. Run from a checkout of pos-tunnel; then re-sign and release.
    Keygen,
    /// Publish the public key in pos/allowed_signers to the posTunnelSigner fleet field.
    Publish,
}

#[derive(Subcommand)]
enum OperatorCommand {
    /// Generate an operator key pair and print the bundle for their `posctl operator import`.
    Add {
        name: String,
    },
    Remove {
        name: String,
    },
    List,
}

fn main() -> Result<()> {
    let command = Cli::parse().command;
    // Before the admin check, which needs the config init writes.
    if let Command::Init {
        base_url,
        client_id,
        policy,
        operator_key,
        name,
    } = command
    {
        let base_url = base_url.trim_end_matches('/');
        admin::require_admin(&operator_key)?;
        admin::check_operator_name(&name)?;
        ninja::login(base_url, &client_id)?;
        let api = Api::connect(base_url, &client_id)?;
        let policies = api.policies()?;
        let pos_policy_id = policies
            .iter()
            .find(|p| p.name == policy)
            .with_context(|| {
                let names: Vec<&str> = policies.iter().map(|p| p.name.as_str()).collect();
                format!(
                    "no NinjaOne policy named '{policy}'; there are: {}",
                    names.join(", ")
                )
            })?
            .id;
        let scripts = api.scripts()?;
        let script = |wanted: &str| {
            scripts
                .iter()
                .find(|s| s.name == wanted)
                .map(|s| s.id)
                .with_context(|| format!("no library script named '{wanted}': paste pos/ninja/{wanted}.ps1 into the NinjaOne library under that name"))
        };
        let ninjaone = NinjaOne {
            base_url: base_url.to_owned(),
            client_id,
            pos_policy_id,
            install_script_id: script("Install-PosTunnel")?,
            invoke_script_id: script("Invoke-PosTunnel")?,
        };
        // A rerun keeps the relay this workstation already pins.
        let relay = Config::load().ok().and_then(|existing| existing.relay);
        Config {
            operator_key: std::path::absolute(&operator_key)?,
            ninjaone,
            relay,
        }
        .save()?;
        let mut operators = Operators::load()?;
        operators
            .operators
            .insert(name.clone(), keys::public_of_file(&operator_key)?);
        operators.save()?;
        println!(
            "posctl is set up for {name}, policy '{policy}' (id {pos_policy_id}). Next: `posctl-admin relay keygen <host>`."
        );
        return Ok(());
    }
    let mut config = Config::load()?;
    admin::require_admin(&config.operator_key)?;
    match command {
        Command::Init { .. } => unreachable!("handled above"),
        Command::Relay(RelayCommand::Keygen { address }) => {
            let (host, port) = parse_host_port(&address)?;
            let key = keys::generate("pos-tunnel relay")?;
            let text = keys::private_text(&key, None)?;
            keys::write_private_key(&admin::relay_key_path()?, &key, None)?;
            config.relay = Some(Relay {
                host,
                port,
                public_key: keys::public_line(key.public_key())?,
            });
            config.save()?;
            println!("{}", admin::relay_env_line(&text));
            eprintln!(
                "Paste that line into the relay's environment in Coolify and redeploy, then run `posctl-admin relay point`."
            );
        }
        Command::Relay(RelayCommand::Point { device }) => {
            let relay = config
                .relay
                .as_ref()
                .context("no relay yet: run `posctl-admin relay keygen` first")?;
            // From the private key on disk, never asked of the network, where an attacker could answer
            // with theirs.
            let public_key = keys::public_of_file(&admin::relay_key_path()?)?;
            if public_key != relay.public_key {
                bail!(
                    "the posctl config pins a different relay key than {}; run `relay keygen` again",
                    admin::relay_key_path()?.display()
                );
            }
            let ninja = &config.ninjaone;
            let api = Api::connect(&ninja.base_url, &ninja.client_id)?;
            let address = format!("{}:{}", relay.host, relay.port);
            let pointed =
                fleet::point_relay(&api, ninja, &address, &public_key, device.as_deref())?;
            println!(
                "Fleet relay fields written on organizations {:?}.",
                pointed.organizations
            );
            if !pointed.ran.is_empty() {
                println!(
                    "Install-PosTunnel -Force started on: {}",
                    pointed.ran.join(", ")
                );
            }
            if !pointed.offline.is_empty() {
                println!(
                    "Offline, converging at their next scheduled install: {}",
                    pointed.offline.join(", ")
                );
            }
            if device.is_none() {
                println!(
                    "Send the other operators this line:\nposctl relay set {address} {public_key}"
                );
            }
            if !pointed.failed.is_empty() {
                bail!(
                    "NinjaOne refused to start Install-PosTunnel -Force on the POSes below; run `relay point` again to retry:\n{}",
                    pointed.failed.join("\n")
                );
            }
        }
        Command::Signing(command) => {
            let public_key = match command {
                SigningCommand::Keygen => {
                    if !Path::new(ALLOWED_SIGNERS).exists() {
                        bail!(
                            "run this from a checkout of pos-tunnel: it rewrites {ALLOWED_SIGNERS}"
                        );
                    }
                    let passphrase =
                        rpassword::prompt_password("Passphrase for the new signing key: ")?;
                    if passphrase.is_empty() || passphrase != rpassword::prompt_password("Again: ")?
                    {
                        bail!("the passphrases are empty or don't match");
                    }
                    let key = keys::generate(SIGNING_NAMESPACE)?;
                    let path = admin::signing_key_path()?;
                    keys::write_private_key(&path, &key, Some(&passphrase))?;
                    let public_key = keys::public_line(key.public_key())?;
                    fs::write(
                        ALLOWED_SIGNERS,
                        format!(
                            "{SIGNING_NAMESPACE} namespaces=\"{SIGNING_NAMESPACE}\" {public_key}\n"
                        ),
                    )?;
                    println!("Signing key stored at {}.", path.display());
                    println!(
                        "Set POS_TUNNEL_SIGNING_KEY to that path, run `poe sign-pos`, commit {ALLOWED_SIGNERS} and the manifest, and release."
                    );
                    println!(
                        "Until that release exists, POSes refuse new releases and keep their installed version."
                    );
                    public_key
                }
                SigningCommand::Publish => {
                    let text = fs::read_to_string(ALLOWED_SIGNERS).with_context(|| {
                        format!("run this from a checkout of pos-tunnel ({ALLOWED_SIGNERS})")
                    })?;
                    let key = text
                        .split_once("ssh-ed25519")
                        .map(|(_, rest)| format!("ssh-ed25519{rest}"))
                        .context("no ed25519 key in it")?;
                    keys::parse_public(&key)?
                }
            };
            let ninja = &config.ninjaone;
            let api = Api::connect(&ninja.base_url, &ninja.client_id)?;
            let organizations = fleet::set_fleet_fields(
                &api,
                ninja.pos_policy_id,
                &json!({"posTunnelSigner": public_key}),
            )?;
            println!("posTunnelSigner written on organizations {organizations:?}.");
        }
        Command::Operator(command) => {
            let mut operators = Operators::load()?;
            match command {
                OperatorCommand::Add { name } => {
                    if config.relay.is_none() {
                        bail!(
                            "no relay yet: run `posctl-admin relay keygen` first, so the bundle carries it"
                        );
                    }
                    let key = keys::generate(&name)?;
                    operators.add(&name, keys::public_line(key.public_key())?)?;
                    let bundle = Bundle {
                        operator_key: keys::private_text(&key, None)?,
                        config: config.clone(),
                    };
                    operators.save()?;
                    eprintln!(
                        "The bundle below holds {name}'s private key and is shown once: send it like a password, never by email or chat."
                    );
                    println!("{}", bundle.encode()?);
                }
                OperatorCommand::Remove { name } => {
                    operators.remove(&name, &keys::public_of_file(&config.operator_key)?)?;
                    operators.save()?;
                }
                OperatorCommand::List => {
                    for (name, key) in &operators.operators {
                        println!("{name}\t{key}");
                    }
                }
            }
            println!("{}", operators.env_line());
            eprintln!("Redeploy the relay with that OPERATOR_KEYS line to apply it.");
        }
    }
    Ok(())
}

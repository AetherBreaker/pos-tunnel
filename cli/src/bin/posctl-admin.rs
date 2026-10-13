//! `posctl-admin`: the admin's key generation and fleet configuration (design section 7.9). Runs only
//! with the admin's operator key, so its commands stay out of other operators' and agents' way.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use posctl::admin::{self, ALLOWED_SIGNERS, Operators};
use posctl::bundle::Bundle;
use posctl::config::{Config, NinjaOne, Relay, parse_host_port, pinned_relay};
use posctl::ninja::{self, Api, Named};
use posctl::{fleet, keys};
use serde_json::json;

const SIGNING_NAMESPACE: &str = "pos-tunnel-release";

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Set up this workstation as the admin's: sign in to NinjaOne, find the organization, the POS
    /// policy and the two library scripts by name, write the posctl config, and list the admin as an
    /// operator.
    Init {
        /// `https://<region>.ninjarmm.com`.
        #[arg(long)]
        base_url: String,
        /// The client ID of the tenant's Native client app.
        #[arg(long)]
        client_id: String,
        /// The exact name of the one NinjaOne organization this system works on: only its devices are
        /// listed, and only its fleet fields are written.
        #[arg(long)]
        organization: String,
        /// The exact name of the NinjaOne policy that makes a device of that organization a POS.
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
        /// Replace the relay private key this workstation already holds: a rotation, after which the
        /// relay must be redeployed and the fleet pointed again.
        #[arg(long)]
        replace: bool,
    },
    /// Point the fleet at the relay: write the organization's fleet relay fields, then run
    /// `Install-PosTunnel -Force` on every online POS at once. Open sessions end.
    Point {
        /// Run `Install-PosTunnel -Force` on this one POS only (its exact display name), to try a relay
        /// on a test device first. The organization's relay changes either way: its other POSes pick it
        /// up at their next scheduled install.
        #[arg(long, value_name = "DISPLAY_NAME")]
        device: Option<String>,
    },
}

#[derive(Subcommand)]
enum SigningCommand {
    /// Generate a release signing key pair (passphrase-protected), rewrite pos/allowed_signers and
    /// publish the public key. Run from a checkout of pos-tunnel; then re-sign and release.
    Keygen {
        /// Replace the signing private key this workstation already holds; POSes then refuse releases
        /// until one is signed with the new key.
        #[arg(long)]
        replace: bool,
    },
    /// Publish the signing public key a release was made with to the posTunnelSigner fleet field: the
    /// one in pos/allowed_signers at that release's git tag, fetched from GitHub. No checkout is read.
    Publish {
        /// The release's git tag.
        tag: String,
    },
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
        organization,
        policy,
        operator_key,
        name,
    } = command
    {
        let base_url = base_url.trim_end_matches('/');
        admin::require_admin(&operator_key)?;
        // The admin's key appears once: a rerun under another name renames the admin, and `add`
        // refuses a name another operator holds. Before the sign-in, so a taken name costs nothing.
        let mut operators = Operators::load()?;
        let admin_key = keys::public_of_file(&operator_key)?;
        operators.operators.retain(|_, key| *key != admin_key);
        operators.add(&name, admin_key)?;
        ninja::login(base_url, &client_id)?;
        let api = Api::connect(base_url, &client_id)?;
        let named = |kind: &str, all: &[Named], wanted: &str| {
            all.iter()
                .find(|one| one.name == wanted)
                .map(|one| one.id)
                .with_context(|| {
                    let names: Vec<&str> = all.iter().map(|one| one.name.as_str()).collect();
                    format!(
                        "no NinjaOne {kind} named '{wanted}'; there are: {}",
                        names.join(", ")
                    )
                })
        };
        // By name, refused when absent: an organization ID that doesn't exist lists no devices instead
        // of failing (design section 11).
        let organization_id = named(
            "organization",
            &api.get::<Vec<Named>>("/v2/organizations")?,
            &organization,
        )?;
        let pos_policy_id = named("policy", &api.policies()?, &policy)?;
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
            organization_id,
            pos_policy_id,
            install_script_id: script(ninja::INSTALL_SCRIPT)?,
            invoke_script_id: script(ninja::INVOKE_SCRIPT)?,
        };
        // A rerun keeps the relay this workstation already pins, also from a file that predates a field.
        let path = Config::path()?;
        let relay = match fs::read_to_string(&path) {
            Ok(text) => pinned_relay(&text).with_context(|| {
                format!(
                    "{} is not a posctl config; move it aside to start over",
                    path.display()
                )
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let next = match &relay {
            Some(relay) => format!("It still pins the relay {}:{}.", relay.host, relay.port),
            None => "Next: `posctl-admin relay keygen <host>`.".to_owned(),
        };
        Config {
            operator_key: std::path::absolute(&operator_key)?,
            ninjaone,
            relay,
        }
        .save()?;
        operators.save()?;
        println!(
            "posctl is set up for {name}: organization '{organization}' (id {organization_id}), policy '{policy}' (id {pos_policy_id}). {next}"
        );
        return Ok(());
    }
    let mut config = Config::load()?;
    admin::require_admin(&config.operator_key)?;
    match command {
        Command::Init { .. } => unreachable!("handled above"),
        Command::Relay(RelayCommand::Keygen { address, replace }) => {
            let (host, port) = parse_host_port(&address)?;
            let path = admin::relay_key_path()?;
            // The live relay serves the key already here; a second run must be meant as a rotation.
            if path.exists() && !replace {
                bail!(
                    "a relay private key already exists at {}; `relay keygen --replace` rotates it (redeploy the relay, then `relay point` again)",
                    path.display()
                );
            }
            let key = keys::generate("pos-tunnel relay")?;
            let text = keys::private_text(&key, None)?;
            keys::write_private_key(&path, &key, None)?;
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
                    "the posctl config pins a different relay key than {}; `posctl relay set {}:{} {public_key}` pins that file's key again (`relay keygen --replace` would rotate it instead)",
                    admin::relay_key_path()?.display(),
                    relay.host,
                    relay.port
                );
            }
            let ninja = &config.ninjaone;
            let api = Api::connect(&ninja.base_url, &ninja.client_id)?;
            let address = format!("{}:{}", relay.host, relay.port);
            let pointed =
                fleet::point_relay(&api, ninja, &address, &public_key, device.as_deref())?;
            println!(
                "Fleet relay fields written on organization {}.",
                ninja.organization_id
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
                    "Install-PosTunnel -Force did not start on the POSes below (NinjaOne refused it or didn't answer); retry one with `relay point --device <name>`, or all with `relay point`, which also ends sessions opened since:\n{}",
                    pointed.failed.join("\n")
                );
            }
        }
        Command::Signing(command) => {
            // Signed in before anything local changes: an expired sign-in must not leave a new key on
            // disk that the fleet never got.
            let ninja = &config.ninjaone;
            let api = Api::connect(&ninja.base_url, &ninja.client_id)?;
            let public_key = match command {
                SigningCommand::Keygen { replace } => {
                    if !Path::new(ALLOWED_SIGNERS).exists() {
                        bail!(
                            "run this from a checkout of pos-tunnel: it rewrites {ALLOWED_SIGNERS}"
                        );
                    }
                    let path = admin::signing_key_path()?;
                    if path.exists() && !replace {
                        bail!(
                            "a release signing private key already exists at {}; `signing keygen --replace` makes a new one",
                            path.display()
                        );
                    }
                    let passphrase =
                        rpassword::prompt_password("Passphrase for the new signing key: ")?;
                    if passphrase.is_empty() || passphrase != rpassword::prompt_password("Again: ")?
                    {
                        bail!("the passphrases are empty or don't match");
                    }
                    let key = keys::generate(SIGNING_NAMESPACE)?;
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
                SigningCommand::Publish { tag } => {
                    let public_key = admin::signer_at_tag(admin::GITHUB_RAW, &tag)?;
                    println!("Signing public key at tag {tag} on GitHub: {public_key}");
                    public_key
                }
            };
            fleet::set_fleet_fields(&api, ninja, &json!({"posTunnelSigner": public_key})).context(
                "posTunnelSigner was not written; once a release carries this key, `posctl-admin signing publish <tag>` writes it",
            )?;
            println!(
                "posTunnelSigner written on organization {}.",
                ninja.organization_id
            );
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

//! `posctl`: on-demand SSH sessions to NinjaOne-managed POS machines. Design: `docs/design.md`.

use std::io::IsTerminal;
use std::time::Duration;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use posctl::bundle::Bundle;
use posctl::config::{Config, Relay, config_home, parse_host_port, write_private};
use posctl::{keys, ninja};

/// Default and ceiling for `--idle-timeout`; the relay enforces the same ceiling (design section 5).
const MAX_IDLE: Duration = Duration::from_secs(12 * 60 * 60);

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sign in to NinjaOne in the browser; the sign-in is kept in the OS keyring.
    Login,
    /// Open a session to a POS, identified by its exact (case-sensitive) NinjaOne display name.
    Connect {
        name: String,
        /// Idle timeout; may only be shorter than the 12h default.
        #[arg(long, value_parser = parse_idle_timeout, default_value = "12h")]
        idle_timeout: Duration,
    },
    /// Renew the session's idle timeout on the relay and the POS.
    Keepalive { name: String },
    /// Show open sessions and their remaining time.
    Status { name: Option<String> },
    /// Close a session and tear down both sides.
    Close { name: String },
    /// Break glass: close and reopen a session, resetting the 72h maximum.
    Rebuild {
        name: String,
        /// Skip the confirmation prompt. Required when stdin is not a terminal.
        #[arg(long)]
        yes: bool,
    },
    /// Install or upgrade the POS package on a device now, instead of waiting for the daily run.
    Update { name: String },
    /// Set up this workstation from the bundle the admin sent you.
    #[command(subcommand)]
    Operator(OperatorCommand),
    /// Point this workstation at a relay (the line `posctl-admin relay point` prints).
    #[command(subcommand)]
    Relay(RelayCommand),
}

#[derive(Subcommand)]
enum OperatorCommand {
    /// Read the bundle from a hidden prompt (or stdin when it isn't a terminal), never an argument,
    /// so it stays out of shell history.
    Import,
}

#[derive(Subcommand)]
enum RelayCommand {
    Set {
        /// `<host>[:<port>]`, port 2222 if omitted.
        address: String,
        /// The relay's public key, `ssh-ed25519 <base64>`.
        #[arg(num_args = 1.., required = true)]
        public_key: Vec<String>,
    },
}

fn parse_idle_timeout(s: &str) -> Result<Duration> {
    let d = humantime::parse_duration(s)?;
    if d.is_zero() || d > MAX_IDLE {
        bail!("idle timeout must be greater than 0 and at most 12h");
    }
    Ok(d)
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Login => {
            let config = Config::load()?;
            ninja::login(&config.ninjaone.base_url, &config.ninjaone.client_id)?;
            println!("Signed in to NinjaOne.");
        }
        Command::Operator(OperatorCommand::Import) => {
            let line = if std::io::stdin().is_terminal() {
                rpassword::prompt_password("Paste the operator bundle (input hidden): ")?
            } else {
                std::io::read_to_string(std::io::stdin())?
            };
            let bundle = Bundle::decode(&line)?;
            let key_path = config_home()?.join("posctl").join("operator_key");
            write_private(&key_path, bundle.operator_key.as_bytes())?;
            Config {
                operator_key: key_path,
                ..bundle.config
            }
            .save()?;
            println!(
                "Imported. Next: `posctl login`, and add `Include posctl/config` at the top of ~/.ssh/config."
            );
        }
        Command::Relay(RelayCommand::Set {
            address,
            public_key,
        }) => {
            let (host, port) = parse_host_port(&address)?;
            let public_key = keys::parse_public(&public_key.join(" "))?;
            let mut config = Config::load()?;
            config.relay = Some(Relay {
                host,
                port,
                public_key,
            });
            config.save()?;
            println!("posctl now uses the relay at {address}.");
        }
        Command::Connect { .. }
        | Command::Keepalive { .. }
        | Command::Status { .. }
        | Command::Close { .. }
        | Command::Rebuild { .. }
        | Command::Update { .. } => bail!("not implemented yet"),
    }
    Ok(())
}

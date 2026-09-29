//! `posctl`: on-demand SSH sessions to NinjaOne-managed POS machines. Design: `docs/design.md`.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

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
    /// Store NinjaOne API client credentials in the OS keyring.
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
    /// Work with the POS scripts compiled into this binary.
    Scripts {
        #[command(subcommand)]
        command: ScriptsCommand,
    },
}

#[derive(Subcommand)]
enum ScriptsCommand {
    /// Write the NinjaOne library versions of the POS scripts to a directory.
    Export { dir: PathBuf },
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
        Command::Login
        | Command::Connect { .. }
        | Command::Keepalive { .. }
        | Command::Status { .. }
        | Command::Close { .. }
        | Command::Rebuild { .. }
        | Command::Scripts { .. } => bail!("not implemented yet"),
    }
}

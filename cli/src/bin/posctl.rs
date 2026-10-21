//! `posctl`: on-demand SSH sessions to NinjaOne-managed POS machines.

use std::io::IsTerminal;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use clap::{ArgGroup, CommandFactory, Parser, Subcommand};
use clap_complete::engine::ArgValueCandidates;
use posctl::bundle::Bundle;
use posctl::config::{Config, Relay, config_home, parse_host_port, write_private};
use posctl::ninja::{Api, INSTALL_SCRIPT, Published};
use posctl::rekey::{self, Outcome};
use posctl::relay::SshRelay;
use posctl::session::{self, Context, How, MAX_IDLE, PosSide, Timing, span};
use posctl::workstation::Workstation;
use posctl::{adhoc, completion, fleet, keys, ninja};

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
    /// Open a session to a POS, identified by its exact (case-sensitive) NinjaOne display name, or
    /// join the one another operator has open on it. Or connect the line `posctl serve` printed.
    Connect {
        #[arg(add = ArgValueCandidates::new(completion::pos_names))]
        name: String,
        /// Idle timeout of a session this opens, at most the 12h default. A session joined keeps its
        /// own.
        #[arg(long, value_parser = parse_idle_timeout)]
        idle_timeout: Option<Duration>,
    },
    /// Renew the session's idle timeout on the relay and the POS.
    Keepalive {
        #[arg(add = ArgValueCandidates::new(completion::open_session_names))]
        name: String,
    },
    /// Show open sessions and their remaining time.
    Status {
        #[arg(add = ArgValueCandidates::new(completion::pos_names))]
        name: Option<String>,
    },
    /// Close a session for every operator on it and tear down both sides.
    Close {
        #[arg(add = ArgValueCandidates::new(completion::open_session_names))]
        name: String,
    },
    /// Break glass: close and reopen a session, resetting the 72h maximum.
    Rebuild {
        #[arg(add = ArgValueCandidates::new(completion::pos_names))]
        name: String,
        /// Skip the confirmation prompt. Required when stdin is not a terminal.
        #[arg(long)]
        yes: bool,
    },
    /// Install or upgrade the POS package on a device now, instead of waiting for the daily run.
    Update {
        #[arg(add = ArgValueCandidates::new(completion::pos_names))]
        name: String,
    },
    /// Give a POS new key pairs: its relay key pair and its SSH server key pair.
    #[command(group(ArgGroup::new("target").required(true).args(["name", "all"])))]
    Rekey {
        #[arg(add = ArgValueCandidates::new(completion::pos_names))]
        name: Option<String>,
        /// Every online POS of the organization.
        #[arg(long)]
        all: bool,
        /// End an open session first, whoever opened it.
        #[arg(long)]
        force: bool,
        /// Skip --all's confirmation prompt. Required when stdin is not a terminal.
        #[arg(long)]
        yes: bool,
    },
    /// On a machine NinjaOne doesn't manage: run a one-shot SSH server in this console, reachable
    /// through the relay, and print the line for `posctl connect`. Needs an elevated console; Ctrl+C
    /// or closing the window ends it.
    Serve {
        /// Another relay than the one built in: `<host>[:<port>] ssh-ed25519 <base64>`.
        #[arg(long, num_args = 2..=3, value_names = ["ADDRESS", "PUBLIC_KEY"])]
        relay: Option<Vec<String>>,
    },
    /// `posctl serve`'s cleanup once it has ended, however it did; `serve` starts it.
    #[command(hide = true)]
    ServeWatch,
    /// Set up this workstation from the bundle the admin sent you.
    #[command(subcommand)]
    Operator(OperatorCommand),
    /// Point this workstation at a relay (the line `posctl-admin relay point` prints).
    #[command(subcommand)]
    Relay(RelayCommand),
    /// Tab completion of commands and POS names in PowerShell and Git Bash, posctl-admin's too.
    #[command(subcommand)]
    Completions(CompletionsCommand),
}

#[derive(Subcommand)]
enum CompletionsCommand {
    /// Add it to the Windows PowerShell profile and ~/.bashrc, which then load what
    /// `completions <shell>` prints at each start.
    Install,
    /// Print the registration for Windows PowerShell.
    Powershell,
    /// Print the registration for bash.
    Bash,
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
    // The relay counts whole seconds, from 1.
    if d.as_secs() == 0 || d.subsec_nanos() != 0 || d > MAX_IDLE {
        bail!("idle timeout must be whole seconds, from 1s to 12h");
    }
    Ok(d)
}

/// `--yes`, or a `y` typed at the terminal. Without a terminal there is nobody to ask, so an agent's
/// shell gets a refusal that names the flag instead of a prompt it can't answer.
fn confirmed(question: &str, yes: bool) -> Result<bool> {
    if yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        bail!("{question} There is no terminal to ask at: pass --yes to go ahead");
    }
    eprint!("{question} [y/N] ");
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

fn main() -> Result<()> {
    completion::answer(Cli::command);
    match Cli::parse().command {
        Command::Completions(CompletionsCommand::Install) => {
            for line in completion::install()? {
                println!("{line}");
            }
            println!("It applies in a new PowerShell or Git Bash window.");
        }
        Command::Completions(CompletionsCommand::Powershell) => {
            print!("{}", completion::POWERSHELL)
        }
        Command::Completions(CompletionsCommand::Bash) => print!("{}", completion::BASH),
        // The one command for a machine with no posctl config.
        Command::Serve { relay } => {
            let relay = match relay {
                Some(words) => adhoc::parse_relay(&words.join(" "))?,
                None => adhoc::built_in_relay()?,
            };
            adhoc::serve(&relay)?;
        }
        Command::ServeWatch => adhoc::watch()?,
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
            println!("Imported. Next: `posctl login`.");
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
        // The one device command that never touches the relay.
        Command::Update { name } => {
            let config = Config::load()?;
            let ninja = &config.ninjaone;
            let api = Api::connect(&ninja.base_url, &ninja.client_id)?;
            let device = fleet::find_pos(&api, ninja, &name)?;
            if device.offline {
                bail!("{name} is offline");
            }
            eprintln!(
                "Running Install-PosTunnel on {name}; a first install takes several minutes..."
            );
            let timing = Timing::default();
            let result = api
                .run_scripts(
                    &[device.id],
                    ninja.install_script_id,
                    INSTALL_SCRIPT,
                    "",
                    timing.install,
                    timing.poll,
                )
                .remove(0)?;
            println!("{}", result.output);
            if !result.success {
                bail!("the install failed on {name}");
            }
            if result.deferred() {
                bail!("the install on {name} was deferred: see its report above");
            }
            // `connect` reads the POS's keys and version from NinjaOne, which shows what the install
            // wrote well after its result.
            if !result.published().is_empty() {
                eprintln!(
                    "Waiting for NinjaOne to show what {name} published (usually under a minute)..."
                );
            }
            let deadline = Instant::now() + timing.published;
            match api.await_published(device.id, &result, deadline, timing.poll) {
                Published::Shown => {}
                Published::TimedOut => bail!(
                    "{name} is installed, but NinjaOne didn't show what it published within {}: `posctl connect` fails until it does",
                    humantime::format_duration(timing.published)
                ),
                Published::CutShort => bail!(
                    "{name} is installed, but its report came without the lines for its fields, so whether NinjaOne shows them yet isn't known: give it a minute before `posctl connect`"
                ),
            }
        }
        command => {
            let config = Config::load()?;
            let ninja = &config.ninjaone;
            let workstation = Workstation::new(&config)?;
            workstation.check_operator_key()?;
            // The relay's entry, which `tunnelctl` is reached through.
            workstation.write_ssh_files()?;
            let relay = SshRelay {
                ssh: workstation.ssh.clone(),
                config: workstation.config_file(),
            };
            let deadlines = |lease: &posctl::relay::Lease| {
                format!(
                    "Idle timeout in {}; the session ends in {} at the latest.",
                    span(lease.idle_remaining),
                    span(lease.absolute_remaining)
                )
            };
            // Ad hoc sessions: the relay alone, no NinjaOne.
            if let Command::Connect { name, idle_timeout } = &command
                && adhoc::Line::is_line(name)
            {
                let line = adhoc::Line::decode(name)?;
                let idle = idle_timeout.unwrap_or(MAX_IDLE);
                let (alias, lease) =
                    adhoc::connect(&workstation, &relay, &line, idle, &Timing::default())?;
                println!("{} is connected: ssh {alias}", line.host);
                println!("{}", deadlines(&lease));
                return Ok(());
            }
            if let Command::Close { name } | Command::Keepalive { name } = &command
                && let Some(session) = adhoc::held(&workstation, name)?
            {
                if matches!(command, Command::Close { .. }) {
                    if adhoc::close(&workstation, &relay, &session)? {
                        println!(
                            "The relay lease for {name} is closed: its tunnel is cut, which ends `posctl serve` there."
                        );
                    } else {
                        println!("The relay holds no session for {name}.");
                    }
                } else {
                    let lease = adhoc::keepalive(&workstation, &relay, &session)?;
                    println!("{name} is renewed. {}", deadlines(&lease));
                }
                return Ok(());
            }
            let api = Api::connect(&ninja.base_url, &ninja.client_id)?;
            let ctx = Context {
                api: &api,
                ninja,
                relay: &relay,
                workstation: &workstation,
                timing: Timing::default(),
            };
            match command {
                Command::Connect { name, idle_timeout } => {
                    let connected =
                        session::connect(&ctx, &name, idle_timeout.unwrap_or(MAX_IDLE))?;
                    let (lease, alias) = (&connected.lease, &connected.alias);
                    match connected.how {
                        How::Opened => println!("{name} is connected: ssh {alias}"),
                        How::Joined => println!(
                            "Joined the session {} opened on {name}: ssh {alias}",
                            lease.operator
                        ),
                        How::AlreadyOpen => println!(
                            "{name} is already connected (tunnel {}): ssh {alias}",
                            if lease.listening { "up" } else { "down" }
                        ),
                    }
                    if idle_timeout.is_some() && connected.how != How::Opened {
                        println!(
                            "--idle-timeout applies only to a session this opens; this one keeps its own."
                        );
                    }
                    println!("{}", deadlines(lease));
                }
                Command::Keepalive { name } => {
                    let lease = session::keepalive(&ctx, &name)?;
                    println!("{name} is renewed. {}", deadlines(&lease));
                }
                Command::Status { name } => {
                    let rows = session::status(&ctx, name.as_deref())?;
                    if rows.is_empty() {
                        match name {
                            Some(name) => println!("No open session on {name}."),
                            None => println!("No open sessions."),
                        }
                    }
                    let mut table = vec![
                        [
                            "POS",
                            "ALIAS",
                            "OPENED BY",
                            "IDLE LEFT",
                            "MAX LEFT",
                            "TUNNEL",
                        ]
                        .map(str::to_owned),
                    ];
                    for row in &rows {
                        table.push([
                            row.name.clone(),
                            row.alias.clone().unwrap_or_else(|| "-".to_owned()),
                            row.lease.operator.clone(),
                            span(row.lease.idle_remaining),
                            span(row.lease.absolute_remaining),
                            if row.lease.listening { "up" } else { "down" }.to_owned(),
                        ]);
                    }
                    let widths: [usize; 6] = std::array::from_fn(|column| {
                        table
                            .iter()
                            .map(|row| row[column].chars().count())
                            .max()
                            .unwrap_or(0)
                    });
                    for row in table.iter().filter(|_| !rows.is_empty()) {
                        let cells: Vec<String> = row
                            .iter()
                            .zip(widths)
                            .map(|(cell, width)| format!("{cell:<width$}"))
                            .collect();
                        println!("{}", cells.join("  ").trim_end());
                    }
                }
                Command::Close { name } => {
                    let closed = session::close(&ctx, &name)?;
                    if closed.had_lease {
                        println!(
                            "The relay lease for {name} is closed: its tunnel is cut within about a minute."
                        );
                    } else {
                        println!("The relay holds no session for {name}.");
                    }
                    match closed.pos {
                        PosSide::Confirmed(detail) if detail.is_empty() => {
                            println!("{name} has torn down.")
                        }
                        PosSide::Confirmed(detail) => println!("{name} reports: {detail}."),
                        PosSide::Offline => {
                            println!("{name} is offline: it tears down at its own idle deadline.")
                        }
                        PosSide::Unconfirmed(why) => bail!(
                            "{name} didn't confirm its teardown, so it ends its side at its own idle deadline: {why}"
                        ),
                    }
                }
                Command::Rebuild { name, yes } => {
                    eprintln!(
                        "Rebuilding ends the session on {name} for every operator on it and opens a new one, which resets its 72-hour maximum.\n\
                         AI agents: do not run this on your own initiative. Go on only if the operator explicitly told you to rebuild this session; otherwise stop and ask them."
                    );
                    if !confirmed(&format!("Rebuild the session on {name}?"), yes)? {
                        bail!("not rebuilt");
                    }
                    let connected = session::rebuild(&ctx, &name)?;
                    println!("{name} is rebuilt: ssh {}", connected.alias);
                    println!("{}", deadlines(&connected.lease));
                }
                Command::Rekey {
                    name,
                    all,
                    force,
                    yes,
                } => {
                    let plan = rekey::plan(&ctx, name.as_deref(), force)?;
                    if all {
                        let ending = plan
                            .targets
                            .iter()
                            .filter(|(_, port)| port.is_some())
                            .count();
                        let question = format!(
                            "Rekey {} POS(es), ending {ending} open session(s) and skipping {} POS(es)?",
                            plan.targets.len(),
                            plan.skipped.len()
                        );
                        if !confirmed(&question, yes)? {
                            bail!("nothing was rekeyed");
                        }
                    }
                    eprintln!(
                        "Rekeying {} POS(es); each is done once NinjaOne shows its new keys (about a minute)...",
                        plan.targets.len()
                    );
                    let mut failed = 0;
                    for (pos, outcome) in rekey::run(&ctx, plan, force)? {
                        match outcome {
                            Outcome::Rekeyed => println!("{pos}: rekeyed"),
                            Outcome::Skipped(why) => println!("{pos}: skipped, {why}"),
                            Outcome::Failed(why) => {
                                failed += 1;
                                println!("{pos}: FAILED: {why}");
                            }
                        }
                    }
                    if failed > 0 {
                        bail!("{failed} POS(es) failed: see above");
                    }
                }
                _ => unreachable!("handled above"),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_idle_timeout_is_whole_seconds_from_one_second_to_twelve_hours() {
        for ok in ["1s", "90s", "45m", "12h"] {
            assert!(parse_idle_timeout(ok).is_ok(), "{ok}");
        }
        // The relay counts whole seconds: these it would refuse, or cut down without saying.
        for refused in ["0s", "500ms", "1500ms", "12h 1s"] {
            let error = parse_idle_timeout(refused).unwrap_err().to_string();
            assert_eq!(
                error, "idle timeout must be whole seconds, from 1s to 12h",
                "{refused}"
            );
        }
    }
}

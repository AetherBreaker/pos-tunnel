//! The session commands (design sections 7.2 to 7.6): `connect`, `keepalive`, `status`, `close` and
//! `rebuild`.

use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use serde_json::Value;

use crate::config::NinjaOne;
use crate::fleet;
use crate::keys;
use crate::ninja::{Api, Device, INVOKE_SCRIPT, ScriptResult};
use crate::relay::{self, Lease, Relay, Starting};
use crate::workstation::{self, Session, Workstation};

/// Default and ceiling for the idle timeout; the relay enforces the same ceiling (design section 5).
pub const MAX_IDLE: Duration = Duration::from_secs(12 * 60 * 60);
/// The first POS package version whose `Open` can add a second operator's key (design section 7.2).
const JOIN_VERSION: u64 = 4;

/// How long each wait lasts; tests shorten them.
pub struct Timing {
    /// Between two looks while waiting.
    pub poll: Duration,
    /// For `Open`'s result and the tunnel (design section 7.2, step 7).
    pub open: Duration,
    /// For a `Touch`, `Close`, `Rekey` or join result.
    pub script: Duration,
    /// For `Install-PosTunnel`: a first install downloads and installs OpenSSH.
    pub install: Duration,
    /// For the relay to drop a lease that has ended, which it does at its next pass (design section 6.5).
    pub released: Duration,
    /// For NinjaOne to show the fields a script wrote: 39 s on the test POS (design section 11).
    pub published: Duration,
}

impl Default for Timing {
    fn default() -> Timing {
        Timing {
            poll: Duration::from_secs(3),
            open: Duration::from_secs(180),
            script: Duration::from_secs(120),
            install: Duration::from_secs(900),
            released: Duration::from_secs(60),
            published: Duration::from_secs(180),
        }
    }
}

/// What every session command works with.
pub struct Context<'a> {
    pub api: &'a Api,
    pub ninja: &'a NinjaOne,
    pub relay: &'a dyn Relay,
    pub workstation: &'a Workstation,
    pub timing: Timing,
}

/// Seconds as `11h 58m`, `58m` or `45s`: the relay's remaining times, for people.
pub fn span(seconds: u64) -> String {
    match (seconds / 3600, seconds % 3600 / 60) {
        (0, 0) => format!("{seconds}s"),
        (0, minutes) => format!("{minutes}m"),
        (hours, minutes) => format!("{hours}h {minutes}m"),
    }
}

/// One `Invoke-PosTunnel` action on one POS, waited for.
fn invoke(ctx: &Context, device: i64, parameters: &str) -> Result<ScriptResult> {
    ctx.api
        .run_scripts(
            &[device],
            ctx.ninja.invoke_script_id,
            INVOKE_SCRIPT,
            parameters,
            ctx.timing.script,
            ctx.timing.poll,
        )
        .remove(0)
}

#[derive(Debug, PartialEq)]
pub enum How {
    Opened,
    /// Another workstation's session, which this one now shares.
    Joined,
    /// This workstation's own session was still open.
    AlreadyOpen,
}

#[derive(Debug)]
pub struct Connected {
    pub alias: String,
    pub lease: Lease,
    pub how: How,
}

pub fn connect(ctx: &Context, name: &str, idle: Duration) -> Result<Connected> {
    let device = fleet::find_pos(ctx.api, ctx.ninja, name)?;
    if device.offline {
        bail!("{name} is offline");
    }
    open(ctx, &device, name, idle, false)
}

/// `connect` from its step 2 (design section 7.2), for a POS already resolved and online: opens a
/// session, or joins the one another workstation holds, and leaves a working alias or nothing.
fn open(
    ctx: &Context,
    device: &Device,
    name: &str,
    idle: Duration,
    rebuild: bool,
) -> Result<Connected> {
    let port = relay::port(device)?;
    let fields = ctx.api.custom_fields(device.id)?;
    // Written by the POS, so untrusted: only a well-formed ed25519 public key gets any further.
    let key_field = |field: &str| {
        fields
            .get(field)
            .and_then(Value::as_str)
            .and_then(|value| keys::parse_public(value).ok())
    };
    let (Some(pos_key), Some(host_key)) = (
        key_field("posTunnelRelayKey"),
        key_field("posTunnelHostKey"),
    ) else {
        bail!(
            "{name} hasn't published its keys, so the POS package isn't installed on it: run `posctl update \"{name}\"`"
        );
    };

    // A lease out of time was closed or has expired, and the daemon drops it at its next pass (design
    // section 6.5). That session has ended: wait for the port rather than join it, as `open` would
    // refuse and `renew` too.
    let deadline = Instant::now() + ctx.timing.released;
    let leases = loop {
        let leases = relay::leases(ctx.relay)?;
        let ended = |lease: &Lease| lease.idle_remaining.min(lease.absolute_remaining) == 0;
        if !leases
            .iter()
            .any(|lease| lease.port == port && ended(lease))
        {
            break leases;
        }
        if Instant::now() >= deadline {
            bail!(
                "the relay still holds the ended lease for {name}; run `posctl connect \"{name}\"` again in a minute"
            );
        }
        std::thread::sleep(ctx.timing.poll);
    };
    let held = ctx.workstation.reconcile(&leases)?;
    let existing = leases.into_iter().find(|lease| lease.port == port);
    if let (Some(lease), Some(session)) = (
        &existing,
        held.iter().find(|session| session.device_id == device.id),
    ) {
        return Ok(Connected {
            alias: session.alias.clone(),
            lease: lease.clone(),
            how: How::AlreadyOpen,
        });
    }

    let taken: Vec<&str> = held.iter().map(|session| session.alias.as_str()).collect();
    let alias = workstation::alias(name, device.id, &taken);
    let key = keys::generate(&format!("posctl {alias}"))?;
    let public = keys::public_line(key.public_key())?;
    // Bare base64, so NinjaOne's parameter string needs no quoting (design section 7.2).
    let session_key = public.trim_start_matches("ssh-ed25519 ");
    let seconds = idle.as_secs();
    let invoke_script = ctx.ninja.invoke_script_id;

    let joining = existing.is_some();
    if let Some(lease) = &existing {
        let version = fields.get("posTunnelVersion").and_then(|value| {
            value
                .as_str()
                .map_or(value.as_u64(), |text| text.parse().ok())
        });
        if version.unwrap_or(0) < JOIN_VERSION {
            bail!(
                "{name} is in a session {} opened, and its POS package is too old to share one. Once that session has ended, run `posctl update \"{name}\"`",
                lease.operator
            );
        }
    } else {
        let flag = if rebuild { " --rebuild" } else { "" };
        let _: Lease = relay::ask(
            ctx.relay,
            &format!("open {port} {} {seconds} {pos_key}{flag}", device.id),
        )?;
    }

    // From here on a failure is undone below.
    let built = (|| -> Result<Lease> {
        let lease = if joining {
            // As `keepalive`: joining is use, and the relay's log then names the joiner.
            let lease: Lease = relay::ask(ctx.relay, &format!("renew {port}"))?;
            eprintln!("Joining the session {} opened on {name}...", lease.operator);
            let joined = invoke(
                ctx,
                device.id,
                &format!("-Action Open -Mode Join -Port {port} -SessionKey {session_key}"),
            )?;
            if !joined.success {
                bail!(
                    "{name} couldn't add this workstation to the session. It reported:\n{}",
                    joined.output
                );
            }
            lease
        } else {
            let mut run = ctx.api.start_script(
                device.id,
                invoke_script,
                INVOKE_SCRIPT,
                &format!(
                    "-Action Open -Port {port} -IdleSeconds {seconds} -SessionKey {session_key}"
                ),
            )?;
            eprintln!("Waiting for {name} to open the session (usually under a minute)...");
            let deadline = Instant::now() + ctx.timing.open;
            let mut reported = false;
            loop {
                if !reported && let Some(result) = ctx.api.poll_script(&mut run)? {
                    if !result.success {
                        bail!(
                            "{name} couldn't open the session. It reported:\n{}",
                            result.output
                        );
                    }
                    reported = true;
                }
                let starting = match relay::leases(ctx.relay) {
                    Ok(leases) => match leases.into_iter().find(|lease| lease.port == port) {
                        // Only once the POS has reported: a tunnel on the port before that is the
                        // previous session's, still connected, which `Open` is about to replace.
                        Some(lease) if reported && lease.listening => break lease,
                        Some(_) => false,
                        None => bail!(
                            "the relay dropped the lease while {name} was opening the session"
                        ),
                    },
                    Err(e) if e.is::<Starting>() => true,
                    Err(e) => return Err(e),
                };
                if Instant::now() >= deadline {
                    let waited = humantime::format_duration(ctx.timing.open);
                    if starting {
                        bail!("{Starting}. Run `posctl connect \"{name}\"` again in a few minutes");
                    }
                    if reported {
                        bail!(
                            "{name} opened the session, but its tunnel didn't reach the relay within {waited}"
                        );
                    }
                    bail!("{name} didn't report on the session within {waited}");
                }
                std::thread::sleep(ctx.timing.poll);
            }
        };
        ctx.workstation.save(
            &Session {
                device_id: device.id,
                name: name.to_owned(),
                alias: alias.clone(),
                host_key: host_key.clone(),
                started: lease.started.clone(),
            },
            &key,
        )?;
        ctx.workstation.write_ssh_files()?;
        if ctx.workstation.ensure_include()? {
            eprintln!(
                "Added `Include posctl/config` at the top of {}.",
                ctx.workstation.ssh_dir.join("config").display()
            );
        }
        ctx.relay.login(&alias)?;
        Ok(lease)
    })();

    match built {
        Ok(lease) => Ok(Connected {
            alias,
            lease,
            how: if joining { How::Joined } else { How::Opened },
        }),
        Err(e) => {
            // A joiner's failure ends nothing: the session isn't its to close. Its own failed open is
            // closed again, the POS asked to tear down without waiting on a POS that may not answer.
            if !joining {
                let _ = ctx.relay.tunnelctl(&format!("close {port}"));
                let _ = ctx
                    .api
                    .run_script(device.id, invoke_script, "-Action Close");
            }
            let _ = ctx.workstation.remove(device.id);
            let _ = ctx.workstation.write_ssh_files();
            Err(e)
        }
    }
}

/// Renews the idle timeout on the relay, then on the POS (design section 7.3). The relay lease is the
/// one that counts, so a refusal there stops; a POS that doesn't confirm is an error naming what was
/// renewed.
pub fn keepalive(ctx: &Context, name: &str) -> Result<Lease> {
    let device = fleet::find_pos(ctx.api, ctx.ninja, name)?;
    let port = relay::port(&device)?;
    let lease: Lease = relay::ask(ctx.relay, &format!("renew {port}"))?;
    let unconfirmed = if device.offline {
        Some("it is offline".to_owned())
    } else {
        match invoke(ctx, device.id, "-Action Touch") {
            Ok(result) if result.success => None,
            Ok(result) => Some(format!("it reported:\n{}", result.output)),
            Err(e) => Some(format!("{e:#}")),
        }
    };
    if let Some(why) = unconfirmed {
        bail!(
            "the relay lease for {name} is renewed (idle timeout in {}), but the POS didn't renew its side: {why}\nThe POS ends its side at its own idle deadline unless a later `posctl keepalive` reaches it.",
            span(lease.idle_remaining)
        );
    }
    Ok(lease)
}

#[derive(Debug, PartialEq)]
pub struct Row {
    pub name: String,
    /// The alias, where this workstation holds the session.
    pub alias: Option<String>,
    pub lease: Lease,
}

/// One row per lease on the relay, or the named POS's alone (design section 7.4).
pub fn status(ctx: &Context, name: Option<&str>) -> Result<Vec<Row>> {
    let leases = relay::leases(ctx.relay)?;
    let held = ctx.workstation.reconcile(&leases)?;
    let devices = match name {
        Some(name) => vec![fleet::find_pos(ctx.api, ctx.ninja, name)?],
        None => fleet::pos_devices(ctx.api, ctx.ninja)?,
    };
    let rows = leases.into_iter().filter_map(|lease| {
        let device = devices.iter().find(|device| device.id == lease.device_id);
        if name.is_some() && device.is_none() {
            return None;
        }
        Some(Row {
            name: device
                .and_then(|device| device.display_name.clone())
                .unwrap_or_else(|| format!("device {}", lease.device_id)),
            alias: held
                .iter()
                .find(|session| session.device_id == lease.device_id)
                .map(|session| session.alias.clone()),
            lease,
        })
    });
    Ok(rows.collect())
}

/// The POS's side of a `close`.
#[derive(Debug, PartialEq)]
pub enum PosSide {
    /// `Close`'s own line: `session ended`, with the number of session keys from package version 4.
    Confirmed(String),
    /// Not asked: it tears down at its own idle deadline.
    Offline,
    Unconfirmed(String),
}

#[derive(Debug, PartialEq)]
pub struct Closed {
    /// The relay held a lease, now closed.
    pub had_lease: bool,
    pub pos: PosSide,
}

pub fn close(ctx: &Context, name: &str) -> Result<Closed> {
    let device = fleet::find_pos(ctx.api, ctx.ninja, name)?;
    end(ctx, &device)
}

/// Ends the session on `device` for every operator on it (design section 7.5): the relay first, which
/// cuts the tunnel whatever the POS does, then the POS, then this workstation's own state. `Close` runs
/// without a lease too, which cleans up a session left on the POS alone.
pub(crate) fn end(ctx: &Context, device: &Device) -> Result<Closed> {
    let port = relay::port(device)?;
    let had_lease = relay::leases(ctx.relay)?
        .iter()
        .any(|lease| lease.port == port);
    if had_lease {
        ctx.relay.tunnelctl(&format!("close {port}"))?;
    }
    let pos = if device.offline {
        PosSide::Offline
    } else {
        match invoke(ctx, device.id, "-Action Close") {
            Ok(result) if result.success => PosSide::Confirmed(
                result
                    .output
                    .lines()
                    .find_map(|line| line.strip_prefix("OK\tclose\t"))
                    .unwrap_or_default()
                    .to_owned(),
            ),
            Ok(result) => PosSide::Unconfirmed(format!("it reported:\n{}", result.output)),
            Err(e) => PosSide::Unconfirmed(format!("{e:#}")),
        }
    };
    ctx.workstation.remove(device.id)?;
    ctx.workstation.write_ssh_files()?;
    Ok(Closed { had_lease, pos })
}

/// Break glass (design section 7.6): closes the session and opens a new one, with a new 72h maximum.
/// The caller has already had the operator confirm.
pub fn rebuild(ctx: &Context, name: &str) -> Result<Connected> {
    let device = fleet::find_pos(ctx.api, ctx.ninja, name)?;
    if device.offline {
        bail!("{name} is offline; nothing was closed");
    }
    if let PosSide::Unconfirmed(why) = end(ctx, &device)?.pos {
        bail!(
            "the session on {name} is closed on the relay, but the POS didn't confirm its teardown, so it wasn't reopened: {why}"
        );
    }
    // `open` waits for the daemon to drop the lease just closed.
    open(ctx, &device, name, MAX_IDLE, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{FakeRelay, Pos, context, pos_tenant, workstation};

    #[test]
    fn spans_read_as_hours_and_minutes() {
        assert_eq!(span(43200), "12h 0m");
        assert_eq!(span(43079), "11h 57m");
        assert_eq!(span(3599), "59m");
        assert_eq!(span(45), "45s");
        assert_eq!(span(0), "0s");
    }

    #[test]
    fn connect_opens_a_session_and_leaves_a_working_alias() {
        let (tenant, pos) = pos_tenant(Pos::default());
        let relay = FakeRelay::new("Jacob");
        let ws = workstation("connect");
        let api = Api::with_token(&tenant.url, "t");
        let ctx = context(&api, &relay, &ws);

        let connected = connect(&ctx, "POS 000 Test", Duration::from_secs(7200)).unwrap();

        assert_eq!(connected.how, How::Opened);
        assert_eq!(connected.alias, "pos-000-test");
        // The relay got the POS's relay public key, the POS the session's, bare.
        assert_eq!(
            relay.calls()[1],
            format!("open 20001 1 7200 {}", pos.relay_key)
        );
        let session_key = keys::public_of_file(&ws.session_key(1)).unwrap();
        let run = &tenant.requests_to("POST", "/v2/device/1/script/run")[0];
        assert_eq!(run["id"], 94);
        assert_eq!(run["runAs"], "system");
        assert_eq!(
            run["parameters"],
            format!(
                "-Action Open -Port 20001 -IdleSeconds 7200 -SessionKey {}",
                session_key.trim_start_matches("ssh-ed25519 ")
            )
        );
        // The alias is written, with the POS's SSH server public key pinned, and was logged in through.
        let held = ws.held().unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(
            (held[0].alias.as_str(), held[0].host_key.as_str()),
            ("pos-000-test", pos.host_key.as_str())
        );
        assert_eq!(held[0].started, connected.lease.started);
        let config = std::fs::read_to_string(ws.config_file()).unwrap();
        assert!(config.contains("Host pos-000-test\n"), "{config}");
        assert_eq!(
            std::fs::read_to_string(ws.ssh_dir.join("config")).unwrap(),
            "Include posctl/config\n\n"
        );
        assert_eq!(*relay.logins.borrow(), ["pos-000-test"]);
    }

    #[test]
    fn connect_again_from_the_same_workstation_reports_the_open_session() {
        let (tenant, _) = pos_tenant(Pos::default());
        let relay = FakeRelay::new("Jacob");
        let ws = workstation("connect again");
        let api = Api::with_token(&tenant.url, "t");
        let ctx = context(&api, &relay, &ws);
        connect(&ctx, "POS 000 Test", MAX_IDLE).unwrap();

        let again = connect(&ctx, "POS 000 Test", MAX_IDLE).unwrap();

        assert_eq!(again.how, How::AlreadyOpen);
        assert_eq!(again.alias, "pos-000-test");
        assert_eq!(
            tenant.requests_to("POST", "/v2/device/1/script/run").len(),
            1
        );
        assert_eq!(relay.count("open"), 1);
    }

    #[test]
    fn connect_refuses_an_offline_or_uninstalled_pos_before_changing_anything() {
        for (pos, expected) in [
            (
                Pos {
                    offline: true,
                    ..Pos::default()
                },
                "POS 000 Test is offline",
            ),
            (
                Pos {
                    relay_key: "not a key; rm -rf".into(),
                    ..Pos::default()
                },
                "run `posctl update \"POS 000 Test\"`",
            ),
        ] {
            let (tenant, _) = pos_tenant(pos);
            let relay = FakeRelay::new("Jacob");
            let ws = workstation("connect refused");
            let api = Api::with_token(&tenant.url, "t");
            let error = connect(&context(&api, &relay, &ws), "POS 000 Test", MAX_IDLE)
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "{error}");
            assert_eq!(relay.count("open"), 0);
            assert!(
                tenant
                    .requests_to("POST", "/v2/device/1/script/run")
                    .is_empty()
            );
        }
    }

    #[test]
    fn a_failed_open_is_closed_again_and_reports_what_the_pos_said() {
        let (tenant, _) = pos_tenant(Pos {
            fail: Some("Open"),
            ..Pos::default()
        });
        let relay = FakeRelay::new("Jacob");
        let ws = workstation("open failed");
        let api = Api::with_token(&tenant.url, "t");

        let error = connect(&context(&api, &relay, &ws), "POS 000 Test", MAX_IDLE)
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("couldn't open the session. It reported:\nFAILED\tOpen\tboom"),
            "{error}"
        );
        assert!(relay.leases.borrow().is_empty());
        assert_eq!(relay.calls().last().unwrap(), "close 20001");
        let runs = tenant.requests_to("POST", "/v2/device/1/script/run");
        assert_eq!(runs[1]["parameters"], "-Action Close");
        assert!(ws.held().unwrap().is_empty());
        assert!(!ws.session_key(1).exists());
    }

    #[test]
    fn a_tunnel_that_never_comes_up_times_out_and_is_closed_again() {
        let (tenant, _) = pos_tenant(Pos::default());
        let relay = FakeRelay::new("Jacob");
        relay.listening.set(false);
        let ws = workstation("no tunnel");
        let api = Api::with_token(&tenant.url, "t");

        let error = connect(&context(&api, &relay, &ws), "POS 000 Test", MAX_IDLE)
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("opened the session, but its tunnel didn't reach the relay"),
            "{error}"
        );
        assert!(relay.leases.borrow().is_empty());
        assert!(ws.held().unwrap().is_empty());
    }

    #[test]
    fn a_tunnel_up_before_the_pos_reports_is_not_taken_for_this_session() {
        // The previous session's tunnel still holds the port, and this POS never answers.
        let (tenant, _) = pos_tenant(Pos {
            silent: true,
            ..Pos::default()
        });
        let relay = FakeRelay::new("Jacob");
        let ws = workstation("stale tunnel");
        let api = Api::with_token(&tenant.url, "t");

        let error = connect(&context(&api, &relay, &ws), "POS 000 Test", MAX_IDLE)
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("POS 000 Test didn't report on the session within"),
            "{error}"
        );
        assert!(relay.logins.borrow().is_empty());
        assert!(relay.leases.borrow().is_empty());
    }

    #[test]
    fn a_relay_that_is_starting_says_so_when_the_wait_runs_out() {
        let (tenant, _) = pos_tenant(Pos::default());
        let relay = FakeRelay::new("Jacob");
        // The daemon stops answering once the lease is open.
        relay.starting_after.set(Some(2));
        let ws = workstation("starting");
        let api = Api::with_token(&tenant.url, "t");

        let error = connect(&context(&api, &relay, &ws), "POS 000 Test", MAX_IDLE)
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("the relay is starting") && error.contains("again in a few minutes"),
            "{error}"
        );
    }

    #[test]
    fn a_failed_login_undoes_the_session() {
        let (tenant, _) = pos_tenant(Pos::default());
        let relay = FakeRelay::new("Jacob");
        *relay.login_error.borrow_mut() = Some("Host key verification failed.".into());
        let ws = workstation("login failed");
        let api = Api::with_token(&tenant.url, "t");

        let error = connect(&context(&api, &relay, &ws), "POS 000 Test", MAX_IDLE)
            .unwrap_err()
            .to_string();

        assert!(error.contains("Host key verification failed"), "{error}");
        assert!(relay.leases.borrow().is_empty());
        assert!(ws.held().unwrap().is_empty());
        let config = std::fs::read_to_string(ws.config_file()).unwrap();
        assert!(!config.contains("Host pos-000-test"), "{config}");
    }

    #[test]
    fn connect_joins_a_session_another_workstation_opened() {
        let (tenant, _) = pos_tenant(Pos::default());
        let relay = FakeRelay::new("Bob");
        relay.open_as("Jacob", 1);
        let ws = workstation("join");
        let api = Api::with_token(&tenant.url, "t");

        let connected = connect(&context(&api, &relay, &ws), "POS 000 Test", MAX_IDLE).unwrap();

        assert_eq!(connected.how, How::Joined);
        assert_eq!(connected.lease.operator, "Jacob");
        // No second lease: the idle timer restarts and the POS adds this workstation's key.
        assert_eq!(relay.calls(), ["status", "renew 20001"]);
        let session_key = keys::public_of_file(&ws.session_key(1)).unwrap();
        assert_eq!(
            tenant.requests_to("POST", "/v2/device/1/script/run")[0]["parameters"],
            format!(
                "-Action Open -Mode Join -Port 20001 -SessionKey {}",
                session_key.trim_start_matches("ssh-ed25519 ")
            )
        );
        // The same `started` as the opener's lease, so this workstation sees the session as its own.
        assert_eq!(ws.held().unwrap()[0].started, connected.lease.started);
        assert_eq!(*relay.logins.borrow(), ["pos-000-test"]);
    }

    #[test]
    fn a_failed_join_leaves_the_other_operators_session_alone() {
        let (tenant, _) = pos_tenant(Pos {
            fail: Some("Open"),
            ..Pos::default()
        });
        let relay = FakeRelay::new("Bob");
        relay.open_as("Jacob", 1);
        let ws = workstation("join failed");
        let api = Api::with_token(&tenant.url, "t");

        let error = connect(&context(&api, &relay, &ws), "POS 000 Test", MAX_IDLE)
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("couldn't add this workstation to the session"),
            "{error}"
        );
        assert_eq!(relay.leases.borrow().len(), 1);
        assert_eq!(relay.count("close"), 0);
        assert_eq!(
            tenant.requests_to("POST", "/v2/device/1/script/run").len(),
            1
        );
        assert!(ws.held().unwrap().is_empty());
    }

    #[test]
    fn a_pos_package_too_old_to_share_a_session_refuses_the_join() {
        let (tenant, _) = pos_tenant(Pos {
            version: "3",
            ..Pos::default()
        });
        let relay = FakeRelay::new("Bob");
        relay.open_as("Jacob", 1);
        let ws = workstation("join old");
        let api = Api::with_token(&tenant.url, "t");

        let error = connect(&context(&api, &relay, &ws), "POS 000 Test", MAX_IDLE)
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("is in a session Jacob opened")
                && error.contains("run `posctl update \"POS 000 Test\"`"),
            "{error}"
        );
        assert_eq!(relay.calls(), ["status"]);
        assert!(
            tenant
                .requests_to("POST", "/v2/device/1/script/run")
                .is_empty()
        );
    }

    #[test]
    fn keepalive_renews_the_relay_then_the_pos() {
        let (tenant, _) = pos_tenant(Pos::default());
        let relay = FakeRelay::new("Jacob");
        relay.open_as("Jacob", 1);
        let ws = workstation("keepalive");
        let api = Api::with_token(&tenant.url, "t");

        let lease = keepalive(&context(&api, &relay, &ws), "POS 000 Test").unwrap();

        assert_eq!(lease.idle_remaining, 43200);
        assert_eq!(relay.calls(), ["renew 20001"]);
        assert_eq!(
            tenant.requests_to("POST", "/v2/device/1/script/run")[0]["parameters"],
            "-Action Touch"
        );
    }

    #[test]
    fn keepalive_stops_when_the_relay_refuses_and_says_when_the_pos_does_not_confirm() {
        let (tenant, _) = pos_tenant(Pos {
            fail: Some("Touch"),
            ..Pos::default()
        });
        let relay = FakeRelay::new("Jacob");
        let ws = workstation("keepalive refused");
        let api = Api::with_token(&tenant.url, "t");
        let ctx = context(&api, &relay, &ws);

        // No lease: the relay refuses, and the POS isn't asked.
        let error = keepalive(&ctx, "POS 000 Test").unwrap_err().to_string();
        assert!(error.contains("no lease for port 20001"), "{error}");
        assert!(
            tenant
                .requests_to("POST", "/v2/device/1/script/run")
                .is_empty()
        );

        relay.open_as("Jacob", 1);
        let error = keepalive(&ctx, "POS 000 Test").unwrap_err().to_string();
        assert!(
            error.contains("the relay lease for POS 000 Test is renewed (idle timeout in 12h 0m), but the POS didn't renew its side")
                && error.contains("FAILED\tTouch\tboom"),
            "{error}"
        );
    }

    #[test]
    fn status_names_each_lease_and_marks_this_workstations_sessions() {
        let (tenant, _) = pos_tenant(Pos::default());
        let relay = FakeRelay::new("Jacob");
        let ws = workstation("status");
        let api = Api::with_token(&tenant.url, "t");
        let ctx = context(&api, &relay, &ws);
        connect(&ctx, "POS 000 Test", MAX_IDLE).unwrap();
        relay.open_as("Bob", 2);
        // A lease for a device NinjaOne no longer lists as a POS.
        relay.open_as("Bob", 77);

        let rows = status(&ctx, None).unwrap();

        let seen: Vec<(&str, Option<&str>, &str)> = rows
            .iter()
            .map(|row| {
                (
                    row.name.as_str(),
                    row.alias.as_deref(),
                    row.lease.operator.as_str(),
                )
            })
            .collect();
        assert_eq!(
            seen,
            [
                ("POS 000 Test", Some("pos-000-test"), "Jacob"),
                ("POS 002", None, "Bob"),
                ("device 77", None, "Bob"),
            ]
        );
        let one = status(&ctx, Some("POS 002")).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].name, "POS 002");
    }

    #[test]
    fn status_drops_the_alias_of_a_session_that_ended_elsewhere() {
        let (tenant, _) = pos_tenant(Pos::default());
        let relay = FakeRelay::new("Jacob");
        let ws = workstation("status ended");
        let api = Api::with_token(&tenant.url, "t");
        let ctx = context(&api, &relay, &ws);
        connect(&ctx, "POS 000 Test", MAX_IDLE).unwrap();
        // Another operator closes it and opens a new one.
        relay.leases.borrow_mut().clear();
        relay.open_as("Bob", 1);

        let rows = status(&ctx, None).unwrap();

        assert_eq!(rows[0].alias, None);
        assert!(ws.held().unwrap().is_empty());
        assert!(!ws.session_key(1).exists());
    }

    #[test]
    fn close_ends_the_relay_lease_then_the_pos_then_the_local_state() {
        let (tenant, _) = pos_tenant(Pos::default());
        let relay = FakeRelay::new("Jacob");
        let ws = workstation("close");
        let api = Api::with_token(&tenant.url, "t");
        let ctx = context(&api, &relay, &ws);
        connect(&ctx, "POS 000 Test", MAX_IDLE).unwrap();

        let closed = close(&ctx, "POS 000 Test").unwrap();

        assert_eq!(
            closed,
            Closed {
                had_lease: true,
                pos: PosSide::Confirmed("session ended".into())
            }
        );
        assert_eq!(relay.calls().last().unwrap(), "close 20001");
        assert!(ws.held().unwrap().is_empty());
        assert!(
            !std::fs::read_to_string(ws.config_file())
                .unwrap()
                .contains("pos-000-test")
        );

        // Nothing on the relay: the POS is still asked, which cleans up a session left on it alone.
        let again = close(&ctx, "POS 000 Test").unwrap();
        assert!(!again.had_lease);
        assert_eq!(
            tenant.requests_to("POST", "/v2/device/1/script/run").len(),
            3
        );
    }

    #[test]
    fn close_skips_an_offline_pos_and_reports_one_that_does_not_confirm() {
        for (pos, expected) in [
            (
                Pos {
                    offline: true,
                    ..Pos::default()
                },
                PosSide::Offline,
            ),
            (
                Pos {
                    fail: Some("Close"),
                    ..Pos::default()
                },
                PosSide::Unconfirmed("it reported:\nFAILED\tClose\tboom".into()),
            ),
        ] {
            let (tenant, _) = pos_tenant(pos);
            let relay = FakeRelay::new("Jacob");
            relay.open_as("Jacob", 1);
            let ws = workstation("close unconfirmed");
            let api = Api::with_token(&tenant.url, "t");

            let closed = close(&context(&api, &relay, &ws), "POS 000 Test").unwrap();

            assert_eq!(closed.pos, expected);
            assert!(closed.had_lease);
            assert!(relay.leases.borrow().is_empty());
        }
    }

    #[test]
    fn rebuild_closes_waits_for_the_lease_to_go_and_opens_anew() {
        let (tenant, _) = pos_tenant(Pos::default());
        let relay = FakeRelay::new("Jacob");
        // As the real daemon: a closed lease is still listed until its next pass.
        relay.linger.set(2);
        let ws = workstation("rebuild");
        let api = Api::with_token(&tenant.url, "t");
        let ctx = context(&api, &relay, &ws);
        let first = connect(&ctx, "POS 000 Test", MAX_IDLE).unwrap();

        let rebuilt = rebuild(&ctx, "POS 000 Test").unwrap();

        assert_eq!(rebuilt.how, How::Opened);
        assert_ne!(rebuilt.lease.started, first.lease.started);
        let opens: Vec<String> = relay
            .calls()
            .into_iter()
            .filter(|call| call.starts_with("open "))
            .collect();
        assert_eq!(opens.len(), 2);
        assert!(opens[1].ends_with(" --rebuild"), "{opens:?}");
        let runs: Vec<String> = tenant
            .requests_to("POST", "/v2/device/1/script/run")
            .iter()
            .map(|run| {
                run["parameters"]
                    .as_str()
                    .unwrap()
                    .split(' ')
                    .nth(1)
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(runs, ["Open", "Close", "Open"]);
    }

    #[test]
    fn connect_waits_out_a_lease_that_has_just_ended() {
        let (tenant, _) = pos_tenant(Pos::default());
        let relay = FakeRelay::new("Jacob");
        relay.linger.set(2);
        // Bob's session, closed a moment ago: the daemon still lists it, out of time.
        relay.open_as("Bob", 1);
        relay.tunnelctl("close 20001").unwrap();
        let ws = workstation("connect ended");
        let api = Api::with_token(&tenant.url, "t");

        let connected = connect(&context(&api, &relay, &ws), "POS 000 Test", MAX_IDLE).unwrap();

        // Opened anew, not joined to the session that ended.
        assert_eq!(connected.how, How::Opened);
        assert_eq!(connected.lease.operator, "Jacob");
        assert_eq!(relay.count("renew"), 0);
    }

    #[test]
    fn rebuild_does_not_reopen_when_the_pos_did_not_confirm_its_teardown() {
        let (tenant, _) = pos_tenant(Pos {
            fail: Some("Close"),
            ..Pos::default()
        });
        let relay = FakeRelay::new("Jacob");
        relay.open_as("Jacob", 1);
        let ws = workstation("rebuild unconfirmed");
        let api = Api::with_token(&tenant.url, "t");

        let error = rebuild(&context(&api, &relay, &ws), "POS 000 Test")
            .unwrap_err()
            .to_string();

        assert!(error.contains("so it wasn't reopened"), "{error}");
        assert_eq!(relay.count("open"), 0);
    }
}

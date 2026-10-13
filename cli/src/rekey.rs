//! `posctl rekey` (design section 7.8): new key pairs on one POS or on every online one.

use anyhow::{Result, bail};

use crate::fleet;
use crate::ninja::{Device, INVOKE_SCRIPT};
use crate::relay;
use crate::session::Context;

/// What a rekey will do, settled before anything changes so that `--all` can ask first.
#[derive(Debug)]
pub struct Plan {
    /// The POSes to rekey, each with the port of the relay lease to close first, if it has one.
    pub targets: Vec<(Device, Option<u16>)>,
    /// The POSes left out, by name, each with why.
    pub skipped: Vec<(String, String)>,
}

#[derive(Debug, PartialEq)]
pub enum Outcome {
    Rekeyed,
    Skipped(String),
    Failed(String),
}

fn label(device: &Device) -> String {
    device
        .display_name
        .clone()
        .unwrap_or_else(|| format!("device {}", device.id))
}

/// The named POS, or with `None` every POS of the organization. An offline POS, and without `force`
/// one in a session, can't be rekeyed: named, that is an error; among all, it is skipped.
pub fn plan(ctx: &Context, name: Option<&str>, force: bool) -> Result<Plan> {
    let devices = match name {
        Some(name) => vec![fleet::find_pos(ctx.api, ctx.ninja, name)?],
        None => fleet::pos_devices(ctx.api, ctx.ninja)?,
    };
    let leases = relay::leases(ctx.relay)?;
    let mut plan = Plan {
        targets: Vec::new(),
        skipped: Vec::new(),
    };
    for device in devices {
        let lease = leases.iter().find(|lease| lease.device_id == device.id);
        let obstacle = match lease {
            _ if device.offline => Some("offline".to_owned()),
            Some(lease) if !force => Some(format!("in a session {} opened", lease.operator)),
            _ => None,
        };
        match obstacle {
            Some(why) if name.is_some() => bail!(
                "{} is {why}{}",
                label(&device),
                if device.offline {
                    ""
                } else {
                    ": `posctl close` it first, or pass --force to end it"
                }
            ),
            Some(why) => plan.skipped.push((label(&device), why)),
            None => plan.targets.push((device, lease.map(|lease| lease.port))),
        }
    }
    Ok(plan)
}

/// Carries `plan` out and returns one outcome per POS, the skipped ones included. With `force`, each
/// target's session is ended first as `close` does (design section 7.5): its relay lease closed, then
/// `Close` run on every target, with a lease or not, so a session left on a POS alone doesn't block
/// its rekey. All POSes run together.
pub fn run(ctx: &Context, plan: Plan, force: bool) -> Result<Vec<(String, Outcome)>> {
    let mut outcomes: Vec<(String, Outcome)> = plan
        .skipped
        .into_iter()
        .map(|(name, why)| (name, Outcome::Skipped(why)))
        .collect();
    let script = ctx.ninja.invoke_script_id;
    let all = |ids: &[i64], action: &str| {
        ctx.api.run_scripts(
            ids,
            script,
            INVOKE_SCRIPT,
            &format!("-Action {action}"),
            ctx.timing.script,
            ctx.timing.poll,
        )
    };
    let mut targets: Vec<Device> = Vec::new();
    if force {
        let mut closing = Vec::new();
        for (device, port) in plan.targets {
            let closed = port.map_or(Ok(String::new()), |port| {
                ctx.relay.tunnelctl(&format!("close {port}"))
            });
            match closed {
                Ok(_) => closing.push(device),
                Err(e) => outcomes.push((
                    label(&device),
                    Outcome::Failed(format!("its relay lease couldn't be closed: {e:#}")),
                )),
            }
        }
        let ids: Vec<i64> = closing.iter().map(|device| device.id).collect();
        for (device, closed) in closing.into_iter().zip(all(&ids, "Close")) {
            ctx.workstation.remove(device.id)?;
            match closed {
                Ok(result) if result.success => targets.push(device),
                Ok(result) => outcomes.push((
                    label(&device),
                    Outcome::Failed(format!(
                        "its session couldn't be ended. It reported:\n{}",
                        result.output
                    )),
                )),
                Err(e) => outcomes.push((
                    label(&device),
                    Outcome::Failed(format!("its session couldn't be ended: {e:#}")),
                )),
            }
        }
        ctx.workstation.write_ssh_files()?;
    } else {
        targets.extend(plan.targets.into_iter().map(|(device, _)| device));
    }
    let ids: Vec<i64> = targets.iter().map(|device| device.id).collect();
    for (device, rekeyed) in targets.iter().zip(all(&ids, "Rekey")) {
        let outcome = match rekeyed {
            Ok(result) if result.success => Outcome::Rekeyed,
            Ok(result) => Outcome::Failed(format!("it reported:\n{}", result.output)),
            Err(e) => Outcome::Failed(format!("{e:#}")),
        };
        outcomes.push((label(device), outcome));
    }
    Ok(outcomes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{FakeRelay, Pos, context, pos_tenant, workstation};
    use crate::ninja::Api;
    use crate::session;

    fn actions(tenant: &crate::fake::Fake, device: i64) -> Vec<String> {
        tenant
            .requests_to("POST", &format!("/v2/device/{device}/script/run"))
            .iter()
            .map(|run| run["parameters"].as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn rekey_runs_on_the_named_pos() {
        let (tenant, _) = pos_tenant(Pos::default());
        let relay = FakeRelay::new("Jacob");
        let ws = workstation("rekey one");
        let api = Api::with_token(&tenant.url, "t");
        let ctx = context(&api, &relay, &ws);

        let plan = plan(&ctx, Some("POS 000 Test"), false).unwrap();
        let outcomes = run(&ctx, plan, false).unwrap();

        assert_eq!(outcomes, [("POS 000 Test".to_owned(), Outcome::Rekeyed)]);
        assert_eq!(actions(&tenant, 1), ["-Action Rekey"]);
        assert!(actions(&tenant, 2).is_empty());
    }

    #[test]
    fn a_named_pos_that_is_offline_or_in_a_session_is_refused() {
        let (tenant, _) = pos_tenant(Pos::default());
        let relay = FakeRelay::new("Jacob");
        relay.open_as("Bob", 1);
        let ws = workstation("rekey refused");
        let api = Api::with_token(&tenant.url, "t");
        let ctx = context(&api, &relay, &ws);

        let error = plan(&ctx, Some("POS 000 Test"), false)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("POS 000 Test is in a session Bob opened")
                && error.contains("pass --force to end it"),
            "{error}"
        );
        let error = plan(&ctx, Some("POS 003"), true).unwrap_err().to_string();
        assert_eq!(error, "POS 003 is offline");
        assert!(actions(&tenant, 1).is_empty());
    }

    #[test]
    fn force_ends_the_session_whoever_opened_it_then_rekeys() {
        let (tenant, _) = pos_tenant(Pos::default());
        let relay = FakeRelay::new("Jacob");
        let ws = workstation("rekey force");
        let api = Api::with_token(&tenant.url, "t");
        let ctx = context(&api, &relay, &ws);
        // This workstation joined a session Bob opened.
        relay.open_as("Bob", 1);
        session::connect(&ctx, "POS 000 Test", session::MAX_IDLE).unwrap();

        let plan = plan(&ctx, Some("POS 000 Test"), true).unwrap();
        let outcomes = run(&ctx, plan, true).unwrap();

        assert_eq!(outcomes, [("POS 000 Test".to_owned(), Outcome::Rekeyed)]);
        assert!(relay.leases.borrow().is_empty());
        assert_eq!(actions(&tenant, 1)[1..], ["-Action Close", "-Action Rekey"]);
        assert!(ws.held().unwrap().is_empty());
    }

    #[test]
    fn force_runs_close_without_a_relay_lease_too() {
        let (tenant, _) = pos_tenant(Pos::default());
        let relay = FakeRelay::new("Jacob");
        let ws = workstation("rekey force no lease");
        let api = Api::with_token(&tenant.url, "t");
        let ctx = context(&api, &relay, &ws);

        let plan = plan(&ctx, Some("POS 000 Test"), true).unwrap();
        run(&ctx, plan, true).unwrap();

        assert_eq!(actions(&tenant, 1), ["-Action Close", "-Action Rekey"]);
        assert_eq!(relay.count("close"), 0);
    }

    #[test]
    fn all_rekeys_every_online_pos_and_skips_the_rest() {
        let (tenant, _) = pos_tenant(Pos {
            fail: Some("Rekey"),
            ..Pos::default()
        });
        let relay = FakeRelay::new("Jacob");
        let ws = workstation("rekey all");
        let api = Api::with_token(&tenant.url, "t");
        let ctx = context(&api, &relay, &ws);

        let plan = plan(&ctx, None, false).unwrap();
        assert_eq!(plan.targets.len(), 2);
        let outcomes = run(&ctx, plan, false).unwrap();

        assert_eq!(
            outcomes,
            [
                ("POS 003".to_owned(), Outcome::Skipped("offline".into())),
                (
                    "POS 000 Test".to_owned(),
                    Outcome::Failed("it reported:\nFAILED\tRekey\tboom".into())
                ),
                ("POS 002".to_owned(), Outcome::Rekeyed),
            ]
        );
        assert!(actions(&tenant, 3).is_empty());
    }

    #[test]
    fn all_skips_a_pos_in_a_session_unless_forced() {
        let (tenant, _) = pos_tenant(Pos::default());
        let relay = FakeRelay::new("Jacob");
        relay.open_as("Bob", 2);
        let ws = workstation("rekey all session");
        let api = Api::with_token(&tenant.url, "t");
        let ctx = context(&api, &relay, &ws);

        let unforced = plan(&ctx, None, false).unwrap();
        assert_eq!(
            unforced.skipped,
            [
                ("POS 002".to_owned(), "in a session Bob opened".to_owned()),
                ("POS 003".to_owned(), "offline".to_owned()),
            ]
        );
        assert_eq!(unforced.targets.len(), 1);

        let forced = plan(&ctx, None, true).unwrap();
        let ending: Vec<Option<u16>> = forced.targets.iter().map(|(_, port)| *port).collect();
        assert_eq!(ending, [None, Some(20002)]);
        let outcomes = run(&ctx, forced, true).unwrap();
        assert_eq!(
            outcomes[1..],
            [
                ("POS 000 Test".to_owned(), Outcome::Rekeyed),
                ("POS 002".to_owned(), Outcome::Rekeyed),
            ]
        );
        assert!(relay.leases.borrow().is_empty());
        assert_eq!(actions(&tenant, 2), ["-Action Close", "-Action Rekey"]);
    }

    #[test]
    fn a_pos_that_never_reports_fails_alone() {
        let (tenant, _) = pos_tenant(Pos {
            silent: true,
            ..Pos::default()
        });
        let relay = FakeRelay::new("Jacob");
        let ws = workstation("rekey silent");
        let api = Api::with_token(&tenant.url, "t");
        let ctx = context(&api, &relay, &ws);

        let plan = plan(&ctx, None, false).unwrap();
        let outcomes = run(&ctx, plan, false).unwrap();

        let Outcome::Failed(why) = &outcomes[1].1 else {
            panic!("{outcomes:?}");
        };
        assert!(
            why.contains("reported no result for Invoke-PosTunnel within"),
            "{why}"
        );
        assert_eq!(outcomes[2], ("POS 002".to_owned(), Outcome::Rekeyed));
    }
}

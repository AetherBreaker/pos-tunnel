//! The six custom fields and the fleet-wide NinjaOne operations of `posctl-admin`.

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use crate::config::NinjaOne;
use crate::ninja::{Api, Device, FieldDefinition};

pub struct Field {
    pub name: &'static str,
    pub label: &'static str,
    /// A fleet field (organization scope, written by `posctl-admin`) rather than a device field
    /// (written by the POS).
    pub fleet: bool,
}

pub const FIELDS: [Field; 6] = [
    Field {
        name: "posTunnelRelayKey",
        label: "PosTunnel relay public key",
        fleet: false,
    },
    Field {
        name: "posTunnelHostKey",
        label: "PosTunnel SSH server public key",
        fleet: false,
    },
    Field {
        name: "posTunnelVersion",
        label: "PosTunnel package version",
        fleet: false,
    },
    Field {
        name: "posTunnelRelay",
        label: "PosTunnel relay address",
        fleet: true,
    },
    Field {
        name: "posTunnelRelayServerKey",
        label: "PosTunnel relay server public key",
        fleet: true,
    },
    Field {
        name: "posTunnelSigner",
        label: "PosTunnel release signing public key",
        fleet: true,
    },
];

impl Field {
    /// Definition scope, script permission, API permission. A device field is written by the POS's
    /// scripts and only read through the API; a fleet field has organization scope only and is read-only
    /// to scripts, either of which stops a POS writing it.
    fn settings(&self) -> [(&'static str, &'static str); 3] {
        if self.fleet {
            [
                ("definition scope", "ORGANIZATION"),
                ("script permission", "READ_ONLY"),
                ("API permission", "READ_WRITE"),
            ]
        } else {
            [
                ("definition scope", "NODE"),
                ("script permission", "READ_WRITE"),
                ("API permission", "READ_ONLY"),
            ]
        }
    }

    /// The first setting `found` has that differs from this field's, as "<setting> is <got>, expected <want>".
    fn mismatch(&self, found: FieldDefinition) -> Option<String> {
        let actual = [
            found.definition_scope.join(","),
            found.script_permission.unwrap_or_default(),
            found.api_permission.unwrap_or_default(),
        ];
        self.settings()
            .into_iter()
            .zip(actual)
            .find(|((_, want), got)| got != want)
            .map(|((setting, want), got)| format!("{setting} is {got}, expected {want}"))
    }
}

/// Reads all six definitions, refuses if an existing one differs from its settings (naming the field
/// and setting), then creates the missing ones and reads each back. It never changes an existing
/// definition, since a changed setting may be tampering; refusing before creating leaves the tenant as it
/// was.
pub fn ensure_fields(api: &Api) -> Result<Vec<&'static str>> {
    let mut missing = Vec::new();
    for field in &FIELDS {
        match api.field_definition(field.name)? {
            None => missing.push(field),
            Some(found) => {
                if let Some(mismatch) = field.mismatch(found) {
                    bail!(
                        "custom field {}: {mismatch}; fix it in NinjaOne or find out who changed it",
                        field.name
                    );
                }
            }
        }
    }
    for field in &missing {
        let [(_, scope), (_, script), (_, api_permission)] = field.settings();
        // `scope` is deprecated in favour of `definitionScope`, but NinjaOne refuses a create without it;
        // NODE_GLOBAL makes a global field, as opposed to a role field.
        api.create_field(&json!({
            "fieldName": field.name,
            "label": field.label,
            "type": "TEXT",
            "scope": "NODE_GLOBAL",
            "definitionScope": [scope],
            "scriptPermission": script,
            "apiPermission": api_permission,
            "technicianPermission": "READ_ONLY",
        }))?;
        let stored = api.field_definition(field.name)?.with_context(|| {
            format!(
                "NinjaOne accepted custom field {} but doesn't return it",
                field.name
            )
        })?;
        if let Some(mismatch) = field.mismatch(stored) {
            bail!(
                "NinjaOne created custom field {} with {mismatch}; delete it in NinjaOne before trying again",
                field.name
            );
        }
    }
    Ok(missing.iter().map(|field| field.name).collect())
}

/// The POSes: the organization's devices whose effective policy is the POS policy. Their names are
/// shared for Tab completion, so every command that lists them keeps the names current.
pub fn pos_devices(api: &Api, ninja: &NinjaOne) -> Result<Vec<Device>> {
    let poses: Vec<Device> = api
        .devices(ninja.organization_id)?
        .into_iter()
        // The organization's list should hold nothing else; a stray device is still not a POS.
        .filter(|device| {
            device.organization_id == ninja.organization_id
                && device.effective_policy() == Some(ninja.pos_policy_id)
        })
        .collect();
    if let Some(shared) = &api.shared {
        let mut named: Vec<(i64, &str)> = poses
            .iter()
            .filter_map(|device| Some((device.id, device.display_name.as_deref()?)))
            .collect();
        named.sort_unstable_by_key(|&(id, name)| (name, id));
        shared.set_poses(&named);
    }
    Ok(poses)
}

/// The one POS whose display name is exactly `name` (case-sensitive). No match or
/// several is an error naming what was found.
pub fn find_pos(api: &Api, ninja: &NinjaOne, name: &str) -> Result<Device> {
    let poses = pos_devices(api, ninja)?;
    let mut matches: Vec<Device> = poses
        .iter()
        .filter(|d| d.display_name.as_deref() == Some(name))
        .cloned()
        .collect();
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => {
            let near: Vec<&str> = poses
                .iter()
                .filter_map(|d| d.display_name.as_deref())
                .filter(|n| n.eq_ignore_ascii_case(name))
                .collect();
            if near.is_empty() {
                bail!("no POS is named '{name}' (names are matched exactly, case included)");
            }
            bail!(
                "no POS is named '{name}'; names differ only in case: {}",
                near.join(", ")
            );
        }
        _ => {
            let ids: Vec<String> = matches.iter().map(|d| d.id.to_string()).collect();
            bail!(
                "{} POSes are named '{name}' (device IDs {}); rename all but one in NinjaOne",
                matches.len(),
                ids.join(", ")
            );
        }
    }
}

/// Writes fleet field values on the organization, after `ensure_fields`: the one door for a fleet-field
/// write, so a changed definition is always refused first. A POS reads its organization's value.
pub fn set_fleet_fields(api: &Api, ninja: &NinjaOne, values: &Value) -> Result<()> {
    ensure_fields(api)?;
    api.set_organization_fields(ninja.organization_id, values)
}

/// What `relay point` did.
#[derive(Debug, PartialEq)]
pub struct Pointed {
    /// The POSes `Install-PosTunnel -Force` was started on.
    pub ran: Vec<String>,
    /// The offline POSes skipped; they converge at their next scheduled install.
    pub offline: Vec<String>,
    /// The POSes NinjaOne refused to start it on, each with its reason.
    pub failed: Vec<String>,
}

/// `posctl-admin relay point`: writes the organization's fleet relay fields, then starts
/// `Install-PosTunnel -Force` on every online POS at once, or on `device` alone (a test POS, by exact
/// display name). `device` limits the install only: the organization's relay changes either way, so
/// its other POSes follow at their next scheduled install. The targets are listed before the write,
/// so a mistyped or offline `device`, or an organization with no POS, changes nothing.
pub fn point_relay(
    api: &Api,
    ninja: &NinjaOne,
    address: &str,
    public_key: &str,
    device: Option<&str>,
) -> Result<Pointed> {
    let targets = match device {
        Some(name) => {
            let target = find_pos(api, ninja, name)?;
            if target.offline {
                bail!("{name} is offline");
            }
            vec![target]
        }
        None => pos_devices(api, ninja)?,
    };
    // Before the write: an organization and policy that match no device would otherwise get the
    // fields and a report of success with nothing installed.
    if targets.is_empty() {
        bail!(
            "no device of organization {} has the POS policy (id {}); nothing was written",
            ninja.organization_id,
            ninja.pos_policy_id
        );
    }
    let values = json!({"posTunnelRelay": address, "posTunnelRelayServerKey": public_key});
    set_fleet_fields(api, ninja, &values)?;
    let (mut ran, mut offline, mut failed) = (Vec::new(), Vec::new(), Vec::new());
    for device in targets {
        let name = device
            .display_name
            .clone()
            .unwrap_or_else(|| format!("device {}", device.id));
        if device.offline {
            offline.push(name);
        } else {
            // A refused run must not stop the rest: the POSes after it would stay on the old relay,
            // unreachable, with nothing saying which ones.
            match api.run_script(device.id, ninja.install_script_id, "-Force") {
                Ok(()) => ran.push(name),
                Err(e) => failed.push(format!("{name}: {e:#}")),
            }
        }
    }
    Ok(Pointed {
        ran,
        offline,
        failed,
    })
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use super::*;
    use crate::fake::{Fake, Memory};
    use crate::ninja::Shared;

    /// What NinjaOne lists at `path`. Organization 3 holds the POSes and an office PC; organization 5
    /// holds one device on the POS policy, which this system must never see. Any path but an
    /// organization's gets the whole tenant, as `GET /v2/devices` would.
    fn devices(path: &str) -> Value {
        let mut all = json!([
            {"id": 1, "displayName": "POS 000 Test", "organizationId": 3, "rolePolicyId": 7, "offline": false},
            {"id": 2, "displayName": "POS 001", "organizationId": 3, "rolePolicyId": 7, "offline": true},
            {"id": 3, "displayName": "Office PC", "organizationId": 3, "rolePolicyId": 8, "offline": false},
            {"id": 4, "displayName": "POS 900", "organizationId": 3, "rolePolicyId": 8, "policyId": 7, "offline": false},
            {"id": 9, "displayName": "POS 950", "organizationId": 5, "rolePolicyId": 7, "offline": false},
        ]);
        let organization = path
            .strip_prefix("/v2/organization/")
            .and_then(|rest| rest.split('/').next())
            .and_then(|id| id.parse::<i64>().ok());
        // Paged as NinjaOne pages: only the devices after the one `after` names.
        let after = path
            .split_once("&after=")
            .map_or(0, |(_, id)| id.parse::<i64>().unwrap());
        all.as_array_mut().unwrap().retain(|device| {
            device["id"].as_i64() > Some(after)
                && organization.is_none_or(|organization| device["organizationId"] == organization)
        });
        all
    }

    /// A tenant whose six fields already exist as they should, with `devices()`; it accepts every write
    /// but one to `refused`, which gets a 500.
    fn tenant_refusing(refused: Option<&'static str>) -> Fake {
        Fake::start(move |method, path, _| {
            let field = path.strip_prefix("/v2/custom-fields/field-name/");
            match (
                method,
                field.and_then(|name| FIELDS.iter().find(|f| f.name == name)),
            ) {
                ("GET", Some(field)) => {
                    let [(_, scope), (_, script), (_, api)] = field.settings();
                    let definition = json!({"name": field.name, "definitionScope": [scope], "scriptPermission": script, "apiPermission": api});
                    (200, definition)
                }
                ("GET", None) => (200, devices(path)),
                _ if refused == Some(path) => (500, json!({"resultCode": "FAILURE"})),
                _ => (204, Value::Null),
            }
        })
    }

    fn tenant() -> Fake {
        tenant_refusing(None)
    }

    fn ninja() -> NinjaOne {
        NinjaOne {
            base_url: String::new(),
            client_id: String::new(),
            organization_id: 3,
            pos_policy_id: 7,
            install_script_id: 93,
            invoke_script_id: 94,
        }
    }

    /// A fake whose custom-field store keeps what is created, passed through `stored` (what NinjaOne
    /// keeps of a create request).
    fn field_store(stored: fn(Value) -> Value) -> Fake {
        let fields = std::sync::Mutex::new(std::collections::HashMap::new());
        Fake::start(move |method, path, body| {
            let mut fields = fields.lock().unwrap();
            match (method, path.strip_prefix("/v2/custom-fields/field-name/")) {
                ("GET", Some(name)) => match fields.get(name) {
                    Some(field) => (200, Value::clone(field)),
                    None => (404, json!({"resultCode": "not found"})),
                },
                ("POST", None) => {
                    let name = body["fieldName"].as_str().unwrap().to_owned();
                    let mut field = stored(body.clone());
                    field["name"] = json!(name);
                    fields.insert(name, field);
                    (201, json!({}))
                }
                _ => (404, json!({})),
            }
        })
    }

    #[test]
    fn ensure_fields_creates_every_missing_field_with_its_settings() {
        let fake = field_store(|request| request);
        let created = ensure_fields(&Api::with_token(&fake.url, "t")).unwrap();
        assert_eq!(created.len(), 6);
        let posts = fake.requests_to("POST", "/v2/custom-fields");
        assert_eq!(posts[0]["fieldName"], "posTunnelRelayKey");
        assert_eq!(posts[0]["scope"], "NODE_GLOBAL");
        assert_eq!(posts[0]["definitionScope"], json!(["NODE"]));
        assert_eq!(posts[0]["scriptPermission"], "READ_WRITE");
        assert_eq!(posts[0]["apiPermission"], "READ_ONLY");
        assert_eq!(posts[5]["fieldName"], "posTunnelSigner");
        assert_eq!(posts[5]["definitionScope"], json!(["ORGANIZATION"]));
        assert_eq!(posts[5]["scriptPermission"], "READ_ONLY");
        assert_eq!(posts[5]["apiPermission"], "READ_WRITE");
        // Run again: everything exists and matches, so nothing more is created.
        assert!(
            ensure_fields(&Api::with_token(&fake.url, "t"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn ensure_fields_refuses_a_field_ninjaone_stored_differently() {
        let fake = field_store(|mut request| {
            request["scriptPermission"] = json!("READ_WRITE");
            request
        });
        let error = ensure_fields(&Api::with_token(&fake.url, "t"))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("NinjaOne created custom field posTunnelRelay with script permission is READ_WRITE, expected READ_ONLY"),
            "{error}"
        );
    }

    #[test]
    fn ensure_fields_refuses_a_changed_setting_and_creates_nothing() {
        let fake = Fake::start(|_, path, _| match path {
            "/v2/custom-fields/field-name/posTunnelSigner" => (
                200,
                json!({"name": "posTunnelSigner", "definitionScope": ["ORGANIZATION"], "scriptPermission": "READ_WRITE", "apiPermission": "READ_WRITE"}),
            ),
            _ => (404, json!({})),
        });
        let error = ensure_fields(&Api::with_token(&fake.url, "t"))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("posTunnelSigner: script permission is READ_WRITE, expected READ_ONLY"),
            "{error}"
        );
        assert!(fake.requests_to("POST", "/v2/custom-fields").is_empty());
    }

    #[test]
    fn a_device_of_another_organization_in_the_list_is_not_a_pos() {
        // A server that lists the whole tenant whatever organization is asked for.
        let fake = Fake::start(|_, path, _| (200, devices(&path.replace("/organization/3", ""))));
        let names: Vec<String> = pos_devices(&Api::with_token(&fake.url, "t"), &ninja())
            .unwrap()
            .into_iter()
            .filter_map(|device| device.display_name)
            .collect();
        assert_eq!(names, ["POS 000 Test", "POS 001", "POS 900"]);
    }

    #[test]
    fn a_device_listing_shares_the_poses_sorted_by_name_for_tab_completion() {
        let fake = Fake::start(|_, path, _| {
            let mut all = devices(path);
            if !path.contains("&after=") {
                all.as_array_mut().unwrap().push(json!({"id": 7, "displayName": "Back Office POS", "organizationId": 3, "rolePolicyId": 7}));
            }
            (200, all)
        });
        let shared = Rc::new(Memory::default());
        shared.set_access_token("t");
        let api = Api::with_refresh_token(&fake.url, "c", "r", Some(shared.clone())).unwrap();
        pos_devices(&api, &ninja()).unwrap();
        let expected = [
            (7, "Back Office POS"),
            (1, "POS 000 Test"),
            (2, "POS 001"),
            (4, "POS 900"),
        ]
        .map(|(id, name)| (id, name.to_owned()));
        assert_eq!(*shared.poses.borrow(), expected);
    }

    #[test]
    fn fleet_fields_are_written_on_the_one_organization() {
        let fake = tenant();
        let values = json!({"posTunnelSigner": "ssh-ed25519 AAAA"});
        set_fleet_fields(&Api::with_token(&fake.url, "t"), &ninja(), &values).unwrap();
        assert_eq!(
            fake.requests_to("PATCH", "/v2/organization/3/custom-fields"),
            vec![values]
        );
        assert!(
            fake.requests_to("PATCH", "/v2/organization/5/custom-fields")
                .is_empty()
        );
    }

    #[test]
    fn another_organizations_device_on_the_pos_policy_is_never_listed_written_or_run() {
        let fake = tenant();
        let api = Api::with_token(&fake.url, "t");
        let names: Vec<String> = pos_devices(&api, &ninja())
            .unwrap()
            .into_iter()
            .filter_map(|device| device.display_name)
            .collect();
        assert_eq!(names, ["POS 000 Test", "POS 001", "POS 900"]);
        assert!(find_pos(&api, &ninja(), "POS 950").is_err());
        point_relay(
            &api,
            &ninja(),
            "relay.example.com:2222",
            "ssh-ed25519 AAAA",
            None,
        )
        .unwrap();
        // Neither the tenant-wide list nor anything of organization 5 is ever asked for.
        for (method, path) in [
            ("GET", "/v2/devices?pageSize=1000"),
            ("GET", "/v2/organization/5/devices?pageSize=1000"),
            ("PATCH", "/v2/organization/5/custom-fields"),
            ("POST", "/v2/device/9/script/run"),
        ] {
            assert!(fake.requests_to(method, path).is_empty(), "{method} {path}");
        }
    }

    #[test]
    fn find_pos_matches_one_pos_exactly() {
        let fake = Fake::start(|_, path, _| {
            let mut all = devices(path);
            if !path.contains("&after=") {
                let list = all.as_array_mut().unwrap();
                list.push(json!({"id": 5, "displayName": "POS 001", "organizationId": 3, "rolePolicyId": 7}));
                list.push(json!({"id": 6, "displayName": "pos 000 test", "organizationId": 3, "rolePolicyId": 8}));
            }
            (200, all)
        });
        let api = Api::with_token(&fake.url, "t");
        assert_eq!(find_pos(&api, &ninja(), "POS 000 Test").unwrap().id, 1);
        assert_eq!(find_pos(&api, &ninja(), "POS 900").unwrap().id, 4);
        let error = |name| find_pos(&api, &ninja(), name).unwrap_err().to_string();
        assert!(
            error("POS 001").contains("device IDs 2, 5"),
            "{}",
            error("POS 001")
        );
        assert!(
            error("pos 000 TEST").contains("differ only in case: POS 000 Test"),
            "{}",
            error("pos 000 TEST")
        );
        // Not a POS: another policy's device by that name doesn't count.
        assert!(
            error("Office PC").contains("no POS is named 'Office PC'"),
            "{}",
            error("Office PC")
        );
    }

    #[test]
    fn point_relay_writes_the_fields_and_installs_on_every_online_pos() {
        let fake = tenant();
        let pointed = point_relay(
            &Api::with_token(&fake.url, "t"),
            &ninja(),
            "relay.example.com:2222",
            "ssh-ed25519 AAAA",
            None,
        )
        .unwrap();
        assert_eq!(
            pointed,
            Pointed {
                ran: vec!["POS 000 Test".into(), "POS 900".into()],
                offline: vec!["POS 001".into()],
                failed: vec![],
            }
        );
        let fields = json!({"posTunnelRelay": "relay.example.com:2222", "posTunnelRelayServerKey": "ssh-ed25519 AAAA"});
        assert_eq!(
            fake.requests_to("PATCH", "/v2/organization/3/custom-fields"),
            vec![fields]
        );
        let run = json!({"type": "SCRIPT", "id": 93, "runAs": "system", "parameters": "-Force"});
        assert_eq!(
            fake.requests_to("POST", "/v2/device/1/script/run"),
            vec![run.clone()]
        );
        assert_eq!(
            fake.requests_to("POST", "/v2/device/4/script/run"),
            vec![run]
        );
        assert!(
            fake.requests_to("POST", "/v2/device/2/script/run")
                .is_empty()
        );
    }

    #[test]
    fn point_relay_goes_on_past_a_refused_script_run_and_reports_it() {
        let fake = tenant_refusing(Some("/v2/device/1/script/run"));
        let pointed = point_relay(
            &Api::with_token(&fake.url, "t"),
            &ninja(),
            "relay.example.com:2222",
            "ssh-ed25519 AAAA",
            None,
        )
        .unwrap();
        assert_eq!(pointed.ran, vec!["POS 900"]);
        assert_eq!(pointed.offline, vec!["POS 001"]);
        assert_eq!(pointed.failed.len(), 1, "{:?}", pointed.failed);
        assert!(
            pointed.failed[0]
                .starts_with("POS 000 Test: NinjaOne POST /v2/device/1/script/run failed (500)"),
            "{:?}",
            pointed.failed
        );
    }

    #[test]
    fn a_refused_fleet_field_write_installs_nothing() {
        let fake = tenant_refusing(Some("/v2/organization/3/custom-fields"));
        let error = point_relay(
            &Api::with_token(&fake.url, "t"),
            &ninja(),
            "relay.example.com:2222",
            "ssh-ed25519 AAAA",
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("/v2/organization/3/custom-fields failed (500)"),
            "{error}"
        );
        for id in [1, 4] {
            let path = format!("/v2/device/{id}/script/run");
            assert!(fake.requests_to("POST", &path).is_empty());
        }
    }

    #[test]
    fn point_relay_with_no_pos_in_the_organization_writes_nothing() {
        let fake = tenant();
        let ninja = NinjaOne {
            pos_policy_id: 99,
            ..ninja()
        };
        let error = point_relay(
            &Api::with_token(&fake.url, "t"),
            &ninja,
            "relay.example.com:2222",
            "ssh-ed25519 AAAA",
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("no device of organization 3 has the POS policy (id 99)"),
            "{error}"
        );
        assert!(
            fake.requests_to("PATCH", "/v2/organization/3/custom-fields")
                .is_empty()
        );
    }

    #[test]
    fn point_relay_with_a_device_installs_on_that_pos_alone() {
        let fake = tenant();
        let pointed = point_relay(
            &Api::with_token(&fake.url, "t"),
            &ninja(),
            "relay.example.com:2222",
            "ssh-ed25519 AAAA",
            Some("POS 000 Test"),
        )
        .unwrap();
        assert_eq!(pointed.ran, ["POS 000 Test"]);
        assert_eq!(fake.requests_to("POST", "/v2/device/1/script/run").len(), 1);
        assert!(
            fake.requests_to("POST", "/v2/device/4/script/run")
                .is_empty()
        );
    }

    #[test]
    fn point_relay_with_a_mistyped_or_offline_device_changes_nothing() {
        for (device, expected) in [
            ("POS 000 test", "differ only in case"),
            ("POS 001", "POS 001 is offline"),
        ] {
            let fake = tenant();
            let error = point_relay(
                &Api::with_token(&fake.url, "t"),
                &ninja(),
                "relay.example.com:2222",
                "ssh-ed25519 AAAA",
                Some(device),
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains(expected), "{error}");
            assert!(
                fake.requests_to("PATCH", "/v2/organization/3/custom-fields")
                    .is_empty(),
                "{device}"
            );
            for id in 1..=4 {
                let path = format!("/v2/device/{id}/script/run");
                assert!(fake.requests_to("POST", &path).is_empty(), "{device}");
            }
        }
    }
}

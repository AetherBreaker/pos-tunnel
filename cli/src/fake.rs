//! Stand-ins for tests: a fake NinjaOne (and GitHub raw file host) that answers each request from a
//! handler and records it, a tenant of POSes that run the library scripts, and a relay.

use std::cell::{Cell, RefCell};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use anyhow::{Result, bail};
use serde_json::{Value, json};

use crate::config::{NinjaOne, Relay as RelayConfig};
use crate::ninja::Api;
use crate::relay::{Lease, Relay, Starting};
use crate::session::{Context, Timing};
use crate::workstation::Workstation;

type Handler = dyn Fn(&str, &str, &Value) -> (u16, Value) + Send + 'static;

pub struct Fake {
    pub url: String,
    requests: Arc<Mutex<Vec<(String, String, Value)>>>,
}

impl Fake {
    /// Serves until the test process ends; `handler` gets method, path with query, and the JSON body
    /// (`Null` when there is none) and returns the status and the reply: JSON, or a string for a
    /// plain-text body.
    pub fn start(handler: impl Fn(&str, &str, &Value) -> (u16, Value) + Send + 'static) -> Fake {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&requests);
        let handler: Box<Handler> = Box::new(handler);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    continue;
                }
                let mut words = line.split_whitespace();
                let (method, path) = (
                    words.next().unwrap_or("").to_owned(),
                    words.next().unwrap_or("").to_owned(),
                );
                let mut length = 0;
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).unwrap();
                    if header.trim().is_empty() {
                        break;
                    }
                    if let Some((name, value)) = header.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    {
                        length = value.trim().parse().unwrap();
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let body = serde_json::from_slice(&body).unwrap_or(Value::Null);
                let (status, reply) = handler(&method, &path, &body);
                log.lock().unwrap().push((method, path, body));
                let text = match &reply {
                    Value::Null => String::new(),
                    // A string is a plain-text body, as GitHub's raw file host sends.
                    Value::String(text) => text.clone(),
                    _ => reply.to_string(),
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                    text.len()
                );
            }
        });
        Fake { url, requests }
    }

    /// The bodies of the requests made with `method` to `path`, in order.
    pub fn requests_to(&self, method: &str, path: &str) -> Vec<Value> {
        let requests = self.requests.lock().unwrap();
        requests
            .iter()
            .filter(|(m, p, _)| m == method && p == path)
            .map(|(_, _, body)| body.clone())
            .collect()
    }
}

/// The test POS of `pos_tenant`: device 1, `POS 000 Test`.
#[derive(Clone)]
pub struct Pos {
    pub offline: bool,
    /// The `posTunnelRelayKey` field as the POS published it.
    pub relay_key: String,
    pub host_key: String,
    /// The `posTunnelVersion` field.
    pub version: &'static str,
    /// An action (`Open`, `Close`, `Touch`, `Rekey`, `Install`) this POS fails.
    pub fail: Option<&'static str>,
    /// It never reports: its runs stay requested.
    pub silent: bool,
}

impl Default for Pos {
    fn default() -> Pos {
        Pos {
            offline: false,
            relay_key:
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJcqClAjDTPmj8pmPsPI3fxOHxZTDZM3whLav0QPDVMB"
                    .into(),
            host_key:
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBxRa3sySInLyRMMVSWz76+abOp7xOibpSn1v7vw1k4x"
                    .into(),
            version: "4",
            fail: None,
            silent: false,
        }
    }
}

/// A tenant whose organization 3 holds `pos` as device 1, `POS 002` (2, online) and `POS 003` (3,
/// offline), and which records a script run as NinjaOne does: three activities sharing a `seriesUid`,
/// the last with the result and the script's output. Returns `pos` for the test's own assertions.
pub fn pos_tenant(pos: Pos) -> (Fake, Pos) {
    let activities = Mutex::new(Vec::<Value>::new());
    let served = pos.clone();
    let fake = Fake::start(move |method, path, body| {
        let (route, query) = path.split_once('?').unwrap_or((path, ""));
        let param = |name: &str| {
            query
                .split('&')
                .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
        };
        let parts: Vec<&str> = route.trim_start_matches("/v2/").split('/').collect();
        let mut activities = activities.lock().unwrap();
        match (method, parts.as_slice()) {
            ("GET", ["organization", "3", "devices"]) => {
                let after: i64 = param("after").map_or(0, |id| id.parse().unwrap());
                let mut devices = json!([
                    {"id": 1, "displayName": "POS 000 Test", "organizationId": 3, "rolePolicyId": 7, "offline": served.offline},
                    {"id": 2, "displayName": "POS 002", "organizationId": 3, "rolePolicyId": 7, "offline": false},
                    {"id": 3, "displayName": "POS 003", "organizationId": 3, "rolePolicyId": 7, "offline": true},
                ]);
                devices
                    .as_array_mut()
                    .unwrap()
                    .retain(|device| device["id"].as_i64() > Some(after));
                (200, devices)
            }
            ("GET", ["device", "1", "custom-fields"]) => (
                200,
                json!({"posTunnelRelayKey": served.relay_key, "posTunnelHostKey": served.host_key,
                    "posTunnelVersion": served.version, "rustdeskAudit": "x"}),
            ),
            ("GET", ["device", _, "custom-fields"]) => {
                let pos = Pos::default();
                (
                    200,
                    json!({"posTunnelRelayKey": pos.relay_key, "posTunnelHostKey": pos.host_key, "posTunnelVersion": "4"}),
                )
            }
            ("GET", ["device", id, "activities"]) => {
                let device: i64 = id.parse().unwrap();
                let newer: i64 = param("newerThan").map_or(0, |id| id.parse().unwrap());
                let of_device: Vec<&Value> = activities
                    .iter()
                    .filter(|a| a["deviceId"] == device)
                    .collect();
                // Newest first, as NinjaOne lists them.
                let listed: Vec<&Value> = of_device
                    .iter()
                    .rev()
                    .filter(|a| match param("seriesUid") {
                        Some(series) => a["seriesUid"] == series,
                        None => a["id"].as_i64() > Some(newer),
                    })
                    .copied()
                    .collect();
                let last = of_device.last().map(|a| a["id"].clone());
                (
                    200,
                    json!({"activities": listed, "lastNodeActivityId": last}),
                )
            }
            ("POST", ["device", id, "script", "run"]) => {
                let device: i64 = id.parse().unwrap();
                let name = if body["id"] == 93 {
                    "Install-PosTunnel"
                } else {
                    "Invoke-PosTunnel"
                };
                let words: Vec<&str> = body["parameters"].as_str().unwrap().split(' ').collect();
                let action = match words[..] {
                    ["-Action", action, ..] => action,
                    _ => "Install",
                };
                let failed = device == 1 && served.fail == Some(action);
                let output = match (failed, action) {
                    (true, _) => format!("FAILED\t{action}\tboom"),
                    (_, "Close") => {
                        "CHANGED\ttunnel\tstopped\r\nOK\tclose\tsession ended".to_owned()
                    }
                    (_, "Install") => "OK\tsignature\r\nOK\tcurrent\tversion 4".to_owned(),
                    _ => format!("CHANGED\t{action}"),
                };
                let series = format!("series-{}", activities.len());
                let mut record = |kind: &str, status: &str, extra: Value| {
                    let mut activity = json!({"id": activities.len() + 1, "deviceId": device, "activityType": kind,
                        "statusCode": status, "sourceName": name, "seriesUid": series});
                    let fields = activity.as_object_mut().unwrap();
                    fields.extend(extra.as_object().unwrap().clone());
                    activities.push(activity);
                };
                record("ACTIONSET", "START_REQUESTED", json!({}));
                if !(device == 1 && served.silent) {
                    record("ACTION", "STARTED", json!({}));
                    record(
                        "ACTION",
                        "COMPLETED",
                        json!({"activityResult": if failed { "FAILURE" } else { "SUCCESS" },
                            "data": {"message": {"params": {"output_message": output}}}}),
                    );
                }
                (204, Value::Null)
            }
            _ => (404, json!({})),
        }
    });
    (fake, pos)
}

/// The relay's leases in memory, and the logins through it. Leases behave as the daemon's do: `open`
/// refuses a port that has one, `renew` and `close` one that has none.
pub struct FakeRelay {
    /// Who opens a lease through this relay handle.
    operator: String,
    pub leases: RefCell<Vec<Lease>>,
    calls: RefCell<Vec<String>>,
    pub logins: RefCell<Vec<String>>,
    /// What a login through an alias fails with.
    pub login_error: RefCell<Option<String>>,
    /// Whether a lease's tunnel shows as up.
    pub listening: Cell<bool>,
    /// The daemon stops answering after this many commands.
    pub starting_after: Cell<Option<usize>>,
    /// How many `status` replies still list a closed lease, as the daemon does until its next pass.
    pub linger: Cell<u32>,
    closed: RefCell<Vec<(Lease, u32)>>,
    opened: Cell<u32>,
}

impl FakeRelay {
    pub fn new(operator: &str) -> FakeRelay {
        FakeRelay {
            operator: operator.to_owned(),
            leases: RefCell::default(),
            calls: RefCell::default(),
            logins: RefCell::default(),
            login_error: RefCell::default(),
            listening: Cell::new(true),
            starting_after: Cell::new(None),
            linger: Cell::new(0),
            closed: RefCell::default(),
            opened: Cell::new(0),
        }
    }

    /// The commands received, in order.
    pub fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }

    /// How many of the commands received were `command`.
    pub fn count(&self, command: &str) -> usize {
        let calls = self.calls.borrow();
        calls
            .iter()
            .filter(|call| call.split(' ').next() == Some(command))
            .count()
    }

    /// A lease `operator` opened from another workstation: no command is recorded for it.
    pub fn open_as(&self, operator: &str, device_id: i64) {
        self.opened.set(self.opened.get() + 1);
        self.leases.borrow_mut().push(Lease {
            port: 20000 + device_id as u16,
            device_id,
            operator: operator.to_owned(),
            started: format!("opened-{}", self.opened.get()),
            idle_remaining: 600,
            absolute_remaining: 259_200,
            listening: false,
        });
    }
}

impl Relay for FakeRelay {
    fn tunnelctl(&self, command: &str) -> Result<String> {
        self.calls.borrow_mut().push(command.to_owned());
        if self
            .starting_after
            .get()
            .is_some_and(|answered| self.calls.borrow().len() > answered)
        {
            return Err(Starting.into());
        }
        let words: Vec<&str> = command.split(' ').collect();
        let port: u16 = words.get(1).map_or(0, |port| port.parse().unwrap());
        let position = self.leases.borrow().iter().position(|l| l.port == port);
        match (words[0], position) {
            ("status", _) => {
                let mut closed = self.closed.borrow_mut();
                let mut listed = self.leases.borrow().clone();
                listed.extend(closed.iter().map(|(lease, _)| lease.clone()));
                closed.retain_mut(|(_, left)| {
                    *left -= 1;
                    *left > 0
                });
                for lease in &mut listed {
                    lease.listening = self.listening.get();
                }
                listed.sort_by_key(|lease| lease.port);
                Ok(serde_json::to_string(&listed)?)
            }
            ("open", None) if !self.closed.borrow().iter().any(|(l, _)| l.port == port) => {
                self.open_as(&self.operator, words[2].parse()?);
                let mut leases = self.leases.borrow_mut();
                let lease = leases.last_mut().unwrap();
                lease.idle_remaining = words[3].parse()?;
                Ok(serde_json::to_string(lease)?)
            }
            ("open", _) => bail!("the relay refused: a lease for port {port} exists"),
            ("renew", Some(at)) => {
                let mut leases = self.leases.borrow_mut();
                leases[at].idle_remaining = 43200;
                Ok(serde_json::to_string(&leases[at])?)
            }
            ("close", Some(at)) => {
                // As the daemon: out of time at once, listed until its next pass.
                let mut lease = self.leases.borrow_mut().remove(at);
                lease.idle_remaining = 0;
                let reply = serde_json::to_string(&lease)?;
                if self.linger.get() > 0 {
                    self.closed.borrow_mut().push((lease, self.linger.get()));
                }
                Ok(reply)
            }
            _ => bail!("the relay refused: no lease for port {port}"),
        }
    }

    fn login(&self, alias: &str) -> Result<()> {
        self.logins.borrow_mut().push(alias.to_owned());
        match &*self.login_error.borrow() {
            Some(error) => bail!("the login through {alias} failed: {error}"),
            None => Ok(()),
        }
    }
}

/// A workstation in a temp dir of its own, the dir's name holding a space as a profile path may.
pub fn workstation(test: &str) -> Workstation {
    let dir = std::env::temp_dir().join(format!("posctl {test} {}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    Workstation {
        sessions: dir.join("config").join("sessions"),
        ssh_dir: dir.join("ssh"),
        ssh: "ssh".into(),
        operator_key: dir.join("operator_key"),
        relay: RelayConfig {
            host: "relay.example.com".into(),
            port: 2222,
            public_key: "ssh-ed25519 AAAARELAY".into(),
        },
    }
}

/// The session commands' context against `pos_tenant` and a `FakeRelay`, with waits short enough for a
/// test that runs one out.
pub fn context<'a>(
    api: &'a Api,
    relay: &'a FakeRelay,
    workstation: &'a Workstation,
) -> Context<'a> {
    static NINJA: LazyLock<NinjaOne> = LazyLock::new(|| NinjaOne {
        base_url: String::new(),
        client_id: String::new(),
        organization_id: 3,
        pos_policy_id: 7,
        install_script_id: 93,
        invoke_script_id: 94,
    });
    let short = Duration::from_millis(300);
    Context {
        api,
        ninja: &NINJA,
        relay,
        workstation,
        timing: Timing {
            poll: Duration::from_millis(5),
            open: short,
            script: short,
            install: short,
            released: short,
        },
    }
}

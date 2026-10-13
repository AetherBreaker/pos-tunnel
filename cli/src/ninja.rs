//! The NinjaOne API (design section 8): the browser sign-in, the stored refresh token, and the calls
//! both binaries make.
//!
//! Running a script needs a user's token (a client-credentials token gets `user_context_required`), so
//! `login` signs in with the authorization-code grant through the tenant's Native app: PKCE (RFC 7636),
//! no client secret, a loopback redirect on a port the OS picks (RFC 8252). Refresh tokens don't rotate,
//! so the one `login` stores lasts; each command trades it for an hour's access token. A refresh ends
//! the access tokens issued before it, so a call answered 401 signs in again (`Api::call`).

use std::cell::RefCell;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::rc::Rc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ssh_key::rand_core::{OsRng, RngCore};
use ureq::Agent;

const SCOPE: &str = "monitoring management offline_access";
/// The library scripts' names (design section 7.1): `posctl-admin init` finds them by name, and a run's
/// activities carry it.
pub const INSTALL_SCRIPT: &str = "Install-PosTunnel";
pub const INVOKE_SCRIPT: &str = "Invoke-PosTunnel";
const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);

/// Signs in through the browser and stores the refresh token.
pub fn login(base_url: &str, client_id: &str) -> Result<()> {
    let verifier = random_token(48);
    let state = random_token(16);
    let listener =
        TcpListener::bind(("127.0.0.1", 0)).context("opening the sign-in callback port")?;
    let redirect = format!("http://127.0.0.1:{}", listener.local_addr()?.port());
    let url = url::Url::parse_with_params(
        &format!("{base_url}/ws/oauth/authorize"),
        [
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", &redirect),
            ("scope", SCOPE),
            ("state", &state),
            ("code_challenge", &pkce_challenge(&verifier)),
            ("code_challenge_method", "S256"),
        ],
    )?;
    eprintln!("Sign in to NinjaOne in your browser. If it didn't open, open this link:\n{url}");
    let _ = webbrowser::open(url.as_str());

    let code = await_code(&listener, &state)?;
    let tokens: Value = token_request(
        base_url,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("code", &code),
            ("redirect_uri", &redirect),
            ("code_verifier", &verifier),
        ],
    )?;
    let refresh = tokens["refresh_token"]
        .as_str()
        .context("NinjaOne returned no refresh token (scope offline_access)")?;
    token_store::save(refresh)
}

/// RFC 7636's S256: unpadded base64url of the verifier's SHA-256.
fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// Waits for the browser's redirect and answers it. Other requests (a favicon, a browser's speculative
/// connection that never sends) are answered or dropped, and waiting goes on.
fn await_code(listener: &TcpListener, state: &str) -> Result<String> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + LOGIN_TIMEOUT;
    while Instant::now() < deadline {
        let mut stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut line = String::new();
        if BufReader::new(&stream).read_line(&mut line).is_err() {
            continue;
        }
        match parse_callback(&line, state) {
            Callback::Code(code) => {
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nposctl is signed in. You can close this tab.\n");
                return Ok(code);
            }
            Callback::Denied(reason) => {
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nSign-in failed; see posctl.\n");
                bail!("NinjaOne sign-in failed: {reason}");
            }
            Callback::Other => {
                let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
            }
        }
    }
    bail!("no sign-in within {} minutes", LOGIN_TIMEOUT.as_secs() / 60)
}

#[derive(Debug, PartialEq)]
enum Callback {
    Code(String),
    Denied(String),
    Other,
}

/// The request line `GET /?code=..&state=.. HTTP/1.1`. A code with the wrong state is refused: another
/// page on this machine could otherwise post a code of its choosing to the open port.
fn parse_callback(request_line: &str, state: &str) -> Callback {
    let Some(target) = request_line
        .strip_prefix("GET ")
        .and_then(|rest| rest.split(' ').next())
    else {
        return Callback::Other;
    };
    let Ok(url) = url::Url::parse(&format!("http://127.0.0.1{target}")) else {
        return Callback::Other;
    };
    let get = |name: &str| {
        url.query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    };
    if let Some(error) = get("error") {
        return Callback::Denied(get("error_description").unwrap_or(error));
    }
    match (get("code"), get("state")) {
        (Some(code), Some(got)) if got == state => Callback::Code(code),
        (Some(_), _) => Callback::Denied("the callback's state didn't match this sign-in".into()),
        _ => Callback::Other,
    }
}

pub(crate) fn agent() -> Agent {
    Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(60)))
        .build()
        .into()
}

/// NinjaOne's own "no" to a token request, as against a request that never reached it.
#[derive(Debug)]
struct Refused {
    status: u16,
    body: String,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Refused { status, body } = self;
        write!(
            f,
            "NinjaOne refused the token request ({status}): {}",
            snippet(body)
        )
    }
}

impl std::error::Error for Refused {}

fn token_request<T: DeserializeOwned>(base_url: &str, form: &[(&str, &str)]) -> Result<T> {
    let mut response = agent()
        .post(format!("{base_url}/ws/oauth/token"))
        .send_form(form.iter().copied())?;
    let status = response.status().as_u16();
    let body = response.body_mut().read_to_string()?;
    if status != 200 {
        return Err(Refused { status, body }.into());
    }
    Ok(serde_json::from_str(&body)?)
}

/// Trades the refresh token for an access token.
fn sign_in(base_url: &str, client_id: &str, refresh: &str) -> Result<String> {
    let tokens: Value = token_request(
        base_url,
        &[
            ("grant_type", "refresh_token"),
            ("client_id", client_id),
            ("refresh_token", refresh),
        ],
    )
    .map_err(|e| {
        // Signing in again cures a sign-in NinjaOne no longer accepts: not an unreachable NinjaOne,
        // and not a refusal for another reason (too many requests, an outage).
        let stale = e
            .downcast_ref::<Refused>()
            .is_some_and(|refused| matches!(refused.status, 400 | 401));
        if stale {
            e.context("refreshing the NinjaOne sign-in failed; run `posctl login`")
        } else if e.chain().any(|cause| cause.is::<ureq::Error>()) {
            e.context(format!("couldn't reach NinjaOne at {base_url}"))
        } else {
            e.context("refreshing the NinjaOne sign-in failed")
        }
    })?;
    tokens["access_token"]
        .as_str()
        .map(str::to_owned)
        .context("NinjaOne returned no access token")
}

fn snippet(body: &str) -> String {
    body.chars().take(300).collect()
}

/// What the commands of one identity share, between runs and with each other while they overlap (design
/// section 8): the access token, since NinjaOne ends the one before at every sign-in, and the NinjaOne
/// user they run as, which the API never states and a command learns from its own script run.
pub trait Shared {
    fn access_token(&self) -> Option<String>;
    fn set_access_token(&self, token: &str);
    fn user(&self) -> Option<i64>;
    fn set_user(&self, user: i64);
}

/// The sign-in as stored: Windows Credential Manager on Windows (design section 3), files elsewhere and
/// wherever `POSCTL_CONFIG_HOME` is set (mode 0600 on Unix), so a second identity has its own sign-in and a
/// test never reads the real one (design section 8).
pub mod token_store {
    use anyhow::{Context, Result};

    /// A stored value: its Credential Manager entry and its file beside the config.
    type Slot = (&'static str, &'static str);
    const REFRESH: Slot = ("ninjaone-refresh-token", "refresh_token");
    const ACCESS: Slot = ("ninjaone-access-token", "access_token");
    const USER: Slot = ("ninjaone-user", "ninja_user");

    #[cfg(windows)]
    fn entry(key: &str) -> Result<keyring_core::Entry> {
        static STORE: std::sync::Once = std::sync::Once::new();
        let mut failed = None;
        STORE.call_once(|| match windows_native_keyring_store::Store::new() {
            Ok(store) => keyring_core::set_default_store(store),
            Err(e) => failed = Some(e),
        });
        if let Some(e) = failed {
            return Err(e.into());
        }
        Ok(keyring_core::Entry::new("posctl", key)?)
    }

    fn path(file: &str) -> Result<std::path::PathBuf> {
        Ok(crate::config::config_home()?.join("posctl").join(file))
    }

    #[cfg_attr(not(windows), allow(unused_variables))]
    fn write((key, file): Slot, value: &str) -> Result<()> {
        #[cfg(windows)]
        if std::env::var_os("POSCTL_CONFIG_HOME").is_none() {
            return Ok(entry(key)?.set_password(value)?);
        }
        crate::config::write_private(&path(file)?, value.as_bytes())
    }

    #[cfg_attr(not(windows), allow(unused_variables))]
    fn read((key, file): Slot) -> Result<String> {
        #[cfg(windows)]
        if std::env::var_os("POSCTL_CONFIG_HOME").is_none() {
            return Ok(entry(key)?.get_password()?);
        }
        Ok(std::fs::read_to_string(path(file)?)?.trim().to_owned())
    }

    #[cfg_attr(not(windows), allow(unused_variables))]
    fn clear((key, file): Slot) -> Result<()> {
        #[cfg(windows)]
        if std::env::var_os("POSCTL_CONFIG_HOME").is_none() {
            return Ok(entry(key)?.delete_credential()?);
        }
        Ok(std::fs::remove_file(path(file)?)?)
    }

    /// Stores a new sign-in's refresh token, and forgets what was shared under the one before it,
    /// which may have been another user's.
    pub fn save(token: &str) -> Result<()> {
        write(REFRESH, token)?;
        let _ = clear(ACCESS);
        let _ = clear(USER);
        Ok(())
    }

    pub fn load() -> Result<String> {
        read(REFRESH).context("not signed in to NinjaOne: run `posctl login`")
    }

    /// `Shared`, kept where the refresh token is. A value that can't be read or written is one not
    /// shared: the command then signs in for itself.
    pub struct Stored;

    impl super::Shared for Stored {
        fn access_token(&self) -> Option<String> {
            read(ACCESS).ok()
        }

        fn set_access_token(&self, token: &str) {
            let _ = write(ACCESS, token);
        }

        fn user(&self) -> Option<i64> {
            read(USER).ok()?.parse().ok()
        }

        fn set_user(&self, user: i64) {
            let _ = write(USER, &user.to_string());
        }
    }
}

/// A signed-in API client: the stored refresh token traded for an access token.
pub struct Api {
    agent: Agent,
    base_url: String,
    access_token: RefCell<String>,
    /// The client ID and refresh token `call` signs in again with; none for a test's fixed token.
    refresh: Option<(String, String)>,
    /// None in tests that share nothing.
    shared: Option<Rc<dyn Shared>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub id: i64,
    pub display_name: Option<String>,
    pub organization_id: i64,
    #[serde(default)]
    pub offline: bool,
    /// A per-device override; absent on every device in the tenant so far (design section 11).
    pub policy_id: Option<i64>,
    pub role_policy_id: Option<i64>,
}

impl Device {
    pub fn effective_policy(&self) -> Option<i64> {
        self.policy_id.or(self.role_policy_id)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Named {
    pub id: i64,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldDefinition {
    pub name: String,
    #[serde(default)]
    pub definition_scope: Vec<String>,
    pub script_permission: Option<String>,
    pub api_permission: Option<String>,
}

/// A requested script run, followed through the device's activity list (design section 8, script
/// results).
#[derive(Debug)]
pub struct ScriptRun {
    pub device: i64,
    name: &'static str,
    /// The device's newest activity before the request.
    after: i64,
    /// The run's `seriesUid`, once its `START_REQUESTED` activity has shown up.
    series: Option<String>,
}

/// The device fields a POS publishes (design section 7.1): `Publish-DeviceFields` reports a line for
/// each, at the end of an install's report and of a rekey's.
const DEVICE_FIELDS: [&str; 3] = ["posTunnelRelayKey", "posTunnelHostKey", "posTunnelVersion"];

/// What became of the fields a script reported writing (`Api::await_published`).
#[derive(Debug, PartialEq)]
pub enum Published {
    /// NinjaOne shows every value written, or nothing was.
    Shown,
    TimedOut,
    /// The report lacks the line of one of the fields: NinjaOne cut it short, and what was written
    /// isn't known.
    CutShort,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScriptResult {
    /// NinjaOne's verdict, and no `FAILED` line in the output.
    pub success: bool,
    /// What the script printed. The POS's words: untrusted, shown as its report and otherwise read
    /// only for which field values to wait for (`published`).
    pub output: String,
}

impl ScriptResult {
    /// A step put off to a later run (a session is open, a restart is pending): design section 7.1.
    pub fn deferred(&self) -> bool {
        self.output
            .lines()
            .any(|line| line.starts_with("DEFERRED\t"))
    }

    /// The device fields the script says it wrote, each with its value: the
    /// `CHANGED<TAB>field <name><TAB><value>` lines of `Publish-DeviceFields`.
    pub fn published(&self) -> Vec<(&str, &str)> {
        self.output
            .lines()
            .filter_map(|line| {
                let (step, value) = line.strip_prefix("CHANGED\t")?.split_once('\t')?;
                Some((step.strip_prefix("field ")?, value))
            })
            .collect()
    }
}

impl Api {
    pub fn connect(base_url: &str, client_id: &str) -> Result<Api> {
        let shared: Rc<dyn Shared> = Rc::new(token_store::Stored);
        Api::with_refresh_token(base_url, client_id, &token_store::load()?, Some(shared))
    }

    /// `connect` without the token store, so a test never touches a real sign-in. Signs in only if
    /// `shared` holds no access token: one already there is another command's, and still good or
    /// found out at the first call.
    pub fn with_refresh_token(
        base_url: &str,
        client_id: &str,
        refresh: &str,
        shared: Option<Rc<dyn Shared>>,
    ) -> Result<Api> {
        let access_token = match shared.as_ref().and_then(|shared| shared.access_token()) {
            Some(token) => token,
            None => {
                let token = sign_in(base_url, client_id, refresh)?;
                if let Some(shared) = &shared {
                    shared.set_access_token(&token);
                }
                token
            }
        };
        Ok(Api {
            agent: agent(),
            base_url: base_url.to_owned(),
            access_token: RefCell::new(access_token),
            refresh: Some((client_id.to_owned(), refresh.to_owned())),
            shared,
        })
    }

    /// For tests: a client of a fake server with a fixed token.
    pub fn with_token(base_url: &str, access_token: &str) -> Api {
        Api {
            agent: agent(),
            base_url: base_url.to_owned(),
            access_token: RefCell::new(access_token.to_owned()),
            refresh: None,
            shared: None,
        }
    }

    /// One call; the status and body, whatever the status. NinjaOne ends an access token at the next
    /// sign-in (design section 8), so the token is shared, and a 401 means it ran out or another
    /// command signed in: this one takes that command's token, or signs in and shares its own, and
    /// repeats the call. Twice at most, as a third command may sign in in between.
    fn call(&self, method: &str, path: &str, body: Option<&Value>) -> Result<(u16, String)> {
        let url = format!("{}{path}", self.base_url);
        let mut sign_ins_left = 2;
        loop {
            let auth = format!("Bearer {}", self.access_token.borrow());
            let mut response = match (method, body) {
                ("GET", _) => self.agent.get(&url).header("Authorization", &auth).call()?,
                ("POST", Some(body)) => self
                    .agent
                    .post(&url)
                    .header("Authorization", &auth)
                    .send_json(body)?,
                ("PATCH", Some(body)) => self
                    .agent
                    .patch(&url)
                    .header("Authorization", &auth)
                    .send_json(body)?,
                _ => bail!("unsupported call {method} {path}"),
            };
            let status = response.status().as_u16();
            let text = response.body_mut().read_to_string()?;
            match &self.refresh {
                Some((client_id, refresh)) if status == 401 && sign_ins_left > 0 => {
                    sign_ins_left -= 1;
                    let refused = self.access_token.borrow().clone();
                    let theirs = self
                        .shared
                        .as_ref()
                        .and_then(|shared| shared.access_token())
                        .filter(|token| *token != refused);
                    let token = match theirs {
                        Some(token) => token,
                        None => {
                            let token = sign_in(&self.base_url, client_id, refresh)?;
                            if let Some(shared) = &self.shared {
                                shared.set_access_token(&token);
                            }
                            token
                        }
                    };
                    *self.access_token.borrow_mut() = token;
                }
                _ => return Ok((status, text)),
            }
        }
    }

    fn checked(&self, method: &str, path: &str, body: Option<&Value>) -> Result<String> {
        let (status, text) = self.call(method, path, body)?;
        if !(200..300).contains(&status) {
            bail!(
                "NinjaOne {method} {path} failed ({status}): {}",
                snippet(&text)
            );
        }
        Ok(text)
    }

    pub fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let text = self.checked("GET", path, None)?;
        serde_json::from_str(&text)
            .with_context(|| format!("NinjaOne GET {path}: unexpected reply: {}", snippet(&text)))
    }

    /// Every device of one organization, a page at a time (`after` is the last device ID of the
    /// previous page). The tenant-wide list is never asked for (design section 8).
    pub fn devices(&self, organization: i64) -> Result<Vec<Device>> {
        let mut devices: Vec<Device> = Vec::new();
        loop {
            let last = devices.last().map(|device| device.id);
            let after = last.map(|id| format!("&after={id}")).unwrap_or_default();
            let page: Vec<Device> = self.get(&format!(
                "/v2/organization/{organization}/devices?pageSize=1000{after}"
            ))?;
            // Until an empty page, not a short one: NinjaOne may cap a page below the size asked for.
            let Some(end) = page.last().map(|device| device.id) else {
                return Ok(devices);
            };
            // A server that ignored `after` would be read forever.
            if last.is_some_and(|last| end <= last) {
                bail!(
                    "NinjaOne's device list for organization {organization} didn't advance past device {end}"
                );
            }
            devices.extend(page);
        }
    }

    pub fn policies(&self) -> Result<Vec<Named>> {
        self.get("/v2/policies")
    }

    pub fn scripts(&self) -> Result<Vec<Named>> {
        self.get("/v2/automation/scripts")
    }

    /// `None` when NinjaOne has no field by that name.
    pub fn field_definition(&self, name: &str) -> Result<Option<FieldDefinition>> {
        let path = format!("/v2/custom-fields/field-name/{name}");
        match self.call("GET", &path, None)? {
            (404, _) => Ok(None),
            (200, text) => Ok(Some(serde_json::from_str(&text)?)),
            (status, text) => bail!("NinjaOne GET {path} failed ({status}): {}", snippet(&text)),
        }
    }

    pub fn create_field(&self, definition: &Value) -> Result<()> {
        self.checked("POST", "/v2/custom-fields", Some(definition))
            .map(drop)
    }

    pub fn set_organization_fields(&self, organization: i64, values: &Value) -> Result<()> {
        self.checked(
            "PATCH",
            &format!("/v2/organization/{organization}/custom-fields"),
            Some(values),
        )
        .map(drop)
    }

    /// Runs a library script as SYSTEM; `parameters` is the string NinjaOne appends to the command line.
    pub fn run_script(&self, device: i64, script: i64, parameters: &str) -> Result<()> {
        let body =
            json!({"type": "SCRIPT", "id": script, "runAs": "system", "parameters": parameters});
        self.checked(
            "POST",
            &format!("/v2/device/{device}/script/run"),
            Some(&body),
        )
        .map(drop)
    }

    /// The device's custom fields, name to value; a field never set is absent.
    pub fn custom_fields(&self, device: i64) -> Result<serde_json::Map<String, Value>> {
        self.get(&format!("/v2/device/{device}/custom-fields"))
    }

    /// Waits until NinjaOne shows every field value `result` says its script wrote, up to `deadline`.
    /// The API shows a POS's field writes well after its run's result (39 s on the test POS, design
    /// section 11), and `connect` reads a POS's keys and version there. A deadline rather than a
    /// timeout, so that the waits for many POSes share one. `result` is an install's or a rekey's:
    /// one that doesn't name every device field was cut short by NinjaOne, and isn't waited on.
    pub fn await_published(
        &self,
        device: i64,
        result: &ScriptResult,
        deadline: Instant,
        poll: Duration,
    ) -> Published {
        let names = |field: &str| {
            result.output.lines().any(|line| {
                line.strip_prefix("OK\tfield ") == Some(field)
                    || line
                        .strip_prefix("CHANGED\tfield ")
                        .is_some_and(|rest| rest.split('\t').next() == Some(field))
            })
        };
        if !DEVICE_FIELDS.into_iter().all(names) {
            return Published::CutShort;
        }
        let written = result.published();
        loop {
            // A failed read is one more "not yet"; the deadline bounds it.
            let shown = written.is_empty()
                || self.custom_fields(device).is_ok_and(|fields| {
                    written.iter().all(|(name, value)| {
                        // The version may come back a number, which `connect` allows for too.
                        fields.get(*name).is_some_and(|shown| {
                            shown.as_str() == Some(*value)
                                || shown.as_u64().is_some_and(|n| value.parse() == Ok(n))
                        })
                    })
                });
            if shown {
                return Published::Shown;
            }
            if Instant::now() >= deadline {
                return Published::TimedOut;
            }
            std::thread::sleep(poll);
        }
    }

    /// `run_script`, returning what `poll_script` follows the run by: `script/run` itself returns
    /// nothing, so the device's newest activity is noted first and the run is the first request after it.
    pub fn start_script(
        &self,
        device: i64,
        script: i64,
        name: &'static str,
        parameters: &str,
    ) -> Result<ScriptRun> {
        let before: Value = self.get(&format!("/v2/device/{device}/activities?pageSize=10"))?;
        // Without it, the newest activity listed: starting from 0 would take an earlier run, already
        // complete, for this one.
        let after = before["lastNodeActivityId"]
            .as_i64()
            .or(before["activities"][0]["id"].as_i64())
            .unwrap_or(0);
        self.run_script(device, script, parameters)?;
        Ok(ScriptRun {
            device,
            name,
            after,
            series: None,
        })
    }

    /// One look at a run: its result once the POS has finished, `None` until then.
    pub fn poll_script(&self, run: &mut ScriptRun) -> Result<Option<ScriptResult>> {
        let device = run.device;
        if run.series.is_none() {
            let reply: Value = self.get(&format!(
                "/v2/device/{device}/activities?newerThan={}&pageSize=200",
                run.after
            ))?;
            // Oldest first; the reply lists newest first.
            let requests: Vec<&Value> = reply["activities"]
                .as_array()
                .into_iter()
                .flatten()
                .rev()
                .filter(|a| a["statusCode"] == "START_REQUESTED" && a["sourceName"] == run.name)
                .collect();
            // This run is the oldest request since `after`: by this user, where one is. Another
            // operator's request for the same script, landing between this run's two calls, would
            // otherwise be followed in its place. The API never says who is signed in, so the user is
            // learned from a request that stands alone, which also puts a wrong one right.
            let user = self.shared.as_ref().and_then(|shared| shared.user());
            let asked_by = |request: &&&Value| user.is_some() && request["userId"].as_i64() == user;
            let mine = requests.iter().find(asked_by).or(requests.first());
            if let (Some(shared), [only]) = (&self.shared, requests.as_slice())
                && let Some(id) = only["userId"].as_i64()
                && user != Some(id)
            {
                shared.set_user(id);
            }
            // By series from here on, not by name: a late `Open` and the `Close` that follows a
            // timed-out `connect` are both `Invoke-PosTunnel`.
            run.series = mine.and_then(|a| a["seriesUid"].as_str().map(str::to_owned));
        }
        let Some(series) = &run.series else {
            return Ok(None);
        };
        let reply: Value = self.get(&format!(
            "/v2/device/{device}/activities?seriesUid={series}&pageSize=10"
        ))?;
        let Some(done) = reply["activities"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|a| a["statusCode"] == "COMPLETED")
        else {
            return Ok(None);
        };
        let output = done["data"]["message"]["params"]["output_message"]
            .as_str()
            .or(done["message"].as_str())
            .unwrap_or_default()
            .replace("\r\n", "\n");
        // The POS's words go to the operator's terminal: never with the control characters, escape
        // sequences among them, that could drive it.
        let output: String = output
            .trim_end()
            .chars()
            .filter(|c| !c.is_control() || matches!(c, '\t' | '\n'))
            .collect();
        // Both: NinjaOne's verdict follows the exit code, and a `FAILED` line is the script's own word.
        let success = done["activityResult"] == "SUCCESS"
            && !output.lines().any(|line| line.starts_with("FAILED\t"));
        Ok(Some(ScriptResult { success, output }))
    }

    /// Runs a library script on every device in `devices` at once and waits for each result, in their
    /// order. A device NinjaOne refuses, or that reports nothing within `timeout`, gets an error; the
    /// others still finish.
    pub fn run_scripts(
        &self,
        devices: &[i64],
        script: i64,
        name: &'static str,
        parameters: &str,
        timeout: Duration,
        poll: Duration,
    ) -> Vec<Result<ScriptResult>> {
        let waited = humantime::format_duration(timeout);
        // Each run with what its last look failed with, if it did.
        let mut pending: Vec<(usize, ScriptRun, Option<anyhow::Error>)> = Vec::new();
        let mut results: Vec<Result<ScriptResult>> = Vec::new();
        for (index, &device) in devices.iter().enumerate() {
            match self.start_script(device, script, name, parameters) {
                Ok(run) => {
                    pending.push((index, run, None));
                    results.push(Err(anyhow::anyhow!(
                        "the POS reported no result for {name} within {waited}"
                    )));
                }
                Err(e) => results.push(Err(e)),
            }
        }
        let deadline = Instant::now() + timeout;
        loop {
            // A look that fails is one more "not yet": one NinjaOne error among the hundreds of calls
            // a fleet takes mustn't fail a POS that goes on to report.
            pending.retain_mut(|(index, run, trouble)| match self.poll_script(run) {
                Ok(Some(result)) => {
                    results[*index] = Ok(result);
                    false
                }
                Ok(None) => {
                    *trouble = None;
                    true
                }
                Err(e) => {
                    *trouble = Some(e);
                    true
                }
            });
            if pending.is_empty() || Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(poll);
        }
        for (index, _, trouble) in pending {
            if let Some(e) = trouble {
                results[index] = Err(e.context(format!(
                    "the POS's result for {name} couldn't be read within {waited}"
                )));
            }
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_matches_rfc_7636_appendix_b() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn the_callback_yields_its_code_only_with_this_sign_ins_state() {
        assert_eq!(
            parse_callback("GET /?code=abc&state=s1 HTTP/1.1\r\n", "s1"),
            Callback::Code("abc".into())
        );
        assert!(matches!(
            parse_callback("GET /?code=abc&state=other HTTP/1.1\r\n", "s1"),
            Callback::Denied(_)
        ));
        assert!(matches!(
            parse_callback("GET /?code=abc HTTP/1.1\r\n", "s1"),
            Callback::Denied(_)
        ));
    }

    #[test]
    fn the_callback_reports_a_refusal_and_ignores_other_requests() {
        assert_eq!(
            parse_callback(
                "GET /?error=access_denied&error_description=user%20said%20no HTTP/1.1",
                "s"
            ),
            Callback::Denied("user said no".into())
        );
        assert_eq!(
            parse_callback("GET /favicon.ico HTTP/1.1", "s"),
            Callback::Other
        );
        assert_eq!(parse_callback("", "s"), Callback::Other);
    }

    #[test]
    fn the_sign_in_listener_answers_other_requests_and_returns_the_code() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let browser = std::thread::spawn(move || {
            let request = |line: &str| {
                let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
                stream
                    .write_all(format!("{line}\r\nHost: 127.0.0.1\r\n\r\n").as_bytes())
                    .unwrap();
                let mut reply = String::new();
                std::io::Read::read_to_string(&mut stream, &mut reply).unwrap();
                reply
            };
            (
                request("GET /favicon.ico HTTP/1.1"),
                request("GET /?code=abc&state=s1 HTTP/1.1"),
            )
        });
        assert_eq!(await_code(&listener, "s1").unwrap(), "abc");
        let (favicon, callback) = browser.join().unwrap();
        assert!(favicon.starts_with("HTTP/1.1 404"), "{favicon}");
        assert!(callback.contains("posctl is signed in"), "{callback}");
    }

    #[test]
    fn a_refused_token_request_reports_ninjaones_reason() {
        let fake = crate::fake::Fake::start(|_, _, _| (400, json!({"error": "invalid_grant"})));
        let error = token_request::<Value>(&fake.url, &[("grant_type", "refresh_token")])
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("NinjaOne refused the token request (400)")
                && error.contains("invalid_grant"),
            "{error}"
        );
    }

    #[test]
    fn a_device_override_beats_its_role_policy() {
        let device = |json| {
            serde_json::from_value::<Device>(json)
                .unwrap()
                .effective_policy()
        };
        assert_eq!(
            device(json!({"id": 1, "organizationId": 3, "rolePolicyId": 5})),
            Some(5)
        );
        assert_eq!(
            device(json!({"id": 1, "organizationId": 3, "rolePolicyId": 5, "policyId": 9})),
            Some(9)
        );
    }

    #[test]
    fn devices_are_read_a_page_at_a_time_until_an_empty_page() {
        // A server that caps a page at two devices, whatever page size is asked for.
        let fake = crate::fake::Fake::start(|_, path, _| {
            let after: i64 = path
                .split_once("&after=")
                .map_or(0, |(_, id)| id.parse().unwrap());
            let page: Vec<Value> = (after + 1..=5)
                .take(2)
                .map(|id| json!({"id": id, "organizationId": 3}))
                .collect();
            (200, Value::Array(page))
        });
        assert_eq!(Api::with_token(&fake.url, "t").devices(3).unwrap().len(), 5);
        // Each page starts after the previous page's last device; the empty one ends the list.
        for after in ["", "&after=2", "&after=4", "&after=5"] {
            let path = format!("/v2/organization/3/devices?pageSize=1000{after}");
            assert_eq!(fake.requests_to("GET", &path).len(), 1, "{path}");
        }
    }

    #[test]
    fn a_device_list_that_does_not_advance_is_refused() {
        // A server that ignores `after` would otherwise be read forever.
        let fake =
            crate::fake::Fake::start(|_, _, _| (200, json!([{"id": 1, "organizationId": 3}])));
        let error = Api::with_token(&fake.url, "t")
            .devices(3)
            .unwrap_err()
            .to_string();
        assert!(error.contains("didn't advance past device 1"), "{error}");
    }

    #[test]
    fn an_unreachable_ninjaone_is_not_blamed_on_the_sign_in() {
        // A port nothing listens on.
        let port = TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let unreachable =
            Api::with_refresh_token(&format!("http://127.0.0.1:{port}"), "c", "r", None);
        let error = format!("{:#}", unreachable.err().unwrap());
        assert!(
            error.contains("couldn't reach NinjaOne") && !error.contains("posctl login"),
            "{error}"
        );
        let fake = crate::fake::Fake::start(|_, _, _| (400, json!({"error": "invalid_grant"})));
        let refused = Api::with_refresh_token(&fake.url, "c", "r", None);
        let error = format!("{:#}", refused.err().unwrap());
        assert!(
            error.contains("run `posctl login`") && error.contains("invalid_grant"),
            "{error}"
        );
    }

    type Activities = std::sync::Arc<std::sync::Mutex<Vec<Value>>>;

    fn activity(id: i64, device: i64, status: &str, series: &str, extra: Value) -> Value {
        let mut activity = json!({"id": id, "deviceId": device, "statusCode": status,
            "sourceName": INVOKE_SCRIPT, "seriesUid": series});
        let fields = activity.as_object_mut().unwrap();
        fields.extend(extra.as_object().unwrap().clone());
        activity
    }

    fn completed(id: i64, device: i64, series: &str, result: &str, output: &str) -> Value {
        let extra = json!({"activityResult": result, "data": {"message": {"params": {"output_message": output}}}});
        activity(id, device, "COMPLETED", series, extra)
    }

    /// A tenant that lists `activities` as NinjaOne does (newest first, `newerThan` and `seriesUid`
    /// filtering) and on a script run does `on_run`, which gets the device and returns the status.
    fn activity_tenant(
        activities: &Activities,
        on_run: impl Fn(i64, &mut Vec<Value>) -> u16 + Send + 'static,
    ) -> crate::fake::Fake {
        let activities = std::sync::Arc::clone(activities);
        crate::fake::Fake::start(move |method, path, _| {
            let (route, query) = path.split_once('?').unwrap_or((path, ""));
            let param = |name: &str| {
                query
                    .split('&')
                    .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
            };
            let device: i64 = route.split('/').nth(3).unwrap().parse().unwrap();
            let mut activities = activities.lock().unwrap();
            if method == "POST" {
                return (on_run(device, &mut activities), Value::Null);
            }
            let newer: i64 = param("newerThan").map_or(0, |id| id.parse().unwrap());
            let of_device: Vec<&Value> = activities
                .iter()
                .filter(|a| a["deviceId"] == device)
                .collect();
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
        })
    }

    #[test]
    fn a_script_run_is_followed_by_its_own_series() {
        // An earlier Invoke-PosTunnel run on the device was requested before this one and ends after it.
        let activities: Activities = Default::default();
        activities
            .lock()
            .unwrap()
            .push(activity(10, 1, "START_REQUESTED", "earlier", json!({})));
        let fake = activity_tenant(&activities, |device, activities| {
            activities.push(activity(11, device, "START_REQUESTED", "this", json!({})));
            204
        });
        let api = Api::with_token(&fake.url, "t");

        let mut run = api
            .start_script(1, 94, INVOKE_SCRIPT, "-Action Close")
            .unwrap();
        assert_eq!(api.poll_script(&mut run).unwrap(), None);
        let earlier = completed(12, 1, "earlier", "SUCCESS", "CHANGED\ttunnel\tport 20001");
        activities.lock().unwrap().push(earlier);
        assert_eq!(api.poll_script(&mut run).unwrap(), None);
        let this = completed(13, 1, "this", "SUCCESS", "OK\tclose\tsession ended\r\n");
        activities.lock().unwrap().push(this);

        assert_eq!(
            api.poll_script(&mut run).unwrap(),
            Some(ScriptResult {
                success: true,
                output: "OK\tclose\tsession ended".into()
            })
        );
    }

    #[test]
    fn a_script_result_is_a_failure_on_ninjaones_word_or_a_failed_line() {
        for (result, output, success, deferred) in [
            (
                "SUCCESS",
                "OK\tfolder\r\nCHANGED\tcurrent\tversion 4",
                true,
                false,
            ),
            ("FAILURE", "", false, false),
            (
                "SUCCESS",
                "OK\tfolder\r\nFAILED\tsetup\tno relay",
                false,
                false,
            ),
            (
                "SUCCESS",
                "OK\tfolder\r\nDEFERRED\tsession\ta session is open",
                true,
                true,
            ),
        ] {
            let activities: Activities = Default::default();
            let fake = activity_tenant(&activities, move |device, activities| {
                activities.push(activity(1, device, "START_REQUESTED", "s", json!({})));
                activities.push(completed(2, device, "s", result, output));
                204
            });
            let api = Api::with_token(&fake.url, "t");
            let mut run = api.start_script(1, 93, INVOKE_SCRIPT, "").unwrap();
            let got = api.poll_script(&mut run).unwrap().unwrap();
            assert_eq!(
                (got.success, got.deferred()),
                (success, deferred),
                "{output}"
            );
            assert_eq!(got.output, output.replace("\r\n", "\n"));
        }
    }

    #[test]
    fn scripts_run_together_and_one_refusal_or_silence_fails_alone() {
        let activities: Activities = Default::default();
        // Device 5 is refused, 6 reports, 7 is requested and never answers.
        let fake = activity_tenant(&activities, |device, activities| {
            let id = activities.len() as i64 * 2;
            let series = format!("s{device}");
            match device {
                5 => return 500,
                6 => {
                    activities.push(activity(id + 1, 6, "START_REQUESTED", &series, json!({})));
                    activities.push(completed(id + 2, 6, &series, "SUCCESS", "CHANGED\tfields"));
                }
                _ => activities.push(activity(
                    id + 1,
                    device,
                    "START_REQUESTED",
                    &series,
                    json!({}),
                )),
            }
            204
        });
        let api = Api::with_token(&fake.url, "t");

        let results = api.run_scripts(
            &[5, 6, 7],
            94,
            INVOKE_SCRIPT,
            "-Action Rekey",
            Duration::from_millis(200),
            Duration::from_millis(5),
        );

        let refused = results[0].as_ref().unwrap_err().to_string();
        assert!(
            refused.contains("/v2/device/5/script/run failed (500)"),
            "{refused}"
        );
        assert!(results[1].as_ref().unwrap().success);
        let silent = results[2].as_ref().unwrap_err().to_string();
        assert!(
            silent.contains("the POS reported no result for Invoke-PosTunnel within 200ms"),
            "{silent}"
        );
    }

    #[test]
    fn written_fields_are_waited_for_until_ninjaone_shows_them() {
        // The first two reads still show the old key; the version comes back as a number.
        let reads = std::sync::atomic::AtomicUsize::new(0);
        let fake = crate::fake::Fake::start(move |_, _, _| {
            let read = reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let key = if read < 2 { "old" } else { "new" };
            (
                200,
                json!({"posTunnelRelayKey": key, "posTunnelVersion": 4}),
            )
        });
        let api = Api::with_token(&fake.url, "t");
        let asked = || fake.requests_to("GET", "/v2/device/1/custom-fields").len();
        let result = |output: &str| ScriptResult {
            success: true,
            output: output.to_owned(),
        };
        let poll = Duration::from_millis(5);
        let soon = || Instant::now() + Duration::from_secs(5);

        let wrote = result(
            "CHANGED\trelay key pair\tregenerated\nCHANGED\tfield posTunnelRelayKey\tnew\nOK\tfield posTunnelHostKey\nCHANGED\tfield posTunnelVersion\t4",
        );
        assert_eq!(
            wrote.published(),
            [("posTunnelRelayKey", "new"), ("posTunnelVersion", "4")]
        );
        assert_eq!(
            api.await_published(1, &wrote, soon(), poll),
            Published::Shown
        );
        assert_eq!(asked(), 3);

        // Nothing written: nothing to wait for, and nothing asked.
        let unchanged = result(
            "OK\tfield posTunnelRelayKey\nOK\tfield posTunnelHostKey\nOK\tfield posTunnelVersion",
        );
        assert_eq!(
            api.await_published(1, &unchanged, Instant::now(), poll),
            Published::Shown
        );
        assert_eq!(asked(), 3);

        // A value NinjaOne never shows runs the wait out.
        let unseen = result(
            "CHANGED\tfield posTunnelRelayKey\tnewer\nOK\tfield posTunnelHostKey\nOK\tfield posTunnelVersion",
        );
        let shortly = Instant::now() + Duration::from_millis(50);
        assert_eq!(
            api.await_published(1, &unseen, shortly, poll),
            Published::TimedOut
        );

        // A report that stops before its field lines says nothing about them: not waited on, not asked.
        let asked_before = asked();
        let cut =
            result("CHANGED\trelay key pair\tregenerated\nCHANGED\tfield posTunnelRelayKey\tnew");
        assert_eq!(
            api.await_published(1, &cut, soon(), poll),
            Published::CutShort
        );
        assert_eq!(asked(), asked_before);
    }

    #[test]
    fn a_call_cut_off_by_another_runs_sign_in_signs_in_again_and_is_repeated() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let (issued, calls) = (AtomicUsize::new(0), AtomicUsize::new(0));
        let fake = crate::fake::Fake::start(move |_, path, _| {
            if path == "/ws/oauth/token" {
                let token = format!("t{}", issued.fetch_add(1, SeqCst) + 1);
                return (200, json!({"access_token": token}));
            }
            // Another `posctl` has refreshed the sign-in since, which ended the first call's token.
            if calls.fetch_add(1, SeqCst) == 0 {
                return (401, json!({"error": "not_authenticated"}));
            }
            (200, json!({"posTunnelVersion": "4"}))
        });
        let api = Api::with_refresh_token(&fake.url, "c", "r", None).unwrap();

        let fields = api.custom_fields(1).unwrap();

        assert_eq!(fields["posTunnelVersion"], "4");
        assert_eq!(
            fake.authorizations_to("GET", "/v2/device/1/custom-fields"),
            ["Bearer t1", "Bearer t2"]
        );
    }

    #[test]
    fn a_call_still_refused_after_two_more_sign_ins_fails() {
        let fake = crate::fake::Fake::start(|_, path, _| {
            if path == "/ws/oauth/token" {
                (200, json!({"access_token": "t"}))
            } else {
                (401, json!({"error": "not_authenticated"}))
            }
        });
        let api = Api::with_refresh_token(&fake.url, "c", "r", None).unwrap();

        let error = api.custom_fields(1).unwrap_err().to_string();

        assert!(
            error.contains("/v2/device/1/custom-fields failed (401)"),
            "{error}"
        );
        // The sign-in at the start and the two after a refusal.
        assert_eq!(fake.requests_to("POST", "/ws/oauth/token").len(), 3);
    }

    #[test]
    fn control_characters_in_a_scripts_output_are_dropped() {
        let activities: Activities = Default::default();
        let fake = activity_tenant(&activities, |device, activities| {
            activities.push(activity(1, device, "START_REQUESTED", "s", json!({})));
            // A clear-screen sequence and a bell, as a compromised POS might print.
            let output = "OK\tfolder\u{1b}[2J\r\nOK\tcurrent\u{7}\tversion 4";
            activities.push(completed(2, device, "s", "SUCCESS", output));
            204
        });
        let api = Api::with_token(&fake.url, "t");
        let mut run = api.start_script(1, 93, INVOKE_SCRIPT, "").unwrap();

        let got = api.poll_script(&mut run).unwrap().unwrap();

        assert_eq!(got.output, "OK\tfolder[2J\nOK\tcurrent\tversion 4");
    }

    /// A tenant whose looks at device 1's run fail `failures` times before listing it complete.
    fn flaky_tenant(failures: usize) -> crate::fake::Fake {
        let looks = std::sync::atomic::AtomicUsize::new(0);
        crate::fake::Fake::start(move |method, path, _| {
            if method == "POST" {
                return (204, Value::Null);
            }
            if !path.contains("newerThan") && !path.contains("seriesUid") {
                return (200, json!({"activities": [], "lastNodeActivityId": 10}));
            }
            if looks.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < failures {
                return (502, json!({"error": "bad gateway"}));
            }
            let run = [
                completed(12, 1, "s", "SUCCESS", "OK\tdone"),
                activity(11, 1, "START_REQUESTED", "s", json!({})),
            ];
            (200, json!({"activities": run, "lastNodeActivityId": 12}))
        })
    }

    #[test]
    fn a_look_that_fails_is_not_the_runs_result() {
        let fake = flaky_tenant(2);
        let api = Api::with_token(&fake.url, "t");

        let results = api.run_scripts(
            &[1],
            94,
            INVOKE_SCRIPT,
            "-Action Touch",
            Duration::from_secs(5),
            Duration::from_millis(5),
        );

        assert_eq!(results[0].as_ref().unwrap().output, "OK\tdone");
    }

    #[test]
    fn looks_that_keep_failing_are_what_the_timeout_reports() {
        let fake = flaky_tenant(usize::MAX);
        let api = Api::with_token(&fake.url, "t");

        let results = api.run_scripts(
            &[1],
            94,
            INVOKE_SCRIPT,
            "-Action Touch",
            Duration::from_millis(100),
            Duration::from_millis(5),
        );

        let error = format!("{:#}", results[0].as_ref().unwrap_err());
        assert!(
            error.contains("couldn't be read within 100ms") && error.contains("(502)"),
            "{error}"
        );
    }

    #[test]
    fn without_a_newest_activity_id_the_newest_listed_one_stands_in() {
        // The run before this one, already complete: taken for this run if looks started from 0.
        let fake = crate::fake::Fake::start(|method, path, _| {
            if method == "POST" {
                return (204, Value::Null);
            }
            if path.contains("newerThan") {
                return (200, json!({"activities": []}));
            }
            let earlier = [
                completed(31, 1, "old", "SUCCESS", "OK\told"),
                activity(30, 1, "START_REQUESTED", "old", json!({})),
            ];
            (200, json!({"activities": earlier}))
        });
        let api = Api::with_token(&fake.url, "t");

        let mut run = api.start_script(1, 94, INVOKE_SCRIPT, "").unwrap();

        assert_eq!(api.poll_script(&mut run).unwrap(), None);
        assert_eq!(
            fake.requests_to("GET", "/v2/device/1/activities?newerThan=31&pageSize=200")
                .len(),
            1
        );
    }

    /// A tenant that issues `t1`, `t2`, ... at the token endpoint and answers the first call `401`.
    fn refusing_once() -> crate::fake::Fake {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let (issued, calls) = (AtomicUsize::new(0), AtomicUsize::new(0));
        crate::fake::Fake::start(move |_, path, _| {
            if path == "/ws/oauth/token" {
                let token = format!("t{}", issued.fetch_add(1, SeqCst) + 1);
                return (200, json!({"access_token": token}));
            }
            if calls.fetch_add(1, SeqCst) == 0 {
                return (401, json!({"error": "not_authenticated"}));
            }
            (200, json!({}))
        })
    }

    #[test]
    fn commands_share_one_access_token() {
        let fake = crate::fake::Fake::start(|_, path, _| {
            if path == "/ws/oauth/token" {
                (200, json!({"access_token": "t1"}))
            } else {
                (200, json!({}))
            }
        });
        let shared = Rc::new(crate::fake::Memory::default());

        // Two commands of one identity, the second starting while the first still runs.
        let first = Api::with_refresh_token(&fake.url, "c", "r", Some(shared.clone())).unwrap();
        let second = Api::with_refresh_token(&fake.url, "c", "r", Some(shared.clone())).unwrap();
        first.custom_fields(1).unwrap();
        second.custom_fields(1).unwrap();
        first.custom_fields(1).unwrap();

        assert_eq!(fake.requests_to("POST", "/ws/oauth/token").len(), 1);
        assert_eq!(
            fake.authorizations_to("GET", "/v2/device/1/custom-fields"),
            ["Bearer t1", "Bearer t1", "Bearer t1"]
        );
    }

    #[test]
    fn a_refused_call_takes_the_token_another_command_signed_in_with() {
        let fake = refusing_once();
        let shared = Rc::new(crate::fake::Memory::default());
        shared.set_access_token("old");
        let api = Api::with_refresh_token(&fake.url, "c", "r", Some(shared.clone())).unwrap();
        // Another command found `old` run out and signed in.
        shared.set_access_token("theirs");

        api.custom_fields(1).unwrap();

        assert_eq!(
            fake.authorizations_to("GET", "/v2/device/1/custom-fields"),
            ["Bearer old", "Bearer theirs"]
        );
        assert!(fake.requests_to("POST", "/ws/oauth/token").is_empty());
    }

    #[test]
    fn a_refused_call_with_nobody_elses_token_signs_in_and_shares_its_own() {
        let fake = refusing_once();
        let shared = Rc::new(crate::fake::Memory::default());
        shared.set_access_token("old");
        let api = Api::with_refresh_token(&fake.url, "c", "r", Some(shared.clone())).unwrap();

        api.custom_fields(1).unwrap();

        assert_eq!(
            fake.authorizations_to("GET", "/v2/device/1/custom-fields"),
            ["Bearer old", "Bearer t1"]
        );
        assert_eq!(shared.access_token().as_deref(), Some("t1"));
    }

    #[test]
    fn only_a_sign_in_ninjaone_no_longer_accepts_is_told_to_log_in_again() {
        let fake = crate::fake::Fake::start(|_, _, _| (429, json!({"error": "too_many_requests"})));

        let refused = Api::with_refresh_token(&fake.url, "c", "r", None);

        let error = format!("{:#}", refused.err().unwrap());
        assert!(
            error.contains("(429)") && !error.contains("posctl login"),
            "{error}"
        );
    }

    /// A client whose commands share `user` as the NinjaOne user they run as.
    fn api_as(fake: &crate::fake::Fake, user: Option<i64>) -> (Api, Rc<crate::fake::Memory>) {
        let shared = Rc::new(crate::fake::Memory::default());
        shared.set_access_token("t");
        if let Some(user) = user {
            shared.set_user(user);
        }
        let api = Api::with_refresh_token(&fake.url, "c", "r", Some(shared.clone())).unwrap();
        (api, shared)
    }

    #[test]
    fn a_run_is_told_from_another_operators_by_who_asked() {
        // Another operator's request for the same script landed between this run's two calls.
        let activities: Activities = Default::default();
        let fake = activity_tenant(&activities, |device, activities| {
            let by = |user: i64| json!({"userId": user});
            activities.push(activity(1, device, "START_REQUESTED", "theirs", by(7)));
            activities.push(completed(2, device, "theirs", "SUCCESS", "OK\ttheirs"));
            activities.push(activity(3, device, "START_REQUESTED", "mine", by(1)));
            activities.push(completed(4, device, "mine", "SUCCESS", "OK\tmine"));
            204
        });
        let (api, shared) = api_as(&fake, Some(1));
        let mut run = api.start_script(1, 94, INVOKE_SCRIPT, "").unwrap();

        let got = api.poll_script(&mut run).unwrap().unwrap();

        assert_eq!(got.output, "OK\tmine");
        // Two requests prove nothing about who this command runs as.
        assert_eq!(shared.user(), Some(1));
    }

    #[test]
    fn the_user_is_learned_from_a_request_that_stands_alone() {
        let activities: Activities = Default::default();
        let fake = activity_tenant(&activities, |device, activities| {
            let by = json!({"userId": 4});
            activities.push(activity(1, device, "START_REQUESTED", "mine", by));
            activities.push(completed(2, device, "mine", "SUCCESS", "OK\tmine"));
            204
        });
        // 9: learned wrongly once, and put right here.
        for known in [None, Some(9)] {
            activities.lock().unwrap().clear();
            let (api, shared) = api_as(&fake, known);
            let mut run = api.start_script(1, 94, INVOKE_SCRIPT, "").unwrap();

            let got = api.poll_script(&mut run).unwrap().unwrap();

            assert_eq!(got.output, "OK\tmine");
            assert_eq!(shared.user(), Some(4));
        }
    }
}

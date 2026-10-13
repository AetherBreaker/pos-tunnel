//! The NinjaOne API (design section 8): the browser sign-in, the stored refresh token, and the calls
//! both binaries make.
//!
//! Running a script needs a user's token (a client-credentials token gets `user_context_required`), so
//! `login` signs in with the authorization-code grant through the tenant's Native app: PKCE (RFC 7636),
//! no client secret, a loopback redirect on a port the OS picks (RFC 8252). Refresh tokens don't rotate,
//! so the one `login` stores lasts; each command trades it for an hour's access token.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
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

fn token_request<T: DeserializeOwned>(base_url: &str, form: &[(&str, &str)]) -> Result<T> {
    let mut response = agent()
        .post(format!("{base_url}/ws/oauth/token"))
        .send_form(form.iter().copied())?;
    let status = response.status().as_u16();
    let body = response.body_mut().read_to_string()?;
    if status != 200 {
        bail!(
            "NinjaOne refused the token request ({status}): {}",
            snippet(&body)
        );
    }
    Ok(serde_json::from_str(&body)?)
}

fn snippet(body: &str) -> String {
    body.chars().take(300).collect()
}

/// The refresh token: Windows Credential Manager on Windows (design section 3), a user-only file elsewhere
/// and wherever `POSCTL_CONFIG_HOME` is set, so a second identity has its own sign-in and a test never
/// reads the real one (design section 8).
pub mod token_store {
    use anyhow::{Context, Result};

    #[cfg(windows)]
    fn entry() -> Result<keyring_core::Entry> {
        static STORE: std::sync::Once = std::sync::Once::new();
        let mut failed = None;
        STORE.call_once(|| match windows_native_keyring_store::Store::new() {
            Ok(store) => keyring_core::set_default_store(store),
            Err(e) => failed = Some(e),
        });
        if let Some(e) = failed {
            return Err(e.into());
        }
        Ok(keyring_core::Entry::new(
            "posctl",
            "ninjaone-refresh-token",
        )?)
    }

    fn path() -> Result<std::path::PathBuf> {
        Ok(crate::config::config_home()?
            .join("posctl")
            .join("refresh_token"))
    }

    pub fn save(token: &str) -> Result<()> {
        #[cfg(windows)]
        if std::env::var_os("POSCTL_CONFIG_HOME").is_none() {
            return Ok(entry()?.set_password(token)?);
        }
        crate::config::write_private(&path()?, token.as_bytes())
    }

    pub fn load() -> Result<String> {
        #[cfg(windows)]
        if std::env::var_os("POSCTL_CONFIG_HOME").is_none() {
            return entry()?
                .get_password()
                .context("not signed in to NinjaOne: run `posctl login`");
        }
        Ok(std::fs::read_to_string(path()?)
            .context("not signed in to NinjaOne: run `posctl login`")?
            .trim()
            .to_owned())
    }
}

/// A signed-in API client: the stored refresh token traded for an access token.
pub struct Api {
    agent: Agent,
    base_url: String,
    access_token: String,
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

#[derive(Debug, Clone, PartialEq)]
pub struct ScriptResult {
    /// NinjaOne's verdict, and no `FAILED` line in the output.
    pub success: bool,
    /// What the script printed. The POS's words: untrusted, shown as its report and nothing more.
    pub output: String,
}

impl ScriptResult {
    /// A step put off to a later run (a session is open, a restart is pending): design section 7.1.
    pub fn deferred(&self) -> bool {
        self.output
            .lines()
            .any(|line| line.starts_with("DEFERRED\t"))
    }
}

impl Api {
    pub fn connect(base_url: &str, client_id: &str) -> Result<Api> {
        Api::with_refresh_token(base_url, client_id, &token_store::load()?)
    }

    /// `connect` without the token store, so a test never touches a real sign-in.
    pub fn with_refresh_token(base_url: &str, client_id: &str, refresh: &str) -> Result<Api> {
        let tokens: Value = token_request(
            base_url,
            &[
                ("grant_type", "refresh_token"),
                ("client_id", client_id),
                ("refresh_token", refresh),
            ],
        )
        .map_err(|e| {
            // Signing in again cures a refusal, not an unreachable NinjaOne.
            if e.chain().any(|cause| cause.is::<ureq::Error>()) {
                e.context(format!("couldn't reach NinjaOne at {base_url}"))
            } else {
                e.context("refreshing the NinjaOne sign-in failed; run `posctl login`")
            }
        })?;
        let access_token = tokens["access_token"]
            .as_str()
            .context("NinjaOne returned no access token")?
            .to_owned();
        Ok(Api {
            agent: agent(),
            base_url: base_url.to_owned(),
            access_token,
        })
    }

    /// For tests: a client of a fake server with a fixed token.
    pub fn with_token(base_url: &str, access_token: &str) -> Api {
        Api {
            agent: agent(),
            base_url: base_url.to_owned(),
            access_token: access_token.to_owned(),
        }
    }

    /// One call; the status and body, whatever the status.
    fn call(&self, method: &str, path: &str, body: Option<&Value>) -> Result<(u16, String)> {
        let url = format!("{}{path}", self.base_url);
        let auth = format!("Bearer {}", self.access_token);
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
        Ok((status, response.body_mut().read_to_string()?))
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
        let after = before["lastNodeActivityId"].as_i64().unwrap_or(0);
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
            // Newest first, so the last match is the oldest request since `after`: this run's. By
            // series from here on, not by name: a late `Open` and the `Close` that follows a timed-out
            // `connect` are both `Invoke-PosTunnel`.
            run.series = reply["activities"]
                .as_array()
                .into_iter()
                .flatten()
                .rfind(|a| a["statusCode"] == "START_REQUESTED" && a["sourceName"] == run.name)
                .and_then(|a| a["seriesUid"].as_str().map(str::to_owned));
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
        let output = output.trim_end().to_owned();
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
        let mut pending: Vec<(usize, ScriptRun)> = Vec::new();
        let mut results: Vec<Option<Result<ScriptResult>>> = Vec::new();
        for (index, &device) in devices.iter().enumerate() {
            match self.start_script(device, script, name, parameters) {
                Ok(run) => {
                    pending.push((index, run));
                    results.push(None);
                }
                Err(e) => results.push(Some(Err(e))),
            }
        }
        let deadline = Instant::now() + timeout;
        loop {
            pending.retain_mut(|(index, run)| match self.poll_script(run).transpose() {
                Some(result) => {
                    results[*index] = Some(result);
                    false
                }
                None => true,
            });
            if pending.is_empty() || Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(poll);
        }
        results
            .into_iter()
            .map(|result| {
                result.unwrap_or_else(|| {
                    bail!(
                        "the POS reported no result for {name} within {}",
                        humantime::format_duration(timeout)
                    )
                })
            })
            .collect()
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
        let unreachable = Api::with_refresh_token(&format!("http://127.0.0.1:{port}"), "c", "r");
        let error = format!("{:#}", unreachable.err().unwrap());
        assert!(
            error.contains("couldn't reach NinjaOne") && !error.contains("posctl login"),
            "{error}"
        );
        let fake = crate::fake::Fake::start(|_, _, _| (400, json!({"error": "invalid_grant"})));
        let refused = Api::with_refresh_token(&fake.url, "c", "r");
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
}

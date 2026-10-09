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
const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);

/// Signs in through the browser and stores the refresh token.
pub fn login(base_url: &str, client_id: &str) -> Result<()> {
    let verifier = random_token(48);
    let state = random_token(16);
    let listener = TcpListener::bind(("127.0.0.1", 0)).context("opening the sign-in callback port")?;
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
    let refresh = tokens["refresh_token"].as_str().context("NinjaOne returned no refresh token (scope offline_access)")?;
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
    let Some(target) = request_line.strip_prefix("GET ").and_then(|rest| rest.split(' ').next()) else {
        return Callback::Other;
    };
    let Ok(url) = url::Url::parse(&format!("http://127.0.0.1{target}")) else {
        return Callback::Other;
    };
    let get = |name: &str| url.query_pairs().find(|(k, _)| k == name).map(|(_, v)| v.into_owned());
    if let Some(error) = get("error") {
        return Callback::Denied(get("error_description").unwrap_or(error));
    }
    match (get("code"), get("state")) {
        (Some(code), Some(got)) if got == state => Callback::Code(code),
        (Some(_), _) => Callback::Denied("the callback's state didn't match this sign-in".into()),
        _ => Callback::Other,
    }
}

fn agent() -> Agent {
    Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(60)))
        .build()
        .into()
}

fn token_request<T: DeserializeOwned>(base_url: &str, form: &[(&str, &str)]) -> Result<T> {
    let mut response = agent().post(format!("{base_url}/ws/oauth/token")).send_form(form.iter().copied())?;
    let status = response.status().as_u16();
    let body = response.body_mut().read_to_string()?;
    if status != 200 {
        bail!("NinjaOne refused the token request ({status}): {}", snippet(&body));
    }
    Ok(serde_json::from_str(&body)?)
}

fn snippet(body: &str) -> String {
    body.chars().take(300).collect()
}

/// The refresh token: Windows Credential Manager on Windows (design section 3), a user-only file elsewhere.
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
        Ok(keyring_core::Entry::new("posctl", "ninjaone-refresh-token")?)
    }

    #[cfg(windows)]
    pub fn save(token: &str) -> Result<()> {
        Ok(entry()?.set_password(token)?)
    }

    #[cfg(windows)]
    pub fn load() -> Result<String> {
        entry()?.get_password().context("not signed in to NinjaOne: run `posctl login`")
    }

    #[cfg(not(windows))]
    fn path() -> Result<std::path::PathBuf> {
        Ok(crate::config::config_home()?.join("posctl").join("refresh_token"))
    }

    #[cfg(not(windows))]
    pub fn save(token: &str) -> Result<()> {
        crate::config::write_private(&path()?, token.as_bytes())
    }

    #[cfg(not(windows))]
    pub fn load() -> Result<String> {
        Ok(std::fs::read_to_string(path()?).context("not signed in to NinjaOne: run `posctl login`")?.trim().to_owned())
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

impl Api {
    pub fn connect(base_url: &str, client_id: &str) -> Result<Api> {
        let refresh = token_store::load()?;
        let tokens: Value =
            token_request(base_url, &[("grant_type", "refresh_token"), ("client_id", client_id), ("refresh_token", &refresh)])
                .context("refreshing the NinjaOne sign-in failed; run `posctl login`")?;
        let access_token = tokens["access_token"].as_str().context("NinjaOne returned no access token")?.to_owned();
        Ok(Api { agent: agent(), base_url: base_url.to_owned(), access_token })
    }

    /// For tests: a client of a fake server with a fixed token.
    pub fn with_token(base_url: &str, access_token: &str) -> Api {
        Api { agent: agent(), base_url: base_url.to_owned(), access_token: access_token.to_owned() }
    }

    /// One call; the status and body, whatever the status.
    fn call(&self, method: &str, path: &str, body: Option<&Value>) -> Result<(u16, String)> {
        let url = format!("{}{path}", self.base_url);
        let auth = format!("Bearer {}", self.access_token);
        let mut response = match (method, body) {
            ("GET", _) => self.agent.get(&url).header("Authorization", &auth).call()?,
            ("POST", Some(body)) => self.agent.post(&url).header("Authorization", &auth).send_json(body)?,
            ("PATCH", Some(body)) => self.agent.patch(&url).header("Authorization", &auth).send_json(body)?,
            _ => bail!("unsupported call {method} {path}"),
        };
        let status = response.status().as_u16();
        Ok((status, response.body_mut().read_to_string()?))
    }

    fn checked(&self, method: &str, path: &str, body: Option<&Value>) -> Result<String> {
        let (status, text) = self.call(method, path, body)?;
        if !(200..300).contains(&status) {
            bail!("NinjaOne {method} {path} failed ({status}): {}", snippet(&text));
        }
        Ok(text)
    }

    pub fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let text = self.checked("GET", path, None)?;
        serde_json::from_str(&text).with_context(|| format!("NinjaOne GET {path}: unexpected reply: {}", snippet(&text)))
    }

    /// Every device, a page at a time (`after` is the last device ID of the previous page).
    pub fn devices(&self) -> Result<Vec<Device>> {
        let mut devices: Vec<Device> = Vec::new();
        loop {
            let after = devices.last().map(|d| format!("&after={}", d.id)).unwrap_or_default();
            let page: Vec<Device> = self.get(&format!("/v2/devices?pageSize=1000{after}"))?;
            let done = page.len() < 1000;
            devices.extend(page);
            if done {
                return Ok(devices);
            }
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
        self.checked("POST", "/v2/custom-fields", Some(definition)).map(drop)
    }

    pub fn set_organization_fields(&self, organization: i64, values: &Value) -> Result<()> {
        self.checked("PATCH", &format!("/v2/organization/{organization}/custom-fields"), Some(values)).map(drop)
    }

    /// Runs a library script as SYSTEM; `parameters` is the string NinjaOne appends to the command line.
    pub fn run_script(&self, device: i64, script: i64, parameters: &str) -> Result<()> {
        let body = json!({"type": "SCRIPT", "id": script, "runAs": "system", "parameters": parameters});
        self.checked("POST", &format!("/v2/device/{device}/script/run"), Some(&body)).map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_matches_rfc_7636_appendix_b() {
        assert_eq!(pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn the_callback_yields_its_code_only_with_this_sign_ins_state() {
        assert_eq!(parse_callback("GET /?code=abc&state=s1 HTTP/1.1\r\n", "s1"), Callback::Code("abc".into()));
        assert!(matches!(parse_callback("GET /?code=abc&state=other HTTP/1.1\r\n", "s1"), Callback::Denied(_)));
        assert!(matches!(parse_callback("GET /?code=abc HTTP/1.1\r\n", "s1"), Callback::Denied(_)));
    }

    #[test]
    fn the_callback_reports_a_refusal_and_ignores_other_requests() {
        assert_eq!(
            parse_callback("GET /?error=access_denied&error_description=user%20said%20no HTTP/1.1", "s"),
            Callback::Denied("user said no".into())
        );
        assert_eq!(parse_callback("GET /favicon.ico HTTP/1.1", "s"), Callback::Other);
        assert_eq!(parse_callback("", "s"), Callback::Other);
    }

    #[test]
    fn a_device_override_beats_its_role_policy() {
        let device = |json| serde_json::from_value::<Device>(json).unwrap().effective_policy();
        assert_eq!(device(json!({"id": 1, "organizationId": 3, "rolePolicyId": 5})), Some(5));
        assert_eq!(device(json!({"id": 1, "organizationId": 3, "rolePolicyId": 5, "policyId": 9})), Some(9));
    }
}

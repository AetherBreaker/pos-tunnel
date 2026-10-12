# posctl Core and posctl-admin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the core `posctl` and `posctl-admin` share (config, ed25519 keys, the NinjaOne API with a browser sign-in, the six custom fields) and all of `posctl-admin` (`init`, `relay keygen`, `relay point`, `signing keygen`/`publish`, `operator add`/`remove`/`list`), plus `posctl`'s setup commands (`login`, `operator import`, `relay set`), so the admin can carry out deployment steps 1-4 of design section 12 and point one test POS at the relay.

**Architecture:** One Rust crate, `cli/`: a library (`posctl::config`, `keys`, `ninja`, `fleet`, `admin`, `bundle`) and two binaries, `posctl` and `posctl-admin`, which maturin packs into the one wheel. The NinjaOne client signs in with the authorization-code grant and PKCE through the tenant's Native client app (no client secret), keeps the refresh token in Windows Credential Manager, and trades it for an access token per command. Unit tests run against a fake NinjaOne (`fake.rs`); a Docker integration test runs the real relay container with the keys `posctl-admin` generates.

**Tech Stack:** Rust 2024 edition, clap 4, ureq 3, ssh-key 0.6 (ed25519, OpenSSH formats, bcrypt-pbkdf encryption), keyring-core 1 with windows-native-keyring-store 1, serde/toml/serde_json; pytest and Docker for the integration test; GitHub Actions.

**Spec:** `docs/design.md`, sections 3 (keys, the six custom fields), 4 (naming), 7.7 and 7.9 (the commands), 8 (config and the NinjaOne API), 11 (what the API showed) and 12 (deployment order). Where this plan and the design differ, this plan is newer and Task 6 brings the design up to date; the differences are under "Decisions this plan makes". `posctl`'s session commands (`connect`, `keepalive`, `status`, `close`, `rebuild`, `update`, `rekey`) are the next plan's.

**Provenance:** every file below ran green before this plan was written: on the throwaway branch `probe/posctl-admin`, `cargo test` 28 of 28 and clippy clean on `windows-latest`, the Docker integration test 4 of 4 on `ubuntu-latest`; against the real NinjaOne tenant, `posctl-admin init` (sign-in, policy `Store POS Windows 11` id 35, `Install-PosTunnel` id 93, `Invoke-PosTunnel` id 94) and `signing publish` (created the six fields, wrote `posTunnelSigner` on organization 3). The code blocks are those files verbatim.

**Already on this branch:** `c3c633d fix(test): wait for the lock in the Watch lock test` (a CI race in the POS suite found while probing). Nothing in this plan touches it.

## Global Constraints

- Work on `feat/posctl`. `cargo` commands run from the repository root (the workspace); this machine's `CARGO_TARGET_DIR` is `D:\cargo-target`, so binaries land in `D:\cargo-target\debug`, not `target\`.
- Every Rust change passes `cargo test`, `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` (rustfmt defaults; no `rustfmt.toml`). CI's `cli` job runs the first two on `windows-latest`.
- The Python test follows the repo's ruff and pyright config (2-space indent, line length 135); run them with `uv run`.
- Comments carry reasoning, densely (`AGENTS.md`, "Comment Density"). No single-use helpers of 4 lines or fewer, and no single-use functions at all unless a lint forces one (`AGENTS.md`, "Abstraction Conventions"); that is why `posctl-admin`'s commands live inline in `main`.
- In prose, say "private key"/"public key", never "host key".
- `.env` holds live NinjaOne values; never print it. Read single values with `grep -m1 '^NAME=' .env | cut -d= -f2-` into a variable, never echo them.
- Nothing in this plan runs a script on a POS. The only NinjaOne writes are in Task 6, Step 4, which the user has approved: creating the six custom fields (already done by the probe, so a no-op) and writing `posTunnelSigner` on organization 3 (the same value it holds).
- Conventional Commits, scope `cli` (or `ci`, `docs`, `test`), every message ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Branch testing (`AGENTS.md`): run each task's own tests while working and the task's full check at its end; the Docker integration test only in Task 5 and Task 6.

**Check** (Git Bash, repository root; run at the end of every task). Expected: the test summary line the task names, and nothing else from clippy or fmt.

```bash
cargo test 2>&1 | grep -E "^test result: .* [1-9][0-9]* passed|FAILED|panicked|^error"
cargo clippy --all-targets -- -D warnings 2>&1 | grep -E "^(warning|error)" -A5
cargo fmt --check
```

**CI check** (Git Bash, after `git push`): waits for this commit's run and prints each job's verdict.

```bash
sha=$(git rev-parse HEAD)
until run=$(gh run list --commit "$sha" --workflow CI --limit 1 --json databaseId --jq '.[0].databaseId') && [ -n "$run" ]; do sleep 5; done
until [ "$(gh run view "$run" --json status --jq .status)" = completed ]; do sleep 15; done
gh run view "$run" --json jobs --jq '.jobs[] | "\(.name): \(.conclusion)"'
```

## Decisions this plan makes

Each was settled by a probe or by the user; Task 6 records them in the design.

1. **NinjaOne sign-in is the authorization-code grant with PKCE through a Native client app, with no client secret.** A client-credentials token can't run scripts (`403 user_context_required`), and a Web app's secret would travel in every operator's bundle. The Native app's redirect is fixed to `http://127.0.0.1`, any port, so `login` listens on one the OS picks. Refresh tokens don't rotate, so `login` stores one and every command trades it for an access token. The design's "prompts for the client ID and secret" is replaced.
2. **The refresh token lives in Windows Credential Manager** through `keyring-core` and `windows-native-keyring-store` (the `keyring` crate's v4 split its stores out; its v1-compatible default pulls in Linux D-Bus stores we don't need). Elsewhere it is a user-only file in the config dir.
3. **`posctl-admin init`** signs in, finds the POS policy and both library scripts by exact name, and writes `config.toml`, replacing design section 12's "write `config.toml`" by hand.
4. **`relay keygen <host>[:<port>]` always activates** the new key pair (the design's `--activate`): `posctl-admin` keeps one relay private key, so generating one and not pinning it has no use. `relay point` therefore takes no address.
5. **`relay point --device <DisplayName>`** runs `Install-PosTunnel -Force` on one POS only (the user's call, 2026-10-12: every device is in the one POS policy, and the policy configuration stays as it is). The device is resolved before any write, so a mistyped or offline one changes nothing.
6. **`signing publish`** writes the public key already in `pos/allowed_signers`: the release signing key exists, so deployment needs this rather than `signing keygen`. `signing keygen` passphrase-protects the key it makes.
7. **Creating a custom field sends `scope: NODE_GLOBAL`** beside `definitionScope`: NinjaOne refuses a create without it, deprecated or not. `ensure_fields` reads each created field back and refuses if NinjaOne stored a setting other than the one requested.
8. **The admin's operator public key is built in from `cli/admin.pub`**; `POSCTL_ADMIN_KEY` at build time overrides it, which the integration test uses to build with a key of its own.
9. **One crate, a library and two binaries.** `maturin build` (bindings `bin`) puts both executables in the one wheel; verified.

## Review Focus

1. **The browser's other requests during sign-in.** A browser fetches `/favicon.ico` or opens a speculative connection before the redirect. Expected: `login` answers or drops them and still takes the code, refusing one with another sign-in's `state`. Test: `ninja::tests::the_sign_in_listener_answers_other_requests_and_returns_the_code` (Task 2).
2. **A revoked or expired sign-in.** Expected: the command fails with NinjaOne's reason and says to run `posctl login`, not a bare HTTP error. Test: `ninja::tests::a_refused_token_request_reports_ninjaones_reason` (Task 2).
3. **A custom field someone edited in NinjaOne.** A fleet field made script-writable would let a POS repoint the fleet. Expected: refuse, naming the field and setting, and create nothing. Test: `fleet::tests::ensure_fields_refuses_a_changed_setting_and_creates_nothing` (Task 3).
4. **`relay point --device` with a mistyped or offline POS.** Expected: an error naming what was found, and no field written, no script run. Test: `fleet::tests::point_relay_with_a_mistyped_or_offline_device_changes_nothing` (Task 3).
5. **A passphrase-protected operator key.** Expected: `posctl-admin` still recognizes the admin, since an OpenSSH key file's public half is unencrypted. Test: `keys::tests::a_written_key_reads_back_with_the_same_public_key` (its encrypted case, Task 1).

---

## File Structure

| File | Responsibility |
| --- | --- |
| `cli/Cargo.toml` | Dependencies; the library and the two binaries |
| `cli/src/lib.rs` | The shared modules |
| `cli/src/config.rs` | `config.toml`, the config dir, `<host>[:<port>]`, user-only writes |
| `cli/src/keys.rs` | ed25519 key pairs: generate, OpenSSH text, public lines |
| `cli/src/ninja.rs` | Browser sign-in (PKCE), the refresh-token store, the API client |
| `cli/src/fake.rs` | Test-only fake NinjaOne |
| `cli/src/fleet.rs` | The six custom fields, POS lookup, fleet-field writes, `point_relay` |
| `cli/src/admin.rs` | `posctl-admin`'s files, the admin check, the operator list |
| `cli/src/bundle.rs` | The operator bundle |
| `cli/admin.pub` | The admin's operator public key (a placeholder until Task 6) |
| `cli/src/bin/posctl.rs` | `posctl` (moved from `cli/src/main.rs`): setup commands; session commands still stubs |
| `cli/src/bin/posctl-admin.rs` | `posctl-admin` |
| `tests/cli/test_relay_setup.py` | Docker: the real relay container with `posctl-admin`'s keys |
| `.github/workflows/ci.yml` | Gains the `cli-integration` job |
| `docs/design.md`, `README.md` | Task 6 |

---

### Task 1: Crate layout, config and keys

**Files:**
- Modify: `cli/Cargo.toml`; `Cargo.lock` (regenerated by cargo)
- Move: `cli/src/main.rs` → `cli/src/bin/posctl.rs` (unchanged until Task 5)
- Create: `cli/src/lib.rs`, `cli/src/config.rs`, `cli/src/keys.rs`

**Interfaces:**
- Produces (`posctl::config`): `Config { operator_key: PathBuf, ninjaone: NinjaOne, relay: Option<Relay> }` with `Config::path()`, `Config::load()`, `Config::save(&self)`; `NinjaOne { base_url, client_id: String, pos_policy_id, install_script_id, invoke_script_id: i64 }`; `Relay { host: String, port: u16, public_key: String }`; `DEFAULT_RELAY_PORT: u16 = 2222`; `config_home() -> Result<PathBuf>` (`POSCTL_CONFIG_HOME` overrides the platform config dir); `parse_host_port(&str) -> Result<(String, u16)>`; `write_private(&Path, &[u8]) -> Result<()>`.
- Produces (`posctl::keys`): `generate(comment) -> Result<PrivateKey>`, `public_line(&PublicKey) -> Result<String>` (`ssh-ed25519 <base64>`, no comment), `parse_public(&str) -> Result<String>`, `private_text(&PrivateKey, Option<&str>) -> Result<String>`, `write_private_key(&Path, &PrivateKey, Option<&str>)`, `public_of_file(&Path) -> Result<String>`.

- [x] **Step 1: Replace `cli/Cargo.toml` and move the binary**

`cli/Cargo.toml` (Task 5 adds the `posctl-admin` binary):

```toml
[package]
name = "posctl"
description = "On-demand SSH access to NinjaOne-managed POS machines through a relay"
version.workspace = true
edition.workspace = true
publish.workspace = true

[lib]
path = "src/lib.rs"

[[bin]]
name = "posctl"
path = "src/bin/posctl.rs"

[dependencies]
anyhow = "1"
base64 = "0.23.1"
clap = { version = "4", features = ["derive"] }
dirs = "7.0.0"
humantime = "2"
keyring-core = "1.0.0"
rpassword = "7.5.4"
serde = { version = "1.0.229", features = ["derive"] }
serde_json = "1.0.151"
sha2 = "0.11.0"
ssh-key = { version = "0.6.7", features = ["ed25519", "rand_core", "std", "encryption", "getrandom"], default-features = false }
toml = "1.1.8"
ureq = { version = "3.4.2", features = ["json"] }
url = "2.5.8"
webbrowser = "1.2.4"

[target."cfg(windows)".dependencies]
windows-native-keyring-store = "1.1.0"
```

```bash
mkdir -p cli/src/bin && git mv cli/src/main.rs cli/src/bin/posctl.rs && cargo fmt
```

`cargo fmt` only reorders the moved file's `use anyhow::{bail, Result};`, which predates rustfmt's 2024 import order.

`cli/src/lib.rs`:

```rust
//! The core `posctl` and `posctl-admin` share: config, keys, the NinjaOne API, and the fleet and admin
//! operations. Design: `docs/design.md`.

pub mod config;
pub mod keys;
```

- [x] **Step 2: Write the tests**

`cli/src/config.rs`, the tests alone for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_defaults_to_the_relay_port() {
        assert_eq!(
            parse_host_port("relay.example.com").unwrap(),
            ("relay.example.com".into(), 2222)
        );
        assert_eq!(
            parse_host_port("10.0.0.5:2200").unwrap(),
            ("10.0.0.5".into(), 2200)
        );
    }

    #[test]
    fn host_port_refuses_anything_install_would() {
        for bad in [
            "",
            ":2222",
            "relay:0",
            "relay:x",
            "re lay",
            "relay:70000",
            "relay/x",
        ] {
            assert!(parse_host_port(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn config_round_trips_through_toml() {
        let config = Config {
            operator_key: "C:/keys/operator".into(),
            ninjaone: NinjaOne {
                base_url: "https://us2.ninjarmm.com".into(),
                client_id: "abc".into(),
                pos_policy_id: 7,
                install_script_id: 93,
                invoke_script_id: 94,
            },
            relay: Some(Relay {
                host: "relay.example.com".into(),
                port: 2222,
                public_key: "ssh-ed25519 AAAA".into(),
            }),
        };
        assert_eq!(
            toml::from_str::<Config>(&toml::to_string(&config).unwrap()).unwrap(),
            config
        );
    }
}
```

`cli/src/keys.rs`, the tests alone for now (the last one needs `ssh-keygen` on `PATH`; Windows and the runners have it):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_written_key_reads_back_with_the_same_public_key() {
        let dir = std::env::temp_dir().join(format!("posctl-keys-{}", std::process::id()));
        let key = generate("test").unwrap();
        for (name, passphrase) in [("plain", None), ("encrypted", Some("pw"))] {
            write_private_key(&dir.join(name), &key, passphrase).unwrap();
            assert_eq!(
                public_of_file(&dir.join(name)).unwrap(),
                public_line(key.public_key()).unwrap()
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn public_lines_have_no_comment() {
        let line = public_line(generate("a comment").unwrap().public_key()).unwrap();
        assert!(
            line.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"),
            "{line}"
        );
        assert_eq!(line.split(' ').count(), 2);
        assert_eq!(parse_public(&format!("{line} someone@host")).unwrap(), line);
    }

    #[test]
    fn parse_public_refuses_other_keys_and_junk() {
        let rsa = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC7";
        for bad in ["", "ssh-ed25519", "ssh-ed25519 !!!", rsa] {
            assert!(parse_public(bad).is_err(), "{bad}");
        }
    }

    /// OpenSSH's `ssh-keygen` (which `poe sign-pos` signs with) reads an encrypted key this crate wrote.
    #[test]
    fn ssh_keygen_reads_an_encrypted_key() {
        let dir = std::env::temp_dir().join(format!("posctl-openssh-{}", std::process::id()));
        let key = generate("test").unwrap();
        write_private_key(&dir.join("k"), &key, Some("correct horse")).unwrap();
        let out = std::process::Command::new("ssh-keygen")
            .args(["-y", "-P", "correct horse", "-f"])
            .arg(dir.join("k"))
            .output()
            .unwrap();
        fs::remove_dir_all(&dir).unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            parse_public(&String::from_utf8(out.stdout).unwrap()).unwrap(),
            public_line(key.public_key()).unwrap()
        );
    }
}
```

- [x] **Step 3: Run them to watch them fail**

Run: `cargo test --lib 2>&1 | grep -E "^error" | head -5`
Expected: compile errors, the tests' `use super::*` finding nothing yet, such as `` error[E0422]: cannot find struct, variant or union type `Config` in this scope ``.

- [x] **Step 4: Write `config.rs`**

Insert above its tests module:

```rust
//! `posctl/config.toml` (design section 8) and where both binaries keep their files.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// The relay's published SSH port (design section 6.1).
pub const DEFAULT_RELAY_PORT: u16 = 2222;

/// Everything `posctl` needs besides the NinjaOne login. `posctl-admin init` writes it on the admin's
/// workstation, `posctl operator import` on the others.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub operator_key: PathBuf,
    pub ninjaone: NinjaOne,
    /// Absent until `posctl-admin relay keygen` or `posctl relay set`.
    pub relay: Option<Relay>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NinjaOne {
    /// `https://<region>.ninjarmm.com`, no trailing slash.
    pub base_url: String,
    /// The tenant's Native client app: PKCE, no secret (design section 11).
    pub client_id: String,
    /// A device whose effective policy is this one is a POS (design section 8).
    pub pos_policy_id: i64,
    pub install_script_id: i64,
    pub invoke_script_id: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Relay {
    pub host: String,
    pub port: u16,
    /// `ssh-ed25519 <base64>`, pinned in the generated `known_hosts`.
    pub public_key: String,
}

/// The platform config dir, or `POSCTL_CONFIG_HOME`: tests, and a second identity on one machine.
pub fn config_home() -> Result<PathBuf> {
    match std::env::var_os("POSCTL_CONFIG_HOME") {
        Some(dir) => Ok(dir.into()),
        None => dirs::config_dir().context("this platform has no config directory"),
    }
}

impl Config {
    pub fn path() -> Result<PathBuf> {
        Ok(config_home()?.join("posctl").join("config.toml"))
    }

    pub fn load() -> Result<Config> {
        let path = Config::path()?;
        let text = fs::read_to_string(&path).with_context(|| {
            format!(
                "no posctl config at {}: run `posctl operator import` (the admin: `posctl-admin init`)",
                path.display()
            )
        })?;
        toml::from_str(&text)
            .with_context(|| format!("{} is not a valid posctl config", path.display()))
    }

    pub fn save(&self) -> Result<()> {
        write_private(&Config::path()?, toml::to_string(self)?.as_bytes())
    }
}

/// `<host>[:<port>]`, the port defaulting to the relay's.
pub fn parse_host_port(value: &str) -> Result<(String, u16)> {
    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) => (
            host,
            port.parse()
                .with_context(|| format!("bad port in '{value}'"))?,
        ),
        None => (value, DEFAULT_RELAY_PORT),
    };
    // The same host pattern Install-PosTunnel accepts from the posTunnelRelay field.
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        || port == 0
    {
        bail!("expected <host>[:<port>], got '{value}'");
    }
    Ok((host.to_owned(), port))
}

/// Writes `bytes` to `path`, creating its directory. Unix gets mode 0600; on Windows the per-user
/// config dir already keeps other users out.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
    }
    #[cfg(not(unix))]
    fs::write(path, bytes)?;
    Ok(())
}
```

- [x] **Step 5: Write `keys.rs`**

Insert above its tests module:

```rust
//! ed25519 key pairs in OpenSSH's formats (design section 3).

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey, PublicKey};

use crate::config::write_private;

pub fn generate(comment: &str) -> Result<PrivateKey> {
    let mut key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
    key.set_comment(comment);
    Ok(key)
}

/// `ssh-ed25519 <base64>` without the comment: the form the fields, the config and `OPERATOR_KEYS` use.
pub fn public_line(key: &PublicKey) -> Result<String> {
    let text = key.to_openssh()?;
    Ok(text
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" "))
}

/// An ed25519 public key in OpenSSH's one-line form, comment allowed; returned without it.
pub fn parse_public(text: &str) -> Result<String> {
    let key = PublicKey::from_openssh(text.trim())
        .with_context(|| format!("'{text}' is not an OpenSSH public key"))?;
    if key.algorithm() != Algorithm::Ed25519 {
        bail!("'{text}' is not an ed25519 key");
    }
    public_line(&key)
}

/// The OpenSSH private key file's text, encrypted with `passphrase` if given.
pub fn private_text(key: &PrivateKey, passphrase: Option<&str>) -> Result<String> {
    let key = match passphrase {
        Some(passphrase) => key.encrypt(&mut OsRng, passphrase)?,
        None => key.clone(),
    };
    Ok(key.to_openssh(LineEnding::LF)?.to_string())
}

pub fn write_private_key(path: &Path, key: &PrivateKey, passphrase: Option<&str>) -> Result<()> {
    write_private(path, private_text(key, passphrase)?.as_bytes())
}

/// The public half of an OpenSSH private key file, readable even when the file is encrypted.
pub fn public_of_file(path: &Path) -> Result<String> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let key = PrivateKey::from_openssh(&text)
        .with_context(|| format!("{} is not an OpenSSH private key", path.display()))?;
    public_line(key.public_key())
}
```

- [x] **Step 6: Check and commit**

Run the check. Expected: `test result: ok. 7 passed`, nothing from clippy or fmt.

```bash
git add cli/Cargo.toml Cargo.lock cli/src
git commit -m "feat(cli): config and ed25519 keys, as a library beside the posctl binary

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: The NinjaOne client

**Files:**
- Create: `cli/src/fake.rs`, `cli/src/ninja.rs`
- Modify: `cli/src/lib.rs`

**Interfaces:**
- Consumes: `config::{config_home, write_private}` (the non-Windows token file).
- Produces (`posctl::ninja`): `login(base_url, client_id) -> Result<()>` (browser sign-in, stores the refresh token); `token_store::{save, load}`; `Api::connect(base_url, client_id) -> Result<Api>`, `Api::with_token(base_url, token)` (tests); `Api::get<T>`, `devices() -> Vec<Device>`, `policies()`, `scripts() -> Vec<Named>`, `field_definition(name) -> Option<FieldDefinition>`, `create_field(&Value)`, `set_organization_fields(org, &Value)`, `run_script(device, script, parameters)`; `Device { id, display_name: Option<String>, organization_id, offline, policy_id, role_policy_id }` with `effective_policy()`; `Named { id, name }`; `FieldDefinition { name, definition_scope: Vec<String>, script_permission, api_permission: Option<String> }`.
- Produces (`crate::fake`, tests only): `Fake::start(|method, path, body| (status, reply))`, `fake.url`, `fake.requests_to(method, path) -> Vec<Value>`.

- [x] **Step 1: Write the fake NinjaOne**

`cli/src/fake.rs`:

```rust
//! A fake NinjaOne for tests: answers each request from a handler and records it.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use serde_json::Value;

type Handler = dyn Fn(&str, &str, &Value) -> (u16, Value) + Send + 'static;

pub struct Fake {
    pub url: String,
    requests: Arc<Mutex<Vec<(String, String, Value)>>>,
}

impl Fake {
    /// Serves until the test process ends; `handler` gets method, path with query, and the JSON body
    /// (`Null` when there is none) and returns the status and JSON reply.
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
                let text = if reply.is_null() {
                    String::new()
                } else {
                    reply.to_string()
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
```

`cli/src/lib.rs`:

```rust
//! The core `posctl` and `posctl-admin` share: config, keys, the NinjaOne API, and the fleet and admin
//! operations. Design: `docs/design.md`.

pub mod config;
pub mod keys;
pub mod ninja;

#[cfg(test)]
mod fake;
```

- [x] **Step 2: Write the tests**

`cli/src/ninja.rs`, the tests alone for now:

```rust
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
    fn devices_are_read_a_page_at_a_time() {
        let fake = crate::fake::Fake::start(|_, path, _| {
            let page: Vec<Value> = match path {
                "/v2/devices?pageSize=1000" => (1..=1000)
                    .map(|id| json!({"id": id, "organizationId": 3}))
                    .collect(),
                "/v2/devices?pageSize=1000&after=1000" => {
                    vec![json!({"id": 1001, "organizationId": 3})]
                }
                _ => vec![],
            };
            (200, Value::Array(page))
        });
        assert_eq!(
            Api::with_token(&fake.url, "t").devices().unwrap().len(),
            1001
        );
        // The second page starts after the first page's last device, and there is no third.
        assert_eq!(
            fake.requests_to("GET", "/v2/devices?pageSize=1000&after=1000")
                .len(),
            1
        );
        assert!(
            fake.requests_to("GET", "/v2/devices?pageSize=1000&after=1001")
                .is_empty()
        );
    }
}
```

- [x] **Step 3: Run them to watch them fail**

Run: `cargo test --lib ninja 2>&1 | grep -E "^error" | head -5`
Expected: compile errors, the tests' `use super::*` finding nothing yet, such as `` error: cannot find macro `json` in this scope ``.

- [x] **Step 4: Write `ninja.rs`**

Insert above its tests module:

```rust
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

fn agent() -> Agent {
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
        Ok(keyring_core::Entry::new(
            "posctl",
            "ninjaone-refresh-token",
        )?)
    }

    #[cfg(windows)]
    pub fn save(token: &str) -> Result<()> {
        Ok(entry()?.set_password(token)?)
    }

    #[cfg(windows)]
    pub fn load() -> Result<String> {
        entry()?
            .get_password()
            .context("not signed in to NinjaOne: run `posctl login`")
    }

    #[cfg(not(windows))]
    fn path() -> Result<std::path::PathBuf> {
        Ok(crate::config::config_home()?
            .join("posctl")
            .join("refresh_token"))
    }

    #[cfg(not(windows))]
    pub fn save(token: &str) -> Result<()> {
        crate::config::write_private(&path()?, token.as_bytes())
    }

    #[cfg(not(windows))]
    pub fn load() -> Result<String> {
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

impl Api {
    pub fn connect(base_url: &str, client_id: &str) -> Result<Api> {
        let refresh = token_store::load()?;
        let tokens: Value = token_request(
            base_url,
            &[
                ("grant_type", "refresh_token"),
                ("client_id", client_id),
                ("refresh_token", &refresh),
            ],
        )
        .context("refreshing the NinjaOne sign-in failed; run `posctl login`")?;
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

    /// Every device, a page at a time (`after` is the last device ID of the previous page).
    pub fn devices(&self) -> Result<Vec<Device>> {
        let mut devices: Vec<Device> = Vec::new();
        loop {
            let after = devices
                .last()
                .map(|d| format!("&after={}", d.id))
                .unwrap_or_default();
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
}
```

- [x] **Step 5: Check and commit**

Run the check. Expected: `test result: ok. 14 passed`, nothing from clippy or fmt.

```bash
git add cli/src
git commit -m "feat(cli): NinjaOne client with a browser sign-in (PKCE, no client secret)

Running a script needs a user's token, so login uses the authorization-code
grant through the tenant's Native client app, on a loopback port the OS picks.
The refresh token is kept in Windows Credential Manager.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: The custom fields and fleet operations

**Files:**
- Create: `cli/src/fleet.rs`
- Modify: `cli/src/lib.rs`

**Interfaces:**
- Consumes: `ninja::{Api, Device, FieldDefinition}`, `config::NinjaOne`, `fake::Fake`.
- Produces (`posctl::fleet`): `FIELDS: [Field; 6]`; `ensure_fields(&Api) -> Result<Vec<&str>>` (the names it created); `pos_devices(&Api, policy) -> Result<Vec<Device>>`; `find_pos(&Api, policy, name) -> Result<Device>` (the next plan's `connect` resolves devices with it); `set_fleet_fields(&Api, policy, &Value) -> Result<Vec<i64>>` (the organizations written); `point_relay(&Api, &NinjaOne, address, public_key, device: Option<&str>) -> Result<Pointed>`; `Pointed { organizations: Vec<i64>, ran, offline: Vec<String> }`.

- [x] **Step 1: Write the tests**

`cli/src/lib.rs`:

```rust
//! The core `posctl` and `posctl-admin` share: config, keys, the NinjaOne API, and the fleet and admin
//! operations. Design: `docs/design.md`.

pub mod config;
pub mod fleet;
pub mod keys;
pub mod ninja;

#[cfg(test)]
mod fake;
```

`cli/src/fleet.rs`, the tests alone for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::Fake;

    fn devices() -> Value {
        json!([
            {"id": 1, "displayName": "POS 000 Test", "organizationId": 3, "rolePolicyId": 7, "offline": false},
            {"id": 2, "displayName": "POS 001", "organizationId": 3, "rolePolicyId": 7, "offline": true},
            {"id": 3, "displayName": "Office PC", "organizationId": 4, "rolePolicyId": 8, "offline": false},
            {"id": 4, "displayName": "POS 900", "organizationId": 5, "rolePolicyId": 8, "policyId": 7, "offline": false},
        ])
    }

    /// A tenant whose six fields already exist as they should, with `devices()`; it accepts every write.
    fn tenant() -> Fake {
        Fake::start(|method, path, _| {
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
                ("GET", None) => (200, devices()),
                _ => (204, Value::Null),
            }
        })
    }

    fn ninja() -> NinjaOne {
        NinjaOne {
            base_url: String::new(),
            client_id: String::new(),
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
    fn fleet_fields_go_to_each_organization_holding_a_pos_once() {
        let fake = tenant();
        let values = json!({"posTunnelSigner": "ssh-ed25519 AAAA"});
        let organizations = set_fleet_fields(&Api::with_token(&fake.url, "t"), 7, &values).unwrap();
        assert_eq!(organizations, vec![3, 5]);
        assert_eq!(
            fake.requests_to("PATCH", "/v2/organization/3/custom-fields"),
            vec![values.clone()]
        );
        assert_eq!(
            fake.requests_to("PATCH", "/v2/organization/5/custom-fields"),
            vec![values]
        );
        assert!(
            fake.requests_to("PATCH", "/v2/organization/4/custom-fields")
                .is_empty()
        );
    }

    #[test]
    fn find_pos_matches_one_pos_exactly() {
        let fake = Fake::start(|_, _, _| {
            let mut all = devices();
            let list = all.as_array_mut().unwrap();
            list.push(
                json!({"id": 5, "displayName": "POS 001", "organizationId": 3, "rolePolicyId": 7}),
            );
            list.push(json!({"id": 6, "displayName": "pos 000 test", "organizationId": 3, "rolePolicyId": 8}));
            (200, all)
        });
        let api = Api::with_token(&fake.url, "t");
        assert_eq!(find_pos(&api, 7, "POS 000 Test").unwrap().id, 1);
        assert_eq!(find_pos(&api, 7, "POS 900").unwrap().id, 4);
        let error = |name| find_pos(&api, 7, name).unwrap_err().to_string();
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
                organizations: vec![3, 5],
                ran: vec!["POS 000 Test".into(), "POS 900".into()],
                offline: vec!["POS 001".into()],
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
            for org in [3, 5] {
                let path = format!("/v2/organization/{org}/custom-fields");
                assert!(fake.requests_to("PATCH", &path).is_empty(), "{device}");
            }
            for id in 1..=4 {
                let path = format!("/v2/device/{id}/script/run");
                assert!(fake.requests_to("POST", &path).is_empty(), "{device}");
            }
        }
    }
}
```

- [x] **Step 2: Run them to watch them fail**

Run: `cargo test --lib fleet 2>&1 | grep -E "^error" | head -5`
Expected: compile errors, the tests' `use super::*` finding nothing yet, such as `` error: cannot find macro `json` in this scope ``.

- [x] **Step 3: Write `fleet.rs`**

Insert above its tests module:

```rust
//! The six custom fields and the fleet-wide NinjaOne operations of `posctl-admin` (design sections 3, 7.9).

use std::collections::BTreeSet;

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
    /// to scripts, either of which stops a POS writing it (design section 3).
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
        // NODE_GLOBAL makes a global field (design section 3), as opposed to a role field.
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

/// The POSes: devices whose effective policy is the POS policy (design section 8).
pub fn pos_devices(api: &Api, pos_policy: i64) -> Result<Vec<Device>> {
    Ok(api
        .devices()?
        .into_iter()
        .filter(|device| device.effective_policy() == Some(pos_policy))
        .collect())
}

/// The one POS whose display name is exactly `name` (case-sensitive, design section 4). No match or
/// several is an error naming what was found.
pub fn find_pos(api: &Api, pos_policy: i64, name: &str) -> Result<Device> {
    let poses = pos_devices(api, pos_policy)?;
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

/// Writes fleet field values on every organization that holds a POS, after `ensure_fields`. A POS reads
/// its organization's value (design section 3). Returns those organizations.
pub fn set_fleet_fields(api: &Api, pos_policy: i64, values: &Value) -> Result<Vec<i64>> {
    ensure_fields(api)?;
    let organizations: BTreeSet<i64> = pos_devices(api, pos_policy)?
        .iter()
        .map(|device| device.organization_id)
        .collect();
    if organizations.is_empty() {
        bail!(
            "no device has the POS policy, so there is no organization to write the fleet fields on"
        );
    }
    for &organization in &organizations {
        api.set_organization_fields(organization, values)?;
    }
    Ok(organizations.into_iter().collect())
}

/// What `relay point` did.
#[derive(Debug, PartialEq)]
pub struct Pointed {
    /// The organizations whose fleet relay fields were written.
    pub organizations: Vec<i64>,
    /// The POSes `Install-PosTunnel -Force` was started on.
    pub ran: Vec<String>,
    /// The offline POSes skipped; they converge at their next scheduled install.
    pub offline: Vec<String>,
}

/// `posctl-admin relay point`: writes the fleet relay fields, then starts `Install-PosTunnel -Force` on
/// every online POS at once, or on `device` alone (a test POS, by exact display name). `device` is
/// resolved first, so a mistyped or offline one changes nothing.
pub fn point_relay(
    api: &Api,
    ninja: &NinjaOne,
    address: &str,
    public_key: &str,
    device: Option<&str>,
) -> Result<Pointed> {
    let target = device
        .map(|name| find_pos(api, ninja.pos_policy_id, name))
        .transpose()?;
    if let Some(target) = &target
        && target.offline
    {
        bail!(
            "{} is offline",
            target.display_name.as_deref().unwrap_or_default()
        );
    }
    let values = json!({"posTunnelRelay": address, "posTunnelRelayServerKey": public_key});
    let organizations = set_fleet_fields(api, ninja.pos_policy_id, &values)?;
    let targets = match target {
        Some(target) => vec![target],
        None => pos_devices(api, ninja.pos_policy_id)?,
    };
    let (mut ran, mut offline) = (Vec::new(), Vec::new());
    for device in targets {
        let name = device
            .display_name
            .clone()
            .unwrap_or_else(|| format!("device {}", device.id));
        if device.offline {
            offline.push(name);
        } else {
            api.run_script(device.id, ninja.install_script_id, "-Force")?;
            ran.push(name);
        }
    }
    Ok(Pointed {
        organizations,
        ran,
        offline,
    })
}
```

- [x] **Step 4: Check and commit**

Run the check. Expected: `test result: ok. 22 passed`, nothing from clippy or fmt.

```bash
git add cli/src
git commit -m "feat(cli): the six custom fields, POS lookup and relay point

ensure_fields creates missing fields with the settings design section 3 sets
(scope NODE_GLOBAL, which NinjaOne requires), reads each back, and refuses one
someone changed. point_relay resolves --device before writing anything.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: posctl-admin's state and the operator bundle

**Files:**
- Create: `cli/src/admin.rs`, `cli/src/bundle.rs`, `cli/admin.pub`
- Modify: `cli/src/lib.rs`

**Interfaces:**
- Consumes: `config::{Config, config_home, write_private}`, `keys`.
- Produces (`posctl::admin`): `ADMIN_KEY: &str`; `require_admin(&Path) -> Result<()>`; `dir()`, `relay_key_path()`, `signing_key_path() -> Result<PathBuf>`; `relay_env_line(&str) -> String`; `Operators { operators: BTreeMap<String, String> }` with `load()`, `save()`, `add(name, public_key)`, `remove(name, admin_key)`, `env_line()`; `check_operator_name(&str) -> Result<()>`.
- Produces (`posctl::bundle`): `Bundle { operator_key: String, config: Config }` with `encode() -> Result<String>`, `Bundle::decode(&str) -> Result<Bundle>`.

- [x] **Step 1: A placeholder admin key**

`admin.rs` builds in `cli/admin.pub`; Task 6 replaces it with the admin's own. Generate a throwaway key pair outside the repository and keep only its public key:

```bash
dir=$(mktemp -d) && ssh-keygen -q -t ed25519 -N "" -C "" -f "$dir/placeholder" && cut -d' ' -f1,2 "$dir/placeholder.pub" > cli/admin.pub && rm -r "$dir"
```

- [x] **Step 2: Write the tests**

`cli/src/lib.rs`:

```rust
//! The core `posctl` and `posctl-admin` share: config, keys, the NinjaOne API, and the fleet and admin
//! operations. Design: `docs/design.md`.

pub mod admin;
pub mod bundle;
pub mod config;
pub mod fleet;
pub mod keys;
pub mod ninja;

#[cfg(test)]
mod fake;
```

`cli/src/admin.rs`, the tests alone for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_keys_line_lists_name_and_bare_base64() {
        let mut operators = Operators::default();
        operators
            .operators
            .insert("bob".into(), "ssh-ed25519 BBBB".into());
        operators
            .operators
            .insert("alice".into(), "ssh-ed25519 AAAA".into());
        assert_eq!(operators.env_line(), "OPERATOR_KEYS=alice=AAAA,bob=BBBB");
    }

    #[test]
    fn operators_refuse_a_duplicate_a_bad_name_and_removing_the_admin() {
        let mut operators = Operators::default();
        operators.add("admin", "ssh-ed25519 AAAA".into()).unwrap();
        operators.add("bob", "ssh-ed25519 BBBB".into()).unwrap();
        assert!(operators.add("bob", "ssh-ed25519 CCCC".into()).is_err());
        assert!(operators.add("a b", "ssh-ed25519 CCCC".into()).is_err());
        let error = operators
            .remove("admin", "ssh-ed25519 AAAA")
            .unwrap_err()
            .to_string();
        assert!(error.contains("lock you out"), "{error}");
        assert!(operators.remove("carol", "ssh-ed25519 AAAA").is_err());
        operators.remove("bob", "ssh-ed25519 AAAA").unwrap();
        assert_eq!(operators.env_line(), "OPERATOR_KEYS=admin=AAAA");
    }

    #[test]
    fn relay_line_is_base64_of_the_key_file() {
        assert_eq!(
            relay_env_line("-----BEGIN-----\n"),
            "RELAY_SSH_PRIVATE_KEY=LS0tLS1CRUdJTi0tLS0tCg=="
        );
    }

    #[test]
    fn operator_names_follow_the_relay() {
        check_operator_name("jacob.ogden_2-x").unwrap();
        for bad in ["", "a b", "a=b", "a,b", "é"] {
            assert!(check_operator_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn only_the_admin_key_passes() {
        let dir = std::env::temp_dir().join(format!("posctl-admin-{}", std::process::id()));
        let other = keys::generate("other").unwrap();
        keys::write_private_key(&dir.join("other"), &other, None).unwrap();
        let error = require_admin(&dir.join("other")).unwrap_err().to_string();
        assert!(error.contains("not the admin's operator key"), "{error}");
        fs::remove_dir_all(dir).unwrap();
    }
}
```

`cli/src/bundle.rs`, the tests alone for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NinjaOne, Relay};

    #[test]
    fn a_bundle_round_trips_and_junk_is_refused() {
        let bundle = Bundle {
            operator_key:
                "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n"
                    .into(),
            config: Config {
                operator_key: "unused".into(),
                ninjaone: NinjaOne {
                    base_url: "https://us2.ninjarmm.com".into(),
                    client_id: "id".into(),
                    pos_policy_id: 7,
                    install_script_id: 93,
                    invoke_script_id: 94,
                },
                relay: Some(Relay {
                    host: "relay.example.com".into(),
                    port: 2222,
                    public_key: "ssh-ed25519 AAAA".into(),
                }),
            },
        };
        assert_eq!(
            Bundle::decode(&format!(" {}\n", bundle.encode().unwrap())).unwrap(),
            bundle
        );
        assert!(Bundle::decode("not base64!").is_err());
        assert!(Bundle::decode("aGVsbG8=").is_err());
    }
}
```

- [x] **Step 3: Run them to watch them fail**

Run: `cargo test --lib 2>&1 | grep -E "^error" | head -5`
Expected: compile errors, the tests' `use super::*` finding nothing yet, such as `` error[E0433]: cannot find module or crate `keys` in this scope ``.

- [x] **Step 4: Write `admin.rs` and `bundle.rs`**

Insert above `admin.rs`'s tests module:

```rust
//! `posctl-admin`'s own files (design section 7.9) and its admin check.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::config::{config_home, write_private};
use crate::keys;

/// The admin's operator public key, built into the binary: `cli/admin.pub`, or `POSCTL_ADMIN_KEY` at
/// build time, which CI's integration job uses to build with a key of its own.
pub const ADMIN_KEY: &str = match option_env!("POSCTL_ADMIN_KEY") {
    Some(key) => key,
    None => include_str!("../admin.pub"),
};

/// Runs only for the admin: keeps these commands out of reach of an agent working through another
/// operator's `posctl`. Not a security boundary; the admin's NinjaOne sign-in is what can change the
/// fleet (design section 7.9).
pub fn require_admin(operator_key: &Path) -> Result<()> {
    if keys::public_of_file(operator_key)? != keys::parse_public(ADMIN_KEY)? {
        bail!(
            "posctl-admin is for the admin only: {} is not the admin's operator key",
            operator_key.display()
        );
    }
    Ok(())
}

pub fn dir() -> Result<PathBuf> {
    Ok(config_home()?.join("posctl-admin"))
}

/// The relay's SSH server private key, as last generated (the active one).
pub fn relay_key_path() -> Result<PathBuf> {
    Ok(dir()?.join("relay_key"))
}

pub fn signing_key_path() -> Result<PathBuf> {
    Ok(dir()?.join("signing_key"))
}

/// The relay's `RELAY_SSH_PRIVATE_KEY` line: base64 of the OpenSSH private key file (design section 6.1).
pub fn relay_env_line(private_key_text: &str) -> String {
    format!(
        "RELAY_SSH_PRIVATE_KEY={}",
        STANDARD.encode(private_key_text)
    )
}

/// The operators the relay lets in, the admin included: `operators.toml`, name to public key. Only
/// public keys are kept here (design section 7.9).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Operators {
    pub operators: BTreeMap<String, String>,
}

impl Operators {
    fn path() -> Result<PathBuf> {
        Ok(dir()?.join("operators.toml"))
    }

    pub fn load() -> Result<Operators> {
        let path = Operators::path()?;
        match fs::read_to_string(&path) {
            Ok(text) => {
                toml::from_str(&text).with_context(|| format!("{} is not valid", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Operators::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self) -> Result<()> {
        write_private(&Operators::path()?, toml::to_string(self)?.as_bytes())
    }

    pub fn add(&mut self, name: &str, public_key: String) -> Result<()> {
        check_operator_name(name)?;
        if self.operators.contains_key(name) {
            bail!("there is already an operator named '{name}'");
        }
        self.operators.insert(name.to_owned(), public_key);
        Ok(())
    }

    /// Refuses to remove the admin's own key, which would lock the admin out of the relay.
    pub fn remove(&mut self, name: &str, admin_key: &str) -> Result<()> {
        match self.operators.get(name) {
            None => bail!("no operator named '{name}'"),
            Some(key) if key == admin_key => {
                bail!("'{name}' is the admin: removing it would lock you out of the relay")
            }
            Some(_) => {
                self.operators.remove(name);
                Ok(())
            }
        }
    }

    /// The relay's `OPERATOR_KEYS` line: `<name>=<ed25519 base64>`, comma-separated (design section 6.1).
    pub fn env_line(&self) -> String {
        let entries: Vec<String> = self
            .operators
            .iter()
            .map(|(name, key)| {
                format!(
                    "{name}={}",
                    key.split_whitespace().nth(1).unwrap_or_default()
                )
            })
            .collect();
        format!("OPERATOR_KEYS={}", entries.join(","))
    }
}

/// The relay's operator-name pattern (its `keys.OPERATOR_NAME`).
pub fn check_operator_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
    {
        bail!("an operator name is letters, digits, '.', '_' and '-' only, got '{name}'");
    }
    Ok(())
}
```

Insert above `bundle.rs`'s tests module:

```rust
//! The operator bundle (design section 7.9): one line `posctl-admin operator add` prints and
//! `posctl operator import` reads, base64 of a small TOML document holding the new operator's private
//! key and the admin's config. It holds a private key, so it travels like a password.

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::config::Config;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Bundle {
    /// The OpenSSH private key file's text.
    pub operator_key: String,
    /// The admin's config; `import` replaces `operator_key` with where it stores the key.
    pub config: Config,
}

impl Bundle {
    pub fn encode(&self) -> Result<String> {
        Ok(STANDARD.encode(toml::to_string(self)?))
    }

    pub fn decode(line: &str) -> Result<Bundle> {
        let bytes = STANDARD
            .decode(line.trim())
            .context("not an operator bundle (bad base64)")?;
        toml::from_str(std::str::from_utf8(&bytes)?).context("not an operator bundle")
    }
}
```

- [x] **Step 5: Check and commit**

Run the check. Expected: `test result: ok. 28 passed`, nothing from clippy or fmt.

```bash
git add cli/src cli/admin.pub
git commit -m "feat(cli): posctl-admin's admin check, operator list and operator bundle

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: The binaries and the relay integration test

**Files:**
- Modify: `cli/Cargo.toml` (the `posctl-admin` binary), `.github/workflows/ci.yml` (a job)
- Replace: `cli/src/bin/posctl.rs`
- Create: `cli/src/bin/posctl-admin.rs`, `tests/cli/test_relay_setup.py`

**Interfaces:**
- Consumes: everything above.
- Produces: `posctl login | operator import | relay set <host>[:<port>] <public key>`; `posctl-admin init --base-url --client-id --policy --operator-key --name | relay keygen <host>[:<port>] | relay point [--device <name>] | signing keygen | signing publish | operator add <name> | operator remove <name> | operator list`. `relay keygen` prints the `RELAY_SSH_PRIVATE_KEY=` line on stdout; `operator add` prints the bundle, then the `OPERATOR_KEYS=` line.

- [x] **Step 1: Write the integration test**

It builds both binaries with its own admin key (`POSCTL_ADMIN_KEY`), has `posctl-admin` generate the relay key pair and a second operator, starts the relay submodule's own test image with those lines, and logs in as each operator with the relay's public key pinned. `tests/cli/test_relay_setup.py`:

```python
# Standard library imports
import json
import os
import socket
import subprocess
import time
import tomllib
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

# Third party imports
import pytest

if TYPE_CHECKING:
  # Standard library imports
  from collections.abc import Callable

pytestmark = pytest.mark.skipif(os.environ.get("POS_TUNNEL_DOCKER") != "1", reason="Docker tests: set POS_TUNNEL_DOCKER=1")
ROOT = Path(__file__).resolve().parents[2]
RELAY = ROOT / "relay"
EXE = ".exe" if os.name == "nt" else ""


def sh(
  *args: str,
  check: bool = True,
  timeout: int = 900,
  cwd: Path | None = None,
  env: dict[str, str] | None = None,
  stdin: str | None = None,
) -> subprocess.CompletedProcess[str]:
  return subprocess.run(list(args), capture_output=True, text=True, check=check, timeout=timeout, cwd=cwd, env=env, input=stdin)


def wait_for(what: str, condition: Callable[[], bool], timeout: float) -> None:
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    if condition():
      return
    time.sleep(2)
  pytest.fail(f"timed out after {timeout:g} s waiting for {what}")


def free_port() -> int:
  with socket.socket() as s:
    s.bind(("127.0.0.1", 0))
    return s.getsockname()[1]


def config_of(home: Path) -> dict[str, Any]:
  return tomllib.loads((home / "posctl" / "config.toml").read_text(encoding="utf-8"))


class Setup:
  """`posctl-admin` building a relay's configuration, and the real relay container running with it."""

  def __init__(self, tmp: Path) -> None:
    self.tag = uuid.uuid4().hex[:8]
    self.port = free_port()
    self.admin_home, self.bob_home = tmp / "admin", tmp / "bob"
    self.network, self.relay, self.logserver = f"setup-net-{self.tag}", f"setup-relay-{self.tag}", f"setup-logs-{self.tag}"
    self.volume = f"setup-data-{self.tag}"
    self.bundle = ""
    admin_key = tmp / "admin_key"
    sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", str(admin_key))
    admin_pub = " ".join(admin_key.with_suffix(".pub").read_text(encoding="utf-8").split()[:2])
    # posctl-admin runs only with the admin key built into it, so build one with this test's.
    sh("cargo", "build", "--bins", cwd=ROOT, env={**os.environ, "POSCTL_ADMIN_KEY": admin_pub})
    target = json.loads(sh("cargo", "metadata", "--format-version", "1", "--no-deps", cwd=ROOT).stdout)["target_directory"]
    self.bin = Path(target) / "debug"
    # What `posctl-admin init` writes after signing in to NinjaOne, which this test has no tenant for.
    config = self.admin_home / "posctl" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text(
      f"operator_key = {json.dumps(str(admin_key))}\n\n[ninjaone]\n"
      'base_url = "https://example.invalid"\nclient_id = "c"\npos_policy_id = 1\ninstall_script_id = 2\ninvoke_script_id = 3\n',
      encoding="utf-8",
    )
    (self.admin_home / "posctl-admin").mkdir()
    (self.admin_home / "posctl-admin" / "operators.toml").write_text(f'[operators]\nadmin = "{admin_pub}"\n', encoding="utf-8")

  def run(self, binary: str, *args: str, home: Path, stdin: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "POSCTL_CONFIG_HOME": str(home)}
    return sh(str(self.bin / f"{binary}{EXE}"), *args, env=env, stdin=stdin, check=check, timeout=60)

  def up(self, relay_line: str, operators_line: str) -> None:
    sh("docker", "build", "-q", "-f", "tests/integration/Dockerfile", "-t", "pos-tunnel-relay:test", ".", cwd=RELAY)
    sh("docker", "build", "-q", "-f", "tests/integration/logserver.Dockerfile", "-t", "pos-tunnel-relay-logs:test", ".", cwd=RELAY)
    sh("docker", "network", "create", self.network)
    sh("docker", "volume", "create", self.volume)
    # -i keeps the log server's stdin open: it shuts down when stdin closes.
    sh(
      "docker",
      "run",
      "-d",
      "-i",
      "--name",
      self.logserver,
      "--network",
      self.network,
      "--network-alias",
      "logserver",
      "pos-tunnel-relay-logs:test",
    )
    # The relay exits if the log server isn't listening yet (aeth_ext's startup probe).
    wait_for("the log server", lambda: '"log_port"' in sh("docker", "logs", self.logserver).stdout, timeout=60)
    sh(
      "docker", "run", "-d", "--name", self.relay, "--network", self.network, "-p", f"127.0.0.1:{self.port}:2222",
      "-v", f"{self.volume}:/app/persisted_data",
      "-e", relay_line, "-e", operators_line,
      "-e", "ALERTS_EMAIL_PWD=unused", "-e", "LOG_CONN_HOST=logserver", "-e", "LOG_CONN_PORT=9020",
      "pos-tunnel-relay:test",
    )  # fmt: skip

  def down(self) -> None:
    for name in (self.relay, self.logserver):
      sh("docker", "rm", "-f", name, check=False)
    sh("docker", "network", "rm", self.network, check=False)
    sh("docker", "volume", "rm", self.volume, check=False)

  def ctl_status(self, home: Path) -> subprocess.CompletedProcess[str]:
    """`tunnelctl status` as the operator whose posctl config is in `home`, the relay key pinned from that config."""
    config = config_of(home)
    known_hosts = home / "known_hosts"
    known_hosts.write_text(f"[127.0.0.1]:{self.port} {config['relay']['public_key']}\n", encoding="utf-8")
    return sh(
      "ssh", "-F", "none", "-p", str(self.port), "-i", config["operator_key"], "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
      "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}", "ctl@127.0.0.1", "tunnelctl", "status",
      check=False, timeout=30,
    )  # fmt: skip


@pytest.fixture(scope="module")
def setup(tmp_path_factory: pytest.TempPathFactory):
  s = Setup(tmp_path_factory.mktemp("setup"))
  try:
    relay_line = s.run("posctl-admin", "relay", "keygen", f"127.0.0.1:{s.port}", home=s.admin_home).stdout.strip()
    s.bundle, operators_line = s.run("posctl-admin", "operator", "add", "bob", home=s.admin_home).stdout.splitlines()
    s.up(relay_line, operators_line)
    wait_for("the relay", lambda: s.ctl_status(s.admin_home).returncode == 0, timeout=120)
    yield s
  finally:
    if os.environ.get("POS_TUNNEL_KEEP") != "1":
      s.down()


def test_the_admin_reaches_tunnelctl_with_the_relay_key_pinned(setup: Setup):
  result = setup.ctl_status(setup.admin_home)

  assert result.returncode == 0, result.stderr
  assert json.loads(result.stdout) == []


def test_an_added_operator_imports_the_bundle_and_reaches_tunnelctl(setup: Setup):
  setup.run("posctl", "operator", "import", home=setup.bob_home, stdin=setup.bundle + "\n")

  result = setup.ctl_status(setup.bob_home)

  assert result.returncode == 0, result.stderr
  assert json.loads(result.stdout) == []


def test_posctl_admin_refuses_anyone_but_the_admin(setup: Setup):
  result = setup.run("posctl-admin", "operator", "list", home=setup.bob_home, check=False)

  assert result.returncode != 0
  assert "not the admin's operator key" in result.stderr


def test_relay_set_repoints_an_operator(setup: Setup):
  relay_key = config_of(setup.admin_home)["relay"]["public_key"]

  setup.run("posctl", "relay", "set", "relay.example.com", *relay_key.split(), home=setup.bob_home)

  assert config_of(setup.bob_home)["relay"] == {"host": "relay.example.com", "port": 2222, "public_key": relay_key}
```

- [x] **Step 2: Run it to watch it fail**

Needs Docker and the relay submodule (`git submodule update --init relay`).

Delete any `posctl-admin.exe` an earlier build left in the shared target dir first, or the test would run that one: `rm -f /d/cargo-target/debug/posctl-admin.exe`.

Run: `POS_TUNNEL_DOCKER=1 uv run pytest tests/cli --no-cov -q 2>&1 | tail -3`
Expected: `4 errors`: the fixture can't run `posctl-admin` (`FileNotFoundError`), since that binary doesn't exist yet.

- [x] **Step 3: Add the `posctl-admin` binary to `cli/Cargo.toml`**

After the `posctl` `[[bin]]` section:

```toml
[[bin]]
name = "posctl-admin"
path = "src/bin/posctl-admin.rs"
```

- [x] **Step 4: Write `posctl.rs`**

`cli/src/bin/posctl.rs` (replacing it):

```rust
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
```

- [x] **Step 5: Write `posctl-admin.rs`**

`cli/src/bin/posctl-admin.rs`:

```rust
//! `posctl-admin`: the admin's key generation and fleet configuration (design section 7.9). Runs only
//! with the admin's operator key, so its commands stay out of other operators' and agents' way.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use posctl::admin::{self, Operators};
use posctl::bundle::Bundle;
use posctl::config::{Config, NinjaOne, Relay, parse_host_port};
use posctl::ninja::{self, Api};
use posctl::{fleet, keys};
use serde_json::json;

const ALLOWED_SIGNERS: &str = "pos/allowed_signers";
const SIGNING_NAMESPACE: &str = "pos-tunnel-release";

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Set up this workstation as the admin's: sign in to NinjaOne, find the POS policy and the two
    /// library scripts by name, write the posctl config, and list the admin as an operator.
    Init {
        /// `https://<region>.ninjarmm.com`.
        #[arg(long)]
        base_url: String,
        /// The client ID of the tenant's Native client app.
        #[arg(long)]
        client_id: String,
        /// The exact name of the NinjaOne policy whose devices are the POSes.
        #[arg(long)]
        policy: String,
        /// The admin's operator private key (made by hand, its public key built into posctl-admin).
        #[arg(long)]
        operator_key: PathBuf,
        /// The admin's operator name, as the relay logs it.
        #[arg(long)]
        name: String,
    },
    #[command(subcommand)]
    Relay(RelayCommand),
    #[command(subcommand)]
    Signing(SigningCommand),
    #[command(subcommand)]
    Operator(OperatorCommand),
}

#[derive(Subcommand)]
enum RelayCommand {
    /// Generate the relay's SSH server key pair and make it the one this workstation pins; prints the
    /// RELAY_SSH_PRIVATE_KEY line for Coolify. Then redeploy the relay, then `relay point`.
    Keygen {
        /// `<host>[:<port>]`, port 2222 if omitted.
        address: String,
    },
    /// Point the fleet at the relay: write the fleet relay fields, then run `Install-PosTunnel -Force` on
    /// every online POS at once. Open sessions end.
    Point {
        /// Run `Install-PosTunnel -Force` on this one POS only (its exact display name), to try a relay
        /// on a test device first. The fleet fields are written either way; other POSes pick them up at
        /// their next scheduled install.
        #[arg(long, value_name = "DISPLAY_NAME")]
        device: Option<String>,
    },
}

#[derive(Subcommand)]
enum SigningCommand {
    /// Generate a release signing key pair (passphrase-protected), rewrite pos/allowed_signers and
    /// publish the public key. Run from a checkout of pos-tunnel; then re-sign and release.
    Keygen,
    /// Publish the public key in pos/allowed_signers to the posTunnelSigner fleet field.
    Publish,
}

#[derive(Subcommand)]
enum OperatorCommand {
    /// Generate an operator key pair and print the bundle for their `posctl operator import`.
    Add {
        name: String,
    },
    Remove {
        name: String,
    },
    List,
}

fn main() -> Result<()> {
    let command = Cli::parse().command;
    // Before the admin check, which needs the config init writes.
    if let Command::Init {
        base_url,
        client_id,
        policy,
        operator_key,
        name,
    } = command
    {
        let base_url = base_url.trim_end_matches('/');
        admin::require_admin(&operator_key)?;
        admin::check_operator_name(&name)?;
        ninja::login(base_url, &client_id)?;
        let api = Api::connect(base_url, &client_id)?;
        let policies = api.policies()?;
        let pos_policy_id = policies
            .iter()
            .find(|p| p.name == policy)
            .with_context(|| {
                let names: Vec<&str> = policies.iter().map(|p| p.name.as_str()).collect();
                format!(
                    "no NinjaOne policy named '{policy}'; there are: {}",
                    names.join(", ")
                )
            })?
            .id;
        let scripts = api.scripts()?;
        let script = |wanted: &str| {
            scripts
                .iter()
                .find(|s| s.name == wanted)
                .map(|s| s.id)
                .with_context(|| format!("no library script named '{wanted}': paste pos/ninja/{wanted}.ps1 into the NinjaOne library under that name"))
        };
        let ninjaone = NinjaOne {
            base_url: base_url.to_owned(),
            client_id,
            pos_policy_id,
            install_script_id: script("Install-PosTunnel")?,
            invoke_script_id: script("Invoke-PosTunnel")?,
        };
        // A rerun keeps the relay this workstation already pins.
        let relay = Config::load().ok().and_then(|existing| existing.relay);
        Config {
            operator_key: std::path::absolute(&operator_key)?,
            ninjaone,
            relay,
        }
        .save()?;
        let mut operators = Operators::load()?;
        operators
            .operators
            .insert(name.clone(), keys::public_of_file(&operator_key)?);
        operators.save()?;
        println!(
            "posctl is set up for {name}, policy '{policy}' (id {pos_policy_id}). Next: `posctl-admin relay keygen <host>`."
        );
        return Ok(());
    }
    let mut config = Config::load()?;
    admin::require_admin(&config.operator_key)?;
    match command {
        Command::Init { .. } => unreachable!("handled above"),
        Command::Relay(RelayCommand::Keygen { address }) => {
            let (host, port) = parse_host_port(&address)?;
            let key = keys::generate("pos-tunnel relay")?;
            let text = keys::private_text(&key, None)?;
            keys::write_private_key(&admin::relay_key_path()?, &key, None)?;
            config.relay = Some(Relay {
                host,
                port,
                public_key: keys::public_line(key.public_key())?,
            });
            config.save()?;
            println!("{}", admin::relay_env_line(&text));
            eprintln!(
                "Paste that line into the relay's environment in Coolify and redeploy, then run `posctl-admin relay point`."
            );
        }
        Command::Relay(RelayCommand::Point { device }) => {
            let relay = config
                .relay
                .as_ref()
                .context("no relay yet: run `posctl-admin relay keygen` first")?;
            // From the private key on disk, never asked of the network, where an attacker could answer
            // with theirs.
            let public_key = keys::public_of_file(&admin::relay_key_path()?)?;
            if public_key != relay.public_key {
                bail!(
                    "the posctl config pins a different relay key than {}; run `relay keygen` again",
                    admin::relay_key_path()?.display()
                );
            }
            let ninja = &config.ninjaone;
            let api = Api::connect(&ninja.base_url, &ninja.client_id)?;
            let address = format!("{}:{}", relay.host, relay.port);
            let pointed =
                fleet::point_relay(&api, ninja, &address, &public_key, device.as_deref())?;
            println!(
                "Fleet relay fields written on organizations {:?}.",
                pointed.organizations
            );
            println!(
                "Install-PosTunnel -Force started on: {}",
                pointed.ran.join(", ")
            );
            if !pointed.offline.is_empty() {
                println!(
                    "Offline, converging at their next scheduled install: {}",
                    pointed.offline.join(", ")
                );
            }
            if device.is_none() {
                println!(
                    "Send the other operators this line:\nposctl relay set {address} {public_key}"
                );
            }
        }
        Command::Signing(command) => {
            let public_key = match command {
                SigningCommand::Keygen => {
                    if !Path::new(ALLOWED_SIGNERS).exists() {
                        bail!(
                            "run this from a checkout of pos-tunnel: it rewrites {ALLOWED_SIGNERS}"
                        );
                    }
                    let passphrase =
                        rpassword::prompt_password("Passphrase for the new signing key: ")?;
                    if passphrase.is_empty() || passphrase != rpassword::prompt_password("Again: ")?
                    {
                        bail!("the passphrases are empty or don't match");
                    }
                    let key = keys::generate(SIGNING_NAMESPACE)?;
                    let path = admin::signing_key_path()?;
                    keys::write_private_key(&path, &key, Some(&passphrase))?;
                    let public_key = keys::public_line(key.public_key())?;
                    fs::write(
                        ALLOWED_SIGNERS,
                        format!(
                            "{SIGNING_NAMESPACE} namespaces=\"{SIGNING_NAMESPACE}\" {public_key}\n"
                        ),
                    )?;
                    println!("Signing key stored at {}.", path.display());
                    println!(
                        "Set POS_TUNNEL_SIGNING_KEY to that path, run `poe sign-pos`, commit {ALLOWED_SIGNERS} and the manifest, and release."
                    );
                    println!(
                        "Until that release exists, POSes refuse new releases and keep their installed version."
                    );
                    public_key
                }
                SigningCommand::Publish => {
                    let text = fs::read_to_string(ALLOWED_SIGNERS).with_context(|| {
                        format!("run this from a checkout of pos-tunnel ({ALLOWED_SIGNERS})")
                    })?;
                    let key = text
                        .split_once("ssh-ed25519")
                        .map(|(_, rest)| format!("ssh-ed25519{rest}"))
                        .context("no ed25519 key in it")?;
                    keys::parse_public(&key)?
                }
            };
            let ninja = &config.ninjaone;
            let api = Api::connect(&ninja.base_url, &ninja.client_id)?;
            let organizations = fleet::set_fleet_fields(
                &api,
                ninja.pos_policy_id,
                &json!({"posTunnelSigner": public_key}),
            )?;
            println!("posTunnelSigner written on organizations {organizations:?}.");
        }
        Command::Operator(command) => {
            let mut operators = Operators::load()?;
            match command {
                OperatorCommand::Add { name } => {
                    if config.relay.is_none() {
                        bail!(
                            "no relay yet: run `posctl-admin relay keygen` first, so the bundle carries it"
                        );
                    }
                    let key = keys::generate(&name)?;
                    operators.add(&name, keys::public_line(key.public_key())?)?;
                    let bundle = Bundle {
                        operator_key: keys::private_text(&key, None)?,
                        config: config.clone(),
                    };
                    operators.save()?;
                    eprintln!(
                        "The bundle below holds {name}'s private key and is shown once: send it like a password, never by email or chat."
                    );
                    println!("{}", bundle.encode()?);
                }
                OperatorCommand::Remove { name } => {
                    operators.remove(&name, &keys::public_of_file(&config.operator_key)?)?;
                    operators.save()?;
                }
                OperatorCommand::List => {
                    for (name, key) in &operators.operators {
                        println!("{name}\t{key}");
                    }
                }
            }
            println!("{}", operators.env_line());
            eprintln!("Redeploy the relay with that OPERATOR_KEYS line to apply it.");
        }
    }
    Ok(())
}
```

- [x] **Step 6: Run the integration test**

Run: `POS_TUNNEL_DOCKER=1 uv run pytest tests/cli --no-cov -q 2>&1 | tail -2`
Expected: `4 passed`.

Then: `uv run ruff check tests/cli && uv run ruff format --check tests/cli && uv run pyright tests/cli`
Expected: `All checks passed!`, `1 file already formatted`, `0 errors, 0 warnings, 0 informations`.

- [x] **Step 7: Add the CI job**

In `.github/workflows/ci.yml`, after the `pos-integration` job:

```yaml
  cli-integration:
    name: "posctl: relay setup integration tests (ubuntu-latest)"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
          submodules: true
      - uses: dtolnay/rust-toolchain@stable
      - uses: astral-sh/setup-uv@v5
      # --no-project: the dev group comes from the private index, which CI can't reach. It also skips
      # requires-python, so pin 3.14, whose lazy annotations the tests' TYPE_CHECKING imports need.
      - name: uv run --no-project --python 3.14 pytest tests/cli
        env:
          POS_TUNNEL_DOCKER: "1"
        run: uv run --no-project --python 3.14 --with pytest --with pytest-cov --with pytest-asyncio pytest tests/cli
```

- [x] **Step 8: Check, commit, push**

Run the check. Expected: `test result: ok. 28 passed`, nothing from clippy or fmt. Also `uvx maturin build --out "$(mktemp -d)"` and list the wheel: it holds `posctl.exe` and `posctl-admin.exe`.

```bash
git add cli tests/cli .github/workflows/ci.yml
git commit -m "feat(cli): posctl-admin, and posctl's login, operator import and relay set

posctl-admin runs only with the admin's operator key. init signs in and finds
the POS policy and library scripts; relay keygen and operator add print the
relay's two .env lines; relay point writes the fleet relay fields and installs
on every POS, or on one with --device; signing keygen/publish set
posTunnelSigner.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push -u origin HEAD
```

Run the CI check. Expected: four lines, each ending `success`, including `posctl: relay setup integration tests (ubuntu-latest): success`.

---

### Task 6: The admin key, the design, and a run against the tenant

**Files:**
- Replace: `cli/admin.pub` (the admin's own)
- Modify: `docs/design.md`, `README.md`

- [x] **Step 1: Bring `docs/design.md` up to date**

Make these replacements. Each Old block is the passage exactly as it stands; replace it with the New block.

1. Section 3, the table's NinjaOne credentials row (the New row is already padded to the table):

    Old:
    ```
    | NinjaOne API client credentials (not a key pair) | in NinjaOne's console                                                                                                      | OS keyring (`posctl login`)                                                   | —                                                                                                                                                           | running SYSTEM scripts on every POS; the admin's also writes the fleet fields                                                                    |
    ```
    New:
    ```
    | NinjaOne sign-in (not a key pair)                | by `posctl login` (the admin's: `posctl-admin init`), a browser sign-in through the tenant's Native client app             | Windows Credential Manager (a user-only file elsewhere)                       | —                                                                                                                                                           | running SYSTEM scripts on every POS, as that NinjaOne user; the admin's also writes the fleet fields                                             |
    ```

2. Section 3, the paragraph on field settings:

    Old:
    ```
    `posctl-admin` owns these settings: before any fleet-field write it reads all six definitions
    (`GET /v2/custom-fields/field-name/{name}`: `definitionScope`, `scriptPermission`,
    `apiPermission`), creates any that are missing (`POST /v2/custom-fields`) with the settings above,
    and refuses, naming the field and setting, if an existing one differs. It never changes an existing
    definition, since a changed setting may be tampering.
    ```
    New:
    ```
    `posctl-admin` owns these settings: before any fleet-field write it reads all six definitions
    (`GET /v2/custom-fields/field-name/{name}`: `definitionScope`, `scriptPermission`,
    `apiPermission`) and refuses, naming the field and setting, if an existing one differs; then it
    creates any that are missing (`POST /v2/custom-fields`, global fields: `scope` `NODE_GLOBAL`) with
    the settings above and reads each back. It never changes an existing definition, since a changed
    setting may be tampering.
    ```

3. Section 7.1, the signing key's path:

    Old:
    ```
    committed. The private key is the one `posctl-admin signing keygen` stored (`POS_TUNNEL_SIGNING_KEY`
    overrides the path). The package version is independent of the wheel version and rises only when the files
    ```
    New:
    ```
    committed. The private key is the one `posctl-admin signing keygen` stored, at the path in
    `POS_TUNNEL_SIGNING_KEY`. The package version is independent of the wheel version and rises only when the files
    ```

4. Section 7.7, `login`:

    Old:
    ```
    - `login`: prompts for the NinjaOne client ID and secret and stores them in the OS keyring.
    ```
    New:
    ```
    - `login`: signs in to NinjaOne in the browser through the tenant's Native client app (section 8) and
      keeps the refresh token in Windows Credential Manager. Needs `config.toml` (`operator import`).
    ```

5. Section 7.9, from its first paragraph through `signing keygen`:

    Old:
    ```
    Runs only when the operator's private key matches the admin public key built into the binary. That
    isn't a security boundary (the admin's NinjaOne credential is what can change the fleet); it keeps
    these commands out of `posctl --help`, so an agent working through `posctl` doesn't come across them.
    Uses a NinjaOne credential that can write the fleet fields. Every command that produces relay
    configuration prints it as a `.env` line ready to paste into Coolify.

    - `relay keygen [--activate [<host>[:<port>]]]`: generates a relay SSH server key pair, stores the
      private key in `posctl-admin`'s config dir and prints the `RELAY_SSH_PRIVATE_KEY=` line.
      `--activate` makes it the active pair: this workstation's `posctl` config takes its public key, and
      the host and port if given (port default 2222).
    - `relay point <host>[:<port>]`: derives the public key from the active relay private key (locally,
      never queried over the network, where an attacker could answer with theirs), writes the fleet relay
      fields, then runs `Install-PosTunnel -Force` on every POS at once. Open sessions end; offline POSes
      converge at their next daily run. Serves both rotating the relay's key pair and moving to a new
      relay; in either case the fleet is unreachable until it runs, so it never waits. Prints the
      `posctl relay set …` line for the other operators. Order: `relay keygen --activate`, paste the line
      into Coolify and redeploy, then `relay point`.
    - `signing keygen`: generates a release signing key pair, stores the private key where `poe sign-pos`
      reads it, rewrites `pos/allowed_signers` (run from a checkout of this repo), and writes the public
      key to `posTunnelSigner` at once. Then re-sign and release: until a release signed with the new key
      exists, POSes reject new releases and keep their installed version.
    ```
    New:
    ```
    Runs only when the operator's private key matches the admin public key built into the binary
    (`cli/admin.pub`). That isn't a security boundary (the admin's NinjaOne sign-in is what can change
    the fleet); it keeps these commands out of `posctl --help`, so an agent working through `posctl`
    doesn't come across them. Every command that produces relay configuration prints it as a `.env` line
    ready to paste into Coolify.

    - `init --base-url <url> --client-id <id> --policy <name> --operator-key <path> --name <name>`: signs
      in to NinjaOne (as `login`), finds the POS policy and the two library scripts by exact name, writes
      this workstation's `config.toml` (keeping a relay it already pins) and lists the admin as an
      operator.
    - `relay keygen <host>[:<port>]`: generates a relay SSH server key pair, stores the private key in
      `posctl-admin`'s config dir, makes this workstation's `posctl` pin its public key at that address
      (port default 2222), and prints the `RELAY_SSH_PRIVATE_KEY=` line.
    - `relay point [--device <DisplayName>]`: derives the public key from the stored relay private key
      (locally, never queried over the network, where an attacker could answer with theirs), writes the
      fleet relay fields, then runs `Install-PosTunnel -Force` on every online POS at once. Open sessions
      end; offline POSes converge at their next daily run. Serves both rotating the relay's key pair and
      moving to a new relay; in either case the fleet is unreachable until it runs, so it never waits.
      Prints the `posctl relay set …` line for the other operators. `--device` runs the install on that
      one POS only, to try a relay on a test device first; it is resolved before anything is written, so
      a mistyped or offline one changes nothing. Order: `relay keygen`, paste the line into Coolify and
      redeploy, then `relay point`.
    - `signing keygen`: generates a passphrase-protected release signing key pair, stores the private key
      in `posctl-admin`'s config dir, rewrites `pos/allowed_signers` (run from a checkout of this repo),
      and writes the public key to `posTunnelSigner` at once. Then point `POS_TUNNEL_SIGNING_KEY` at it,
      re-sign and release: until a release signed with the new key exists, POSes reject new releases and
      keep their installed version. `signing publish` writes the key already in `pos/allowed_signers`.
    ```

6. Section 7.9, the operator commands' bundle contents and last sentence:

    Old:
    ```
      of a small TOML document holding the operator private key and the admin's `config.toml` (NinjaOne
      base URL, script IDs, POS policy ID, relay host, port and public key). It contains a private key, so
      it travels like a password (e.g. a password manager), never by email or chat. `posctl-admin` keeps
      only the public keys, the admin's own included. All three print the full `OPERATOR_KEYS=` line;
      redeploy the relay to apply it. The new operator still runs `posctl login` with their own NinjaOne
      credential.
    ```
    New:
    ```
      of a small TOML document holding the operator private key and the admin's `config.toml` (NinjaOne
      base URL and Native client ID, script IDs, POS policy ID, relay host, port and public key). It
      contains a private key, so it travels like a password (e.g. a password manager), never by email or
      chat. `posctl-admin` keeps only the public keys, the admin's own included, and `remove` refuses the
      admin's. All three print the full `OPERATOR_KEYS=` line; redeploy the relay to apply it. The new
      operator still runs `posctl login`, signing in as their own NinjaOne user.
    ```

7. Section 8, the config and the API's sign-in:

    Old:
    ```
    - Config `posctl/config.toml` in the platform config dir: NinjaOne API base URL (region-specific),
      library script IDs for `Install-PosTunnel` and `Invoke-PosTunnel`, and the POS policy ID; relay
      host, port and public key (set by `relay keygen --activate` on the admin's workstation,
      `operator import` or `relay set` on others); operator private key path.
    - NinjaOne API (OAuth client credentials; scopes `monitoring` to read, `management` to run scripts
      and write fields; base URL `app`, `us2`, `eu`, `ca` or `oc` `.ninjarmm.com`):
    ```
    New:
    ```
    - Config `posctl/config.toml` in the platform config dir (`POSCTL_CONFIG_HOME` overrides it): NinjaOne
      API base URL (region-specific) and Native client ID, library script IDs for `Install-PosTunnel` and
      `Invoke-PosTunnel`, and the POS policy ID (written by `posctl-admin init`); relay host, port and
      public key (set by `relay keygen` on the admin's workstation, `operator import` or `relay set` on
      others); operator private key path.
    - NinjaOne API (OAuth authorization code with PKCE through the tenant's Native client app, no client
      secret; scopes `monitoring` to read, `management` to run scripts and write fields,
      `offline_access` for the refresh token, which `login` keeps and each command trades for an access
      token; base URL `app`, `us2`, `eu`, `ca` or `oc` `.ninjarmm.com`):
    ```

8. Section 11, after the devices sentence:

    Old:
    ```
    `message`. `GET /v2/devices` returns `rolePolicyId` and no `policyId` key (no device in the tenant has
    an override). Still open:
    ```
    New:
    ```
    `message`. `GET /v2/devices` returns `rolePolicyId` and no `policyId` key (no device in the tenant has
    an override). Creating a custom field (`POST /v2/custom-fields`) needs the deprecated `scope`
    (`NODE_GLOBAL` for a global field) beside `definitionScope`, and NinjaOne stores the definition scope
    and permissions as sent (`posctl-admin` created the six). Still open:
    ```

9. Section 12, the whole list:

    Old:
    ```
    1. Admin key: generate the admin's operator key pair by hand (`ssh-keygen -t ed25519`) and build its
       public key into `posctl-admin`.
    2. NinjaOne: paste `Install-PosTunnel` and `Invoke-PosTunnel` into the library; create the admin's
       API client (`posctl-admin` creates the custom fields on its first fleet-field write);
       `posctl login`; write `config.toml`, add the `Include`.
    3. Release: `posctl-admin signing keygen`; `poe sign-pos`; commit; `poe release`.
    4. Relay: `posctl-admin relay keygen --activate <host>[:<port>]` and `operator list` (or `add` for a second
       operator); in Coolify, a Docker Compose application from `pos-tunnel-relay`, with both lines in its
       environment; deploy; add the DNS record; open 2222 in the Vultr firewall.
    5. With only one test device in the POS policy: `posctl-admin relay point <host>`, then test end to
       end. Then add the fleet to the policy and schedule `Install-PosTunnel` daily.
    ```
    New:
    ```
    1. Admin key: generate the admin's operator key pair by hand (`ssh-keygen -t ed25519`) and commit its
       public key as `cli/admin.pub`, which `posctl-admin` is built with.
    2. NinjaOne: paste `Install-PosTunnel` and `Invoke-PosTunnel` into the library; create a Native
       client app (redirect `http://127.0.0.1`, scopes Monitoring, Management and Offline Access, grant
       types Authorization Code and Refresh Token); `posctl-admin init` (it signs in); add the
       `Include`. The first fleet-field write creates the custom fields.
    3. Release: `posctl-admin signing publish` (or `signing keygen` for a new key); `poe sign-pos`;
       commit; `poe release`.
    4. Relay: `posctl-admin relay keygen <host>[:<port>]` and `operator list` (or `add` for a second
       operator); in Coolify, a Docker Compose application from `pos-tunnel-relay`, with both lines in its
       environment; deploy; add the DNS record; open 2222 in the Vultr firewall.
    5. `posctl-admin relay point --device <test POS>`, then test end to end. Then `relay point` for the
       whole fleet, and schedule `Install-PosTunnel` daily in the POS policy.
    ```

- [x] **Step 2: Update the README's status line**

In `README.md`:

Old:
```
**Status:** the relay and the POS package are implemented; `posctl` is not (everything below `cli/` is
scaffolding).
```
New:
```
**Status:** the relay, the POS package and `posctl-admin` are implemented; `posctl`'s session commands
(`connect`, `keepalive`, `status`, `close`, `rebuild`, `update`, `rekey`) are not yet.
```

Commit:

```bash
git add docs/design.md README.md
git commit -m "docs(design): record posctl-admin's decisions

The browser sign-in through a Native app (PKCE, no secret) and Windows Credential
Manager; init; relay keygen always activating; relay point --device; signing
publish; the custom-field scope NinjaOne requires.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [x] **Step 3: Ask the user for the admin's operator public key**

Stop and ask the user to generate the admin's operator key pair on their workstation (PowerShell; a passphrase is fine, `posctl-admin` reads the public half), and to give you the `.pub` line:

```powershell
ssh-keygen -t ed25519 -C <their operator name> -f $HOME\.ssh\pos-tunnel-operator
Get-Content $HOME\.ssh\pos-tunnel-operator.pub
```

Write that line's first two fields to `cli/admin.pub`, then run the check (expected: `test result: ok. 28 passed`) and commit:

```bash
git add cli/admin.pub
git commit -m "chore(cli): build posctl-admin with the admin's operator public key

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [x] **Step 4: Run posctl-admin against the tenant**

> Changed in flight (user, 2026-10-12): `signing publish` now takes a release tag and reads the key from
> the repository at it. No release tag exists yet and `posTunnelSigner` already holds this key, so this
> step runs `init` only.

This writes the admin's real `config.toml` (deployment step 2). Tell the user a browser tab will ask them to sign in to NinjaOne and approve. From the repository root:

```bash
cargo build --bins
cid=$(grep -m1 '^NINJAONE_NATIVE_CLIENT_ID=' .env | cut -d= -f2- | tr -d '\r"'"'")
/d/cargo-target/debug/posctl-admin.exe init --base-url https://us2.ninjarmm.com --client-id "$cid" \
  --policy "Store POS Windows 11" --operator-key "$HOME/.ssh/pos-tunnel-operator" --name <their operator name>
/d/cargo-target/debug/posctl-admin.exe signing publish
```

Expected: `posctl is set up for <name>, policy 'Store POS Windows 11' (id 35). Next: ...`, then `posTunnelSigner written on organizations [3].` (the six fields already exist with the right settings, so nothing is created).

- [x] **Step 5: Push and check**

```bash
git push
```

Run the CI check. Expected: four lines, each ending `success`.

---

## After this plan

- Deployment steps 3-5 (design section 12): a release (`poe release`), the relay (`posctl-admin relay keygen`, Coolify), then `posctl-admin relay point --device "POS 000 Test"`.
- The next plan: `posctl`'s session commands, built on `fleet::find_pos`, `Api::run_script` and the relay's `tunnelctl`.
- Delete the throwaway branch `probe/posctl-admin` on GitHub, and its worktree, once this plan has landed.

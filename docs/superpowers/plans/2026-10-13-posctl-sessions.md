# posctl Session Commands Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `posctl`'s session commands (`connect`, `keepalive`, `status`, `close`, `rebuild`, `update`, `rekey`), including a second operator joining an open session, so that an operator and a coding agent on the operator's workstation can open, use and end an SSH session to any POS.

**Architecture:** Four new modules in the `posctl` library crate. `relay` reaches the relay's `tunnelctl` through OpenSSH's client behind a `Relay` trait, which is the one seam tests replace. `workstation` owns what this machine holds for its sessions: the state dir, the generated `ssh` config and `known_hosts`, the `Include` line, the agent check. `session` and `rekey` are the commands, written against the trait and the NinjaOne client, which gains "run a script and wait for its result" by following the device's activity list. The POS package gains a join mode in `Open` (package version 4); the relay and the two NinjaOne library scripts are unchanged.

**Tech Stack:** Rust 2024 edition (clap 4, ureq 3, ssh-key 0.6, serde/toml/serde_json, humantime; no new dependency); Windows OpenSSH 9.5 as the `ssh` client; PowerShell 5.1 and Pester for the POS package; pytest and Docker for the end-to-end test; GitHub Actions.

**Spec:** `docs/design.md`, sections 4 (naming), 5 (timers), 7.2 to 7.8 (the commands, joining, `Open -Mode Join`), 8 (the workstation: session state, script results, `ssh`, the generated entries), 9 (limitations), 10 (rejected: keys on the relay, a `close` that only leaves) and 11 (what was verified). The spec was amended on this branch before this plan (`2727593`, `43730cf`, `c7cdf84`, `107355e` and the one after it); where the two differ, the spec is wrong and Task 6 corrects it.

**Provenance:** every code block below is a file, or a diff of one, from the throwaway branch `probe/posctl-sessions`, where it ran before this plan was written (2026-10-13, this workstation, Windows 11):

- `cargo test` 80 of 80, `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` clean. Replayed in this plan's task order: 42 after Task 1, 73 after Task 2, 80 after Task 3.
- The Docker tests, `tests/cli`: 12 of 12 (the 4 relay-setup tests and the 8 new session tests) against the real relay image, a stand-in POS and a fake NinjaOne, two operators included.
- Against the deployed relay and the real `POS 000 Test` (package version 3): `status`; `connect` (15 s, then 11 s), the alias from both Windows' and Git Bash's `ssh`; `connect` again (reports the open session); `keepalive` (12 s); `rebuild` without and with `--yes` (24 s); `close` (12 s); `rekey` refused by the POS for a session left on it alone, then `rekey --force` (28 s) and a `connect` with the republished keys; `update` deferred under a session and complete without one (16 s); and, with the final build, a `connect` straight after the lease was closed on the relay alone, the old tunnel still holding the port (24 s). That last case failed on the first try: `connect` took the old tunnel for the new session's. Decision 15 is the fix.
- **Not run yet:** the POS package's integration tests with the join mode (`tests/pos`, which reconfigure the machine and so run only in CI's `pos-integration` job), and this branch's other CI jobs. Task 5 and Task 6 run them. Joining on a real POS needs package version 4 released: see "After this plan".

## Global Constraints

- Work on `feat/posctl-sessions`. `cargo` commands run from the repository root (the workspace); this machine's `CARGO_TARGET_DIR` is `D:\cargo-target`, so binaries land in `D:\cargo-target\debug`.
- Every Rust change passes `cargo test`, `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` (rustfmt defaults).
- Python follows the repo's ruff and pyright config (2-space indent, line length 135); run them with `uv run`. There is no bare `python` in Git Bash: use `uv run python`.
- `.ps1` files are CRLF in the working tree (`.gitattributes`) and ASCII only; `scripts/sign_pos.py` refuses an LF one. The Write tool writes LF, so after creating or rewriting a `.ps1` file run `sed -i 's/$/\r/' <file>` once (never on a file that is already CRLF), then check with `tr -cd '\r' < <file> | wc -c` that the count equals `wc -l`.
- A Bash tool command over about 8 KB fails before running anything: write long content with the Write tool, never a heredoc.
- A `diff` block applies with `git apply <file>` once saved to a file; for a `.ps1` add `--ignore-whitespace`, since the working copy is CRLF and the block is shown LF. Every diff block here was applied to the branch as it stood when this plan was written, and each reproduced the probe's file.
- The Docker tests need Docker running and `POS_TUNNEL_DOCKER=1`. On Windows they call Windows' own `ssh` tools (`openssh()` in `tests/cli/test_relay_setup.py`), so they run the same from PowerShell and Git Bash.
- Comments carry reasoning, densely (`AGENTS.md`, "Comment Density"). No single-use helpers of 4 lines or fewer (`AGENTS.md`, "Abstraction Conventions").
- In prose and comments say "private key"/"public key", never "host key" (`posTunnelHostKey`, `HostKeyAlias` and `known_hosts` are names, not prose).
- `.env` holds live NinjaOne values; never print it.
- The user has approved running the session commands against `POS 000 Test` and no other POS (2026-10-13). Nothing in this plan touches another device, and `rekey --all` is never run against the tenant.
- Pushing the branch, opening the pull request, signing the POS package and releasing are the user's to approve or do; the steps that need them say so.
- Conventional Commits, scope `cli`, `pos`, `test`, `ci` or `docs`, every message ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Branch testing (`AGENTS.md`): each task's own tests while working, the task's check at its end, the Docker test only in Task 4 and Task 6.

**Check** (Git Bash, repository root; run at the end of every Rust task). Expected: the test summary line the task names, and nothing else from clippy or fmt.

```bash
cargo test 2>&1 | grep -E "^test result: .* [1-9][0-9]* passed|FAILED|panicked|^error"
cargo clippy --all-targets -- -D warnings 2>&1 | grep -E "^(warning|error)" -A5
cargo fmt --check
```

## Decisions this plan makes

Each was settled by a probe or by the user; the spec records them.

1. **`posctl` runs OpenSSH's client; it has no SSH library of its own.** The alias an operator types and `posctl`'s own calls then behave the same way, with the agent, `known_hosts` and config the operator already has. On Windows it is `System32\OpenSSH\ssh.exe` (else `Program Files\OpenSSH`, else `PATH`), never Git Bash's, which can't reach the Windows `ssh-agent`.
2. **The alias's hop is a `ProxyCommand` naming that client with a quoted `-F`, not `ProxyJump`.** Probed: Windows' client passes its own `-F` to the jump unquoted, so a config path with a space fails; and with the client named, the alias also works from Git Bash's `ssh`, whose hop then runs in Windows' client.
3. **An operator key with a passphrase goes through `ssh-agent`** (the user's choice). `posctl` checks before any relay call and prints the commands.
4. **A script run is followed by its series in the device's activity list.** `script/run` returns nothing; the run is the oldest `START_REQUESTED` activity newer than the device's last activity before the request, and its `seriesUid` leads to the `COMPLETED` one with the result and output. Probed against the tenant.
5. **A session is this workstation's when the lease's `started` equals the one it recorded.** Any other value, or no lease, means it ended or was reopened elsewhere, and the local state and alias are dropped by the next command that reads the relay.
6. **The generated `config` and `known_hosts` are rewritten whole on every command**, from the config and the session state, so there is nothing to parse or patch.
7. **`connect` adds `Include posctl/config` to `~/.ssh/config` itself** (the user's choice), unless the line already precedes every `Host` and `Match` block.
8. **`connect` logs in once before it reports success**, which checks both keys and takes the wait when Windows creates `support`'s profile.
9. **A failed `connect` closes the lease and asks the POS to `Close` without waiting for it:** a POS that didn't answer `Open` wouldn't answer `Close` either, and the relay's side is what cuts access.
10. **Operators share a session** (the user's requirement): a second `connect` joins, through `Open -Mode Join` in POS package version 4. The relay is unchanged, and the session's private keys stay off it. **`close` ends the session for everyone** (the user's choice).
11. **`rekey --force` always runs `Close` first**, with or without a relay lease, so a session left on the POS alone doesn't block it. `rekey --all` asks before it starts.
12. **`keepalive` renews the POS through NinjaOne.** Probed on the test POS: `support` can list the SYSTEM-only state folder but can't set the lease file's time.
13. **With `POSCTL_CONFIG_HOME` set, the NinjaOne refresh token is a file there on every platform.** The end-to-end test needs a sign-in that isn't the real one in Credential Manager. This changes a review note the user had left alone; the user approved it (2026-10-13).
14. **`connect` waits out a lease that has just ended.** A closed or expired lease stays listed, out of time, until the daemon's next pass; joining it would fail, so `connect` waits up to a minute for the port, and `rebuild` relies on the same wait.
15. **The tunnel counts as up only once the POS has reported `Open`'s success.** Found against the test POS: after a lease is closed on the relay alone, the previous session's tunnel still holds the port for up to a minute, so "the port is listening" by itself proves nothing.
16. **The `Relay` trait is the tests' seam.** `session` and `rekey` are tested against `FakeRelay` and a fake tenant; `SshRelay` itself runs in the Docker test and against the real relay.

## Review Focus

1. **A second operator connects to a POS already in a session.** Expected: they join it with a key of their own, and a failed join leaves the first operator's session untouched. Tests: `session::tests::connect_joins_a_session_another_workstation_opened`, `a_failed_join_leaves_the_other_operators_session_alone`, `a_pos_package_too_old_to_share_a_session_refuses_the_join` (Task 2); `test_a_second_operator_joins_and_both_reach_the_pos` (Task 4); the join cases in `tests/pos` (Task 5).
2. **A POS that stops answering part-way** (asleep, rebooting, NinjaOne slow). Expected: `connect` gives up after its wait and closes the lease again; among many, one silent or refused POS fails alone. Tests: `session::tests::a_tunnel_that_never_comes_up_times_out_and_is_closed_again`, `a_tunnel_up_before_the_pos_reports_is_not_taken_for_this_session` (Task 2), `ninja::tests::scripts_run_together_and_one_refusal_or_silence_fails_alone` (Task 1), `rekey::tests::a_pos_that_never_reports_fails_alone` (Task 3).
3. **The session ended elsewhere while this workstation still has its alias** (expired, or another operator closed or rebuilt it). Expected: the stale alias and key are dropped, never left pointing at someone else's session. Tests: `workstation::tests::reconcile_drops_sessions_the_relay_no_longer_holds_as_they_were`, `session::tests::status_drops_the_alias_of_a_session_that_ended_elsewhere` (Task 2), `test_close_ends_the_session_for_both_operators` (Task 4).
4. **An operator key with a passphrase that the agent doesn't hold.** Expected: a refusal before anything changes, with the commands to run, not a bare `Permission denied`. Test: `workstation::tests::an_encrypted_operator_key_the_agent_lacks_is_refused_with_the_commands` (Task 2).
5. **A profile path with a space, and a `~/.ssh/config` that already has `Host` blocks.** Expected: `ssh` reads the generated config, and the `Include` lands above the blocks once, leaving the rest of the file as it was. Tests: `workstation::tests::ssh_parses_the_generated_config`, `the_include_goes_first_once_and_keeps_the_rest_of_the_file` (Task 2).

---

## File Structure

| File | Responsibility |
| --- | --- |
| `cli/src/ninja.rs` | Gains custom-field reads, script results (`start_script`, `poll_script`, `run_scripts`), the script-name constants, and the sign-in file under `POSCTL_CONFIG_HOME` |
| `cli/src/relay.rs` | New. `Lease`, the `Relay` trait, `tunnelctl` replies, the tunnel port, and `SshRelay`, the real client |
| `cli/src/workstation.rs` | New. Session state on disk, the alias, the generated `ssh` files, the `Include` line, the agent check |
| `cli/src/session.rs` | New. `connect` (open or join), `keepalive`, `status`, `close`, `rebuild` |
| `cli/src/rekey.rs` | New. `rekey`'s plan and run |
| `cli/src/fake.rs` | Test-only: gains a tenant of POSes that run scripts, `FakeRelay`, a temp workstation and a fast context |
| `cli/src/lib.rs` | Lists the new modules |
| `cli/src/bin/posctl.rs` | The session commands wired up, `rekey` added, output and prompts |
| `cli/src/bin/posctl-admin.rs` | Uses the script-name constants |
| `tests/cli/test_sessions.py` | New. Docker: the real relay, a stand-in POS, a fake NinjaOne, two operators |
| `tests/cli/test_relay_setup.py` | Gains `openssh()` and `workdir()`, which both test files use |
| `pos/package/Open.ps1`, `Close.ps1` | The join mode; `Close` reports how many session keys it removed |
| `tests/pos/Harness.ps1`, `PosTunnel.Tests.ps1` | A second operator's key and the join cases |
| `pos/manifest.json`, `pos/manifest.json.sig` | Package version 4, signed by the user (Task 5) |
| `.github/workflows/ci.yml`, `README.md`, `docs/design.md` | The job's name, usage, and any correction Task 6 finds |

---

### Task 1: Script results, and the sign-in file under `POSCTL_CONFIG_HOME`

**Files:**
- Modify: `cli/src/ninja.rs`, `cli/src/bin/posctl-admin.rs`

**Interfaces:**
- Consumes: `Api::get`, `Api::run_script`, `crate::fake::Fake` (all existing).
- Produces (`posctl::ninja`): `INSTALL_SCRIPT: &str = "Install-PosTunnel"`, `INVOKE_SCRIPT: &str = "Invoke-PosTunnel"`; `ScriptRun` (opaque but for `pub device: i64`); `ScriptResult { pub success: bool, pub output: String }` with `deferred(&self) -> bool`; `Api::custom_fields(&self, device: i64) -> Result<serde_json::Map<String, Value>>`; `Api::start_script(&self, device: i64, script: i64, name: &'static str, parameters: &str) -> Result<ScriptRun>`; `Api::poll_script(&self, run: &mut ScriptRun) -> Result<Option<ScriptResult>>`; `Api::run_scripts(&self, devices: &[i64], script: i64, name: &'static str, parameters: &str, timeout: Duration, poll: Duration) -> Vec<Result<ScriptResult>>` (one result per device, in order). `token_store::save`/`load` keep their signatures.

- [x] **Step 1: Add the tests**

In `cli/src/ninja.rs`, inside `mod tests`, after the last test (`an_unreachable_ninjaone_is_not_blamed_on_the_sign_in`) and before the module's closing brace:

```rust
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
```

- [x] **Step 2: Run them to watch them fail**

Run: `cargo test --lib 2>&1 | grep -E "^error" | sort -u | head -5`
Expected: compile errors for what Step 3 adds, such as `` error[E0425]: cannot find value `INVOKE_SCRIPT` in this scope `` and `` error[E0422]: cannot find struct, variant or union type `ScriptResult` in this scope ``.

- [x] **Step 3: Add the code**

Apply to `cli/src/ninja.rs` (the constants, the token store reading a file wherever `POSCTL_CONFIG_HOME` is set, the two types, and four `Api` methods):

```diff
--- a/cli/src/ninja.rs
+++ b/cli/src/ninja.rs
@@ -21,6 +21,10 @@ use ssh_key::rand_core::{OsRng, RngCore};
 use ureq::Agent;
 
 const SCOPE: &str = "monitoring management offline_access";
+/// The library scripts' names (design section 7.1): `posctl-admin init` finds them by name, and a run's
+/// activities carry it.
+pub const INSTALL_SCRIPT: &str = "Install-PosTunnel";
+pub const INVOKE_SCRIPT: &str = "Invoke-PosTunnel";
 const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);
 
 /// Signs in through the browser and stores the refresh token.
@@ -171,7 +175,9 @@ fn snippet(body: &str) -> String {
     body.chars().take(300).collect()
 }
 
-/// The refresh token: Windows Credential Manager on Windows (design section 3), a user-only file elsewhere.
+/// The refresh token: Windows Credential Manager on Windows (design section 3), a user-only file elsewhere
+/// and wherever `POSCTL_CONFIG_HOME` is set, so a second identity has its own sign-in and a test never
+/// reads the real one (design section 8).
 pub mod token_store {
     use anyhow::{Context, Result};
 
@@ -192,32 +198,27 @@ pub mod token_store {
         )?)
     }
 
-    #[cfg(windows)]
-    pub fn save(token: &str) -> Result<()> {
-        Ok(entry()?.set_password(token)?)
-    }
-
-    #[cfg(windows)]
-    pub fn load() -> Result<String> {
-        entry()?
-            .get_password()
-            .context("not signed in to NinjaOne: run `posctl login`")
-    }
-
-    #[cfg(not(windows))]
     fn path() -> Result<std::path::PathBuf> {
         Ok(crate::config::config_home()?
             .join("posctl")
             .join("refresh_token"))
     }
 
-    #[cfg(not(windows))]
     pub fn save(token: &str) -> Result<()> {
+        #[cfg(windows)]
+        if std::env::var_os("POSCTL_CONFIG_HOME").is_none() {
+            return Ok(entry()?.set_password(token)?);
+        }
         crate::config::write_private(&path()?, token.as_bytes())
     }
 
-    #[cfg(not(windows))]
     pub fn load() -> Result<String> {
+        #[cfg(windows)]
+        if std::env::var_os("POSCTL_CONFIG_HOME").is_none() {
+            return entry()?
+                .get_password()
+                .context("not signed in to NinjaOne: run `posctl login`");
+        }
         Ok(std::fs::read_to_string(path()?)
             .context("not signed in to NinjaOne: run `posctl login`")?
             .trim()
@@ -267,6 +268,35 @@ pub struct FieldDefinition {
     pub api_permission: Option<String>,
 }
 
+/// A requested script run, followed through the device's activity list (design section 8, script
+/// results).
+#[derive(Debug)]
+pub struct ScriptRun {
+    pub device: i64,
+    name: &'static str,
+    /// The device's newest activity before the request.
+    after: i64,
+    /// The run's `seriesUid`, once its `START_REQUESTED` activity has shown up.
+    series: Option<String>,
+}
+
+#[derive(Debug, Clone, PartialEq)]
+pub struct ScriptResult {
+    /// NinjaOne's verdict, and no `FAILED` line in the output.
+    pub success: bool,
+    /// What the script printed. The POS's words: untrusted, shown as its report and nothing more.
+    pub output: String,
+}
+
+impl ScriptResult {
+    /// A step put off to a later run (a session is open, a restart is pending): design section 7.1.
+    pub fn deferred(&self) -> bool {
+        self.output
+            .lines()
+            .any(|line| line.starts_with("DEFERRED\t"))
+    }
+}
+
 impl Api {
     pub fn connect(base_url: &str, client_id: &str) -> Result<Api> {
         Api::with_refresh_token(base_url, client_id, &token_store::load()?)
@@ -416,6 +446,125 @@ impl Api {
         )
         .map(drop)
     }
+
+    /// The device's custom fields, name to value; a field never set is absent.
+    pub fn custom_fields(&self, device: i64) -> Result<serde_json::Map<String, Value>> {
+        self.get(&format!("/v2/device/{device}/custom-fields"))
+    }
+
+    /// `run_script`, returning what `poll_script` follows the run by: `script/run` itself returns
+    /// nothing, so the device's newest activity is noted first and the run is the first request after it.
+    pub fn start_script(
+        &self,
+        device: i64,
+        script: i64,
+        name: &'static str,
+        parameters: &str,
+    ) -> Result<ScriptRun> {
+        let before: Value = self.get(&format!("/v2/device/{device}/activities?pageSize=10"))?;
+        let after = before["lastNodeActivityId"].as_i64().unwrap_or(0);
+        self.run_script(device, script, parameters)?;
+        Ok(ScriptRun {
+            device,
+            name,
+            after,
+            series: None,
+        })
+    }
+
+    /// One look at a run: its result once the POS has finished, `None` until then.
+    pub fn poll_script(&self, run: &mut ScriptRun) -> Result<Option<ScriptResult>> {
+        let device = run.device;
+        if run.series.is_none() {
+            let reply: Value = self.get(&format!(
+                "/v2/device/{device}/activities?newerThan={}&pageSize=200",
+                run.after
+            ))?;
+            // Newest first, so the last match is the oldest request since `after`: this run's. By
+            // series from here on, not by name: a late `Open` and the `Close` that follows a timed-out
+            // `connect` are both `Invoke-PosTunnel`.
+            run.series = reply["activities"]
+                .as_array()
+                .into_iter()
+                .flatten()
+                .rfind(|a| a["statusCode"] == "START_REQUESTED" && a["sourceName"] == run.name)
+                .and_then(|a| a["seriesUid"].as_str().map(str::to_owned));
+        }
+        let Some(series) = &run.series else {
+            return Ok(None);
+        };
+        let reply: Value = self.get(&format!(
+            "/v2/device/{device}/activities?seriesUid={series}&pageSize=10"
+        ))?;
+        let Some(done) = reply["activities"]
+            .as_array()
+            .into_iter()
+            .flatten()
+            .find(|a| a["statusCode"] == "COMPLETED")
+        else {
+            return Ok(None);
+        };
+        let output = done["data"]["message"]["params"]["output_message"]
+            .as_str()
+            .or(done["message"].as_str())
+            .unwrap_or_default()
+            .replace("\r\n", "\n");
+        let output = output.trim_end().to_owned();
+        // Both: NinjaOne's verdict follows the exit code, and a `FAILED` line is the script's own word.
+        let success = done["activityResult"] == "SUCCESS"
+            && !output.lines().any(|line| line.starts_with("FAILED\t"));
+        Ok(Some(ScriptResult { success, output }))
+    }
+
+    /// Runs a library script on every device in `devices` at once and waits for each result, in their
+    /// order. A device NinjaOne refuses, or that reports nothing within `timeout`, gets an error; the
+    /// others still finish.
+    pub fn run_scripts(
+        &self,
+        devices: &[i64],
+        script: i64,
+        name: &'static str,
+        parameters: &str,
+        timeout: Duration,
+        poll: Duration,
+    ) -> Vec<Result<ScriptResult>> {
+        let mut pending: Vec<(usize, ScriptRun)> = Vec::new();
+        let mut results: Vec<Option<Result<ScriptResult>>> = Vec::new();
+        for (index, &device) in devices.iter().enumerate() {
+            match self.start_script(device, script, name, parameters) {
+                Ok(run) => {
+                    pending.push((index, run));
+                    results.push(None);
+                }
+                Err(e) => results.push(Some(Err(e))),
+            }
+        }
+        let deadline = Instant::now() + timeout;
+        loop {
+            pending.retain_mut(|(index, run)| match self.poll_script(run).transpose() {
+                Some(result) => {
+                    results[*index] = Some(result);
+                    false
+                }
+                None => true,
+            });
+            if pending.is_empty() || Instant::now() >= deadline {
+                break;
+            }
+            std::thread::sleep(poll);
+        }
+        results
+            .into_iter()
+            .map(|result| {
+                result.unwrap_or_else(|| {
+                    bail!(
+                        "the POS reported no result for {name} within {}",
+                        humantime::format_duration(timeout)
+                    )
+                })
+            })
+            .collect()
+    }
 }
 
 #[cfg(test)]
```

And in `cli/src/bin/posctl-admin.rs`, the names `init` looks the scripts up by come from the same constants:

```diff
--- a/cli/src/bin/posctl-admin.rs
+++ b/cli/src/bin/posctl-admin.rs
@@ -164,8 +164,8 @@ fn main() -> Result<()> {
             client_id,
             organization_id,
             pos_policy_id,
-            install_script_id: script("Install-PosTunnel")?,
-            invoke_script_id: script("Invoke-PosTunnel")?,
+            install_script_id: script(ninja::INSTALL_SCRIPT)?,
+            invoke_script_id: script(ninja::INVOKE_SCRIPT)?,
         };
         // A rerun keeps the relay this workstation already pins, also from a file that predates a field.
         let path = Config::path()?;
```

- [x] **Step 4: Check and commit**

Run `cargo fmt`, then the check. Expected: `test result: ok. 42 passed`, nothing from clippy or fmt.

```bash
git add cli/src/ninja.rs cli/src/bin/posctl-admin.rs
git commit -F - <<'EOF'
feat(cli): follow a script run to its result

script/run returns nothing to follow a run by, so posctl notes the device's newest activity
first, takes the oldest request after it as its run, and reads that series' COMPLETED activity
for the result and the script's output. run_scripts does this for many devices at once.

With POSCTL_CONFIG_HOME set the NinjaOne sign-in is a file there on every platform, so a second
identity has its own and a test never reads the real one.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

---

### Task 2: The relay client, the workstation's state and the session commands

**Files:**
- Create: `cli/src/relay.rs`, `cli/src/workstation.rs`, `cli/src/session.rs`
- Replace: `cli/src/fake.rs`
- Modify: `cli/src/lib.rs`

**Interfaces:**
- Consumes: Task 1's `Api` methods and `INVOKE_SCRIPT`; `fleet::find_pos`, `fleet::pos_devices`; `keys::{generate, public_line, parse_public, write_private_key, public_of_file}`; `config::{Config, NinjaOne, Relay, config_home, write_private}`.
- Produces (`posctl::relay`): `Lease { port: u16, device_id: i64, operator: String, started: String, idle_remaining: u64, absolute_remaining: u64, listening: bool }` (serde both ways); `Starting` (an error type); `trait Relay { fn tunnelctl(&self, command: &str) -> Result<String>; fn login(&self, alias: &str) -> Result<()>; }`; `ask<T: DeserializeOwned>(relay: &dyn Relay, command: &str) -> Result<T>`; `leases(relay: &dyn Relay) -> Result<Vec<Lease>>`; `port(device: &Device) -> Result<u16>`; `SshRelay { pub ssh: PathBuf, pub config: PathBuf }` implementing `Relay`.
- Produces (`posctl::workstation`): `Session { device_id: i64, name, alias, host_key, started: String }`; `alias(name: &str, device_id: i64, taken: &[&str]) -> String`; `Workstation { pub sessions, ssh_dir, ssh, operator_key: PathBuf, pub relay: config::Relay }` with `new(&Config) -> Result<Workstation>`, `config_file() -> PathBuf`, `session_key(device_id) -> PathBuf`, `check_operator_key() -> Result<()>`, `held() -> Result<Vec<Session>>`, `save(&Session, &PrivateKey) -> Result<()>`, `remove(device_id) -> Result<()>`, `reconcile(&[Lease]) -> Result<Vec<Session>>`, `write_ssh_files() -> Result<()>`, `ensure_include() -> Result<bool>`.
- Produces (`posctl::session`): `MAX_IDLE: Duration`; `Timing { poll, open, script, install, released: Duration }` with `Default`; `Context<'a> { api: &'a Api, ninja: &'a NinjaOne, relay: &'a dyn Relay, workstation: &'a Workstation, timing: Timing }`; `span(seconds: u64) -> String`; `How { Opened, Joined, AlreadyOpen }`; `Connected { alias: String, lease: Lease, how: How }`; `connect(&Context, name: &str, idle: Duration) -> Result<Connected>`; `keepalive(&Context, name) -> Result<Lease>`; `Row { name: String, alias: Option<String>, lease: Lease }`; `status(&Context, name: Option<&str>) -> Result<Vec<Row>>`; `PosSide { Confirmed(String), Offline, Unconfirmed(String) }`; `Closed { had_lease: bool, pos: PosSide }`; `close(&Context, name) -> Result<Closed>`; `pub(crate) end(&Context, &Device) -> Result<Closed>`; `rebuild(&Context, name) -> Result<Connected>`.
- Produces (`crate::fake`, tests only): `Pos { offline: bool, relay_key: String, host_key: String, version: &'static str, fail: Option<&'static str>, silent: bool }` with `Default`; `pos_tenant(Pos) -> (Fake, Pos)` (organization 3: device 1 `POS 000 Test` as given, 2 `POS 002` online, 3 `POS 003` offline; script IDs 93 install, 94 invoke); `FakeRelay::new(operator)` with `leases`, `logins`, `login_error`, `listening`, `starting_after`, `linger`, `calls()`, `count(command)`, `open_as(operator, device_id)`; `workstation(test: &str) -> Workstation`; `context(&Api, &FakeRelay, &Workstation) -> Context`.

- [x] **Step 1: List the modules**

`cli/src/lib.rs` becomes (Task 3 adds `rekey`):

```rust
//! The core `posctl` and `posctl-admin` share: config, keys, the NinjaOne API, the fleet and admin
//! operations, and `posctl`'s sessions. Design: `docs/design.md`.

pub mod admin;
pub mod bundle;
pub mod config;
pub mod fleet;
pub mod keys;
pub mod ninja;
pub mod relay;
pub mod session;
pub mod workstation;

#[cfg(test)]
mod fake;
```

- [x] **Step 2: Replace `cli/src/fake.rs`**

The existing `Fake` stays as it is; the rest is new.

```rust
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
```

- [x] **Step 3: Write the tests**

Create each of the three files holding only its tests module; Steps 5 to 7 put the code above it.

`cli/src/relay.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_port_is_20000_plus_the_device_id_within_range() {
        let device = |id: i64| {
            serde_json::from_value::<Device>(serde_json::json!({"id": id, "organizationId": 3}))
                .unwrap()
        };
        assert_eq!(port(&device(1)).unwrap(), 20001);
        assert_eq!(port(&device(45535)).unwrap(), 65535);
        for bad in [0, -4, 45536, 70000] {
            assert!(port(&device(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_lease_reads_from_tunnelctls_view() {
        // The relay's `_view`, with the fields posctl doesn't use.
        let view = r#"{"port": 20001, "device_id": 1, "operator": "Jacob", "started": "2026-10-13T15:00:00+00:00",
            "idle_deadline": "2026-10-14T03:00:00+00:00", "absolute_deadline": "2026-10-16T15:00:00+00:00",
            "idle_remaining": 43200, "absolute_remaining": 259200, "listening": false, "connections": 0}"#;
        let lease: Lease = serde_json::from_str(view).unwrap();
        assert_eq!(
            (lease.port, lease.operator.as_str(), lease.listening),
            (20001, "Jacob", false)
        );
        assert_eq!(lease.started, "2026-10-13T15:00:00+00:00");
    }
}
```

`cli/src/workstation.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::workstation;

    const HOST_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBxRa3sySInLyRMMVSWz76+abOp7xOibpSn1v7vw1k4x";

    fn session(device_id: i64, alias: &str, started: &str) -> Session {
        Session {
            device_id,
            name: format!("POS {device_id}"),
            alias: alias.into(),
            host_key: HOST_KEY.into(),
            started: started.into(),
        }
    }

    fn lease(device_id: i64, started: &str) -> Lease {
        Lease {
            port: 20000 + device_id as u16,
            device_id,
            operator: "Jacob".into(),
            started: started.into(),
            idle_remaining: 100,
            absolute_remaining: 1000,
            listening: true,
        }
    }

    #[test]
    fn an_alias_is_the_names_slug_with_one_pos_prefix() {
        assert_eq!(alias("POS 000 Test", 1, &[]), "pos-000-test");
        assert_eq!(alias("  Front  Till #2 ", 7, &[]), "pos-front-till-2");
        assert_eq!(alias("POS", 7, &[]), "pos-pos");
        // Nothing usable in the name: the device ID.
        assert_eq!(alias("!!!", 7, &[]), "pos-7");
        // Another session on this workstation has the alias already.
        assert_eq!(alias("pos 001", 9, &["pos-001"]), "pos-001-9");
    }

    #[test]
    fn a_saved_session_reads_back_and_remove_deletes_it() {
        let ws = workstation("state");
        assert!(ws.held().unwrap().is_empty());
        let key = keys::generate("test").unwrap();
        ws.save(&session(4, "pos-004", "t1"), &key).unwrap();
        ws.save(&session(1, "pos-001", "t2"), &key).unwrap();
        // Not a session: left alone and not listed.
        fs::create_dir_all(ws.sessions.join("notes")).unwrap();
        assert_eq!(
            ws.held().unwrap(),
            [session(1, "pos-001", "t2"), session(4, "pos-004", "t1")]
        );
        assert_eq!(
            keys::public_of_file(&ws.session_key(4)).unwrap(),
            keys::public_line(key.public_key()).unwrap()
        );
        ws.remove(4).unwrap();
        ws.remove(4).unwrap();
        assert_eq!(ws.held().unwrap(), [session(1, "pos-001", "t2")]);
        assert!(ws.sessions.join("notes").exists());
    }

    #[test]
    fn reconcile_drops_sessions_the_relay_no_longer_holds_as_they_were() {
        let ws = workstation("reconcile");
        let key = keys::generate("test").unwrap();
        for (id, started) in [(1, "t1"), (2, "t2"), (3, "t3")] {
            ws.save(&session(id, &format!("pos-{id}"), started), &key)
                .unwrap();
        }
        // 1 is as it was; 2 was closed and reopened by someone else; 3 has no lease.
        let held = ws.reconcile(&[lease(1, "t1"), lease(2, "later")]).unwrap();
        assert_eq!(held, [session(1, "pos-1", "t1")]);
        assert_eq!(ws.held().unwrap(), held);
        let config = fs::read_to_string(ws.config_file()).unwrap();
        assert!(
            config.contains("Host pos-1\n") && !config.contains("Host pos-2\n"),
            "{config}"
        );
    }

    #[test]
    fn the_generated_files_hold_the_relay_and_one_entry_per_session() {
        let ws = workstation("files");
        let key = keys::generate("test").unwrap();
        ws.save(&session(1, "pos-000-test", "t1"), &key).unwrap();
        ws.write_ssh_files().unwrap();
        let slashed = |path: PathBuf| path.to_string_lossy().replace('\\', "/");
        let config = fs::read_to_string(ws.config_file()).unwrap();
        let hosts = slashed(ws.ssh_dir.join("posctl").join("known_hosts"));
        let relay = format!(
            "Host posctl-relay\n  HostName relay.example.com\n  Port 2222\n  User jump\n  IdentityFile \"{}\"\n  IdentitiesOnly yes\n  HostKeyAlias posctl-relay\n  UserKnownHostsFile \"{hosts}\"\n  StrictHostKeyChecking yes\n  BatchMode yes\n",
            slashed(ws.operator_key.clone())
        );
        let pos = format!(
            "Host pos-000-test\n  HostName localhost\n  Port 20001\n  User support\n  ProxyCommand \"ssh\" -F \"{}\" -W \"[%h]:%p\" posctl-relay\n  IdentityFile \"{}\"\n  IdentitiesOnly yes\n  HostKeyAlias pos-1\n  UserKnownHostsFile \"{hosts}\"\n  StrictHostKeyChecking yes\n  BatchMode yes\n",
            slashed(ws.config_file()),
            slashed(ws.session_key(1))
        );
        assert!(config.contains(&relay), "{config}");
        assert!(config.ends_with(&format!("\n{pos}")), "{config}");
        assert!(!config.contains('\\'), "{config}");
        assert_eq!(
            fs::read_to_string(ws.ssh_dir.join("posctl").join("known_hosts")).unwrap(),
            format!("posctl-relay ssh-ed25519 AAAARELAY\npos-1 {HOST_KEY}\n")
        );
    }

    /// OpenSSH itself reads the generated config, spaces in its paths included.
    #[test]
    fn ssh_parses_the_generated_config() {
        let ws = workstation("parse");
        let key = keys::generate("test").unwrap();
        ws.save(&session(1, "pos-000-test", "t1"), &key).unwrap();
        ws.write_ssh_files().unwrap();
        let out = Command::new("ssh")
            .arg("-G")
            .arg("-F")
            .arg(ws.config_file())
            .arg("pos-000-test")
            .output()
            .unwrap();
        let parsed = String::from_utf8_lossy(&out.stdout).to_lowercase();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let slashed = |path: PathBuf| path.to_string_lossy().replace('\\', "/").to_lowercase();
        for line in [
            "hostname localhost".to_owned(),
            "port 20001".to_owned(),
            "user support".to_owned(),
            "hostkeyalias pos-1".to_owned(),
            format!("identityfile {}", slashed(ws.session_key(1))),
            format!(
                "userknownhostsfile {}",
                slashed(ws.ssh_dir.join("posctl").join("known_hosts"))
            ),
        ] {
            assert!(
                parsed.lines().any(|l| l == line),
                "no `{line}` in:\n{parsed}"
            );
        }
        assert!(parsed.contains("proxycommand \"ssh\" -f "), "{parsed}");
    }

    #[test]
    fn the_include_goes_first_once_and_keeps_the_rest_of_the_file() {
        let ws = workstation("include");
        // No file yet.
        assert!(ws.ensure_include().unwrap());
        let path = ws.ssh_dir.join("config");
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "Include posctl/config\n\n"
        );
        assert!(!ws.ensure_include().unwrap());

        // An Include inside a Host block applies to that host only, so it doesn't count.
        let existing =
            "# mine\nHost Coolify_Server\n  HostName 10.0.0.1\n  Include posctl/config\n";
        fs::write(&path, existing).unwrap();
        assert!(ws.ensure_include().unwrap());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            format!("Include posctl/config\n\n{existing}")
        );

        // Already there before the first block, in ssh_config's other spellings.
        for present in [
            "ServerAliveInterval 30\ninclude other posctl/config\nHost x\n",
            "Include=posctl/config\nMatch all\n",
        ] {
            fs::write(&path, present).unwrap();
            assert!(!ws.ensure_include().unwrap(), "{present}");
            assert_eq!(fs::read_to_string(&path).unwrap(), present);
        }
    }

    #[test]
    fn an_operator_key_without_a_passphrase_needs_no_agent() {
        let ws = workstation("plain key");
        keys::write_private_key(&ws.operator_key, &keys::generate("op").unwrap(), None).unwrap();
        ws.check_operator_key().unwrap();
    }

    #[test]
    fn an_encrypted_operator_key_the_agent_lacks_is_refused_with_the_commands() {
        let ws = workstation("encrypted key");
        keys::write_private_key(&ws.operator_key, &keys::generate("op").unwrap(), Some("pw"))
            .unwrap();
        // A key generated here can't be in any agent.
        let error = ws.check_operator_key().unwrap_err().to_string();
        assert!(
            error.contains("has a passphrase and ssh-agent doesn't hold it")
                && error.contains(&format!("ssh-add \"{}\"", ws.operator_key.display())),
            "{error}"
        );
    }
}
```

`cli/src/session.rs`:

```rust
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
```

- [x] **Step 4: Run them to watch them fail**

Run: `cargo test --lib 2>&1 | grep -E "^error" | sort -u | head -5`
Expected: compile errors, the tests' `use super::*` and `fake.rs`'s imports finding nothing yet, such as `` error[E0432]: unresolved imports `crate::relay::Lease`, `crate::relay::Relay`, `crate::relay::Starting` ``.

- [x] **Step 5: Write `relay.rs`**

Above the tests module in `cli/src/relay.rs`:

```rust
//! The relay as an operator reaches it (design sections 6.4 and 8): `tunnelctl` as `ctl` over OpenSSH's
//! client, and the login through a session's alias.

use std::fmt;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::ninja::Device;

/// A lease as `tunnelctl` prints it; what `posctl` doesn't use is ignored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Lease {
    pub port: u16,
    pub device_id: i64,
    /// Who opened it. An operator who joined later isn't recorded (design section 9).
    pub operator: String,
    /// When it was opened, as the relay printed it. Never compared with this machine's clock (design
    /// section 5): it only tells one session on a port from the next (design section 8).
    pub started: String,
    pub idle_remaining: u64,
    pub absolute_remaining: u64,
    /// The POS's tunnel is up.
    pub listening: bool,
}

/// `tunnelctl`'s exit status while the relay's daemon isn't answering (design section 6.4).
const EX_UNAVAILABLE: i32 = 75;
/// The first login as `support` on a POS waits for Windows to create its profile (design section 7.2).
const LOGIN_WAIT: Duration = Duration::from_secs(120);

/// The relay's daemon isn't answering yet (design section 6.4).
#[derive(Debug)]
pub struct Starting;

impl fmt::Display for Starting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "the relay is starting: POS logins are paused until its daemon is ready, and a POS retries within 2 minutes",
        )
    }
}

impl std::error::Error for Starting {}

/// What the session commands do through `ssh`; tests stand in for it.
pub trait Relay {
    /// `tunnelctl <command>` as `ctl`; its output. Fails with `Starting` while the daemon isn't
    /// answering.
    fn tunnelctl(&self, command: &str) -> Result<String>;
    /// Logs in through a session's alias once (design section 7.2, step 8).
    fn login(&self, alias: &str) -> Result<()>;
}

/// `tunnelctl <command>`, its JSON reply read as `T`.
pub fn ask<T: DeserializeOwned>(relay: &dyn Relay, command: &str) -> Result<T> {
    let reply = relay.tunnelctl(command)?;
    serde_json::from_str(&reply)
        .with_context(|| format!("tunnelctl answered something else than expected: {reply}"))
}

/// Every lease the relay holds.
pub fn leases(relay: &dyn Relay) -> Result<Vec<Lease>> {
    ask(relay, "status")
}

/// The device's tunnel port, 20000 + its NinjaOne ID (design section 4).
pub fn port(device: &Device) -> Result<u16> {
    match u16::try_from(device.id) {
        Ok(id @ 1..=45535) => Ok(20000 + id),
        _ => bail!(
            "device ID {} is outside 1..45535, so it has no tunnel port",
            device.id
        ),
    }
}

/// The real relay: OpenSSH's client with the generated config, which holds the relay's address, its
/// pinned public key and the operator key (design section 8).
pub struct SshRelay {
    pub ssh: PathBuf,
    pub config: PathBuf,
}

impl Relay for SshRelay {
    fn tunnelctl(&self, command: &str) -> Result<String> {
        let out = Command::new(&self.ssh)
            .arg("-F")
            .arg(&self.config)
            .args(["-o", "ConnectTimeout=15", "ctl@posctl-relay", "tunnelctl"])
            .args(command.split(' '))
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("running {}", self.ssh.display()))?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        match out.status.code() {
            Some(0) => Ok(String::from_utf8_lossy(&out.stdout).into_owned()),
            Some(EX_UNAVAILABLE) => Err(Starting.into()),
            // tunnelctl's own refusal, printed as "error: <why>".
            Some(1) => bail!(
                "the relay refused: {}",
                stderr.trim().trim_start_matches("error: ")
            ),
            _ => bail!("couldn't reach the relay: {}", stderr.trim()),
        }
    }

    fn login(&self, alias: &str) -> Result<()> {
        let mut child = Command::new(&self.ssh)
            .arg("-F")
            .arg(&self.config)
            .args(["-o", "ConnectTimeout=30", alias, "exit"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("running {}", self.ssh.display()))?;
        let deadline = Instant::now() + LOGIN_WAIT;
        loop {
            if let Some(status) = child.try_wait()? {
                if status.success() {
                    return Ok(());
                }
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    let _ = pipe.read_to_string(&mut stderr);
                }
                bail!("the login through {alias} failed: {}", stderr.trim());
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                bail!(
                    "the login through {alias} didn't finish within {}",
                    humantime::format_duration(LOGIN_WAIT)
                );
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}
```

- [x] **Step 6: Write `workstation.rs`**

Above the tests module in `cli/src/workstation.rs`:

```rust
//! This workstation's side of its sessions (design section 8): the session state dir, the generated
//! `ssh` files, the `Include` line, and the OpenSSH client and agent that serve them.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use ssh_key::PrivateKey;

use crate::config::{self, Config, config_home, write_private};
use crate::keys;
use crate::relay::Lease;

/// A session this workstation holds a key for: `sessions/<device id>/session.toml`, beside
/// `session_key`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Session {
    /// The directory's name; not in the file.
    #[serde(skip)]
    pub device_id: i64,
    pub name: String,
    pub alias: String,
    /// The POS's SSH server public key, pinned in the generated `known_hosts`.
    pub host_key: String,
    /// The lease's `started` when this workstation connected: the same value on the relay is the same
    /// session.
    pub started: String,
}

pub struct Workstation {
    /// `posctl/sessions` in the config dir.
    pub sessions: PathBuf,
    /// `~/.ssh`, or `POSCTL_SSH_DIR` (tests).
    pub ssh_dir: PathBuf,
    /// OpenSSH's client.
    pub ssh: PathBuf,
    pub operator_key: PathBuf,
    pub relay: config::Relay,
}

/// The display name's slug, prefixed `pos-` unless it starts so (design section 4): `POS 000 Test` is
/// `pos-000-test`. The device ID stands in for an empty slug and is appended to one in `taken`.
pub fn alias(name: &str, device_id: i64, taken: &[&str]) -> String {
    let mut slug = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug = slug.trim_end_matches('-');
    let alias = if slug.is_empty() {
        format!("pos-{device_id}")
    } else if slug.starts_with("pos-") {
        slug.to_owned()
    } else {
        format!("pos-{slug}")
    };
    if taken.contains(&alias.as_str()) {
        format!("{alias}-{device_id}")
    } else {
        alias
    }
}

impl Workstation {
    pub fn new(config: &Config) -> Result<Workstation> {
        let relay = config.relay.clone().context(
            "no relay yet: run the `posctl relay set ...` line the admin sent (the admin: `posctl-admin relay keygen`)",
        )?;
        let ssh_dir = match std::env::var_os("POSCTL_SSH_DIR") {
            Some(dir) => dir.into(),
            None => dirs::home_dir()
                .context("this platform has no home directory")?
                .join(".ssh"),
        };
        // On Windows the client Windows ships, else Win32-OpenSSH's own install, never the first `ssh`
        // on `PATH`: under Git Bash that is MSYS's, which can't reach the Windows ssh-agent.
        let mut ssh = PathBuf::from("ssh");
        #[cfg(windows)]
        for (root, rest) in [
            ("SystemRoot", r"System32\OpenSSH\ssh.exe"),
            ("ProgramFiles", r"OpenSSH\ssh.exe"),
        ] {
            let path = std::env::var_os(root).map(|root| PathBuf::from(root).join(rest));
            if let Some(path) = path.filter(|path| path.exists()) {
                ssh = path;
                break;
            }
        }
        Ok(Workstation {
            sessions: config_home()?.join("posctl").join("sessions"),
            ssh_dir,
            ssh,
            operator_key: config.operator_key.clone(),
            relay,
        })
    }

    /// The generated `ssh` config: what `posctl`'s own `ssh` calls and every alias's hop read.
    pub fn config_file(&self) -> PathBuf {
        self.ssh_dir.join("posctl").join("config")
    }

    pub fn session_key(&self, device_id: i64) -> PathBuf {
        self.sessions
            .join(device_id.to_string())
            .join("session_key")
    }

    /// Stops when the operator key has a passphrase and `ssh-agent` doesn't hold it: `ssh` runs
    /// non-interactively, so it would be refused with no hint why (design section 8).
    pub fn check_operator_key(&self) -> Result<()> {
        let key = &self.operator_key;
        let text = fs::read_to_string(key).with_context(|| format!("reading {}", key.display()))?;
        let private = PrivateKey::from_openssh(&text)
            .with_context(|| format!("{} is not an OpenSSH private key", key.display()))?;
        if !private.is_encrypted() {
            return Ok(());
        }
        let public = keys::public_line(private.public_key())?;
        let ssh_add = self.ssh.with_file_name(if cfg!(windows) {
            "ssh-add.exe"
        } else {
            "ssh-add"
        });
        // An agent that isn't running fails here and counts as not holding it.
        let held = Command::new(ssh_add).arg("-L").output().is_ok_and(|out| {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .any(|line| keys::parse_public(line).is_ok_and(|listed| listed == public))
        });
        if held {
            return Ok(());
        }
        let start_agent = if cfg!(windows) {
            "  Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile', '-Command', 'Set-Service ssh-agent -StartupType Automatic; Start-Service ssh-agent'\n"
        } else {
            ""
        };
        bail!(
            "the operator key {0} has a passphrase and ssh-agent doesn't hold it. Add it once:\n{start_agent}  ssh-add \"{0}\"",
            key.display()
        );
    }

    /// The sessions this workstation holds state for, by device ID. Anything in the dir that isn't a
    /// session `save` wrote is left alone.
    pub fn held(&self) -> Result<Vec<Session>> {
        let entries = match fs::read_dir(&self.sessions) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(e).with_context(|| format!("reading {}", self.sessions.display()));
            }
        };
        let mut sessions = Vec::new();
        for entry in entries {
            let dir = entry?.path();
            let device_id = dir
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.parse::<i64>().ok());
            let session = fs::read_to_string(dir.join("session.toml"))
                .ok()
                .and_then(|text| toml::from_str::<Session>(&text).ok());
            if let (Some(device_id), Some(session)) = (device_id, session) {
                sessions.push(Session {
                    device_id,
                    ..session
                });
            }
        }
        sessions.sort_by_key(|session| session.device_id);
        Ok(sessions)
    }

    pub fn save(&self, session: &Session, key: &PrivateKey) -> Result<()> {
        keys::write_private_key(&self.session_key(session.device_id), key, None)?;
        let path = self
            .sessions
            .join(session.device_id.to_string())
            .join("session.toml");
        write_private(&path, toml::to_string(session)?.as_bytes())
    }

    /// Deletes a session's state, key included; no error if there is none.
    pub fn remove(&self, device_id: i64) -> Result<()> {
        let dir = self.sessions.join(device_id.to_string());
        match fs::remove_dir_all(&dir) {
            Err(e) if e.kind() != ErrorKind::NotFound => {
                Err(e).with_context(|| format!("deleting {}", dir.display()))
            }
            _ => Ok(()),
        }
    }

    /// Drops the state of every session the relay no longer holds as this workstation knew it (ended,
    /// or reopened elsewhere), rewrites the generated files, and returns the sessions still held.
    pub fn reconcile(&self, leases: &[Lease]) -> Result<Vec<Session>> {
        let (live, stale): (Vec<Session>, Vec<Session>) =
            self.held()?.into_iter().partition(|session| {
                leases
                    .iter()
                    .any(|l| l.device_id == session.device_id && l.started == session.started)
            });
        for session in &stale {
            self.remove(session.device_id)?;
        }
        self.write_ssh_files()?;
        Ok(live)
    }

    /// Rewrites the generated `config` and `known_hosts` whole from the config and the session state;
    /// nothing edits them in place (design section 8).
    pub fn write_ssh_files(&self) -> Result<()> {
        // Forward-slashed and quoted: a profile path may hold a space, and `ssh_config` reads a
        // backslash before a quote as an escape.
        let quoted = |path: &Path| format!("\"{}\"", path.to_string_lossy().replace('\\', "/"));
        let dir = self.ssh_dir.join("posctl");
        let known_hosts = quoted(&dir.join("known_hosts"));
        let mut config = format!(
            "# Generated by posctl and rewritten by every session command: edits are lost.\n\
             Host posctl-relay\n  HostName {}\n  Port {}\n  User jump\n  IdentityFile {}\n  IdentitiesOnly yes\n  \
             HostKeyAlias posctl-relay\n  UserKnownHostsFile {known_hosts}\n  StrictHostKeyChecking yes\n  BatchMode yes\n",
            self.relay.host,
            self.relay.port,
            quoted(&self.operator_key),
        );
        let mut hosts = format!("posctl-relay {}\n", self.relay.public_key);
        for session in self.held()? {
            // ProxyCommand, not ProxyJump: Windows' client hands its own -F to the jump unquoted, and
            // naming the client keeps the hop in it (and its agent) when Git Bash's ssh runs the alias.
            config.push_str(&format!(
                "\nHost {}\n  HostName localhost\n  Port {}\n  User support\n  \
                 ProxyCommand {} -F {} -W \"[%h]:%p\" posctl-relay\n  IdentityFile {}\n  IdentitiesOnly yes\n  \
                 HostKeyAlias pos-{}\n  UserKnownHostsFile {known_hosts}\n  StrictHostKeyChecking yes\n  BatchMode yes\n",
                session.alias,
                20000 + session.device_id,
                quoted(&self.ssh),
                quoted(&self.config_file()),
                quoted(&self.session_key(session.device_id)),
                session.device_id,
            ));
            hosts.push_str(&format!("pos-{} {}\n", session.device_id, session.host_key));
        }
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        fs::write(self.config_file(), config)?;
        fs::write(dir.join("known_hosts"), hosts)?;
        Ok(())
    }

    /// Makes `~/.ssh/config` read the generated file: adds `Include posctl/config` as its first line
    /// unless that line already precedes every `Host` and `Match` block (inside one it would apply to
    /// that block only). Returns whether it changed the file.
    pub fn ensure_include(&self) -> Result<bool> {
        let path = self.ssh_dir.join("config");
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        for line in text.lines() {
            // `Keyword value` or `Keyword=value`.
            let mut words = line
                .split(|c: char| c.is_whitespace() || c == '=')
                .filter(|word| !word.is_empty());
            let keyword = words.next().unwrap_or_default();
            if keyword.eq_ignore_ascii_case("Host") || keyword.eq_ignore_ascii_case("Match") {
                break;
            }
            if keyword.eq_ignore_ascii_case("Include") && words.any(|word| word == "posctl/config")
            {
                return Ok(false);
            }
        }
        fs::create_dir_all(&self.ssh_dir)?;
        fs::write(&path, format!("Include posctl/config\n\n{text}"))
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(true)
    }
}
```

- [x] **Step 7: Write `session.rs`**

Above the tests module in `cli/src/session.rs`:

```rust
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
}

impl Default for Timing {
    fn default() -> Timing {
        Timing {
            poll: Duration::from_secs(3),
            open: Duration::from_secs(180),
            script: Duration::from_secs(120),
            install: Duration::from_secs(900),
            released: Duration::from_secs(60),
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
```

- [x] **Step 8: Check and commit**

Run `cargo fmt`, then the check. Expected: `test result: ok. 73 passed`, nothing from clippy or fmt. `workstation::tests::ssh_parses_the_generated_config` runs the `ssh` on `PATH` with `-G`, which only parses.

```bash
git add cli/src/lib.rs cli/src/fake.rs cli/src/relay.rs cli/src/workstation.rs cli/src/session.rs
git commit -F - <<'EOF'
feat(cli): session commands: connect, keepalive, status, close, rebuild

connect opens a session or joins the one another workstation holds, waits for the POS's own
report and for the tunnel, writes the alias and logs in through it once; a failure after the
lease is opened is undone. keepalive renews the relay, then the POS through NinjaOne. close ends
the session for every operator on it, the relay first. The relay is reached through OpenSSH's
client behind a trait the tests replace.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

---

### Task 3: `rekey`

**Files:**
- Create: `cli/src/rekey.rs`
- Modify: `cli/src/lib.rs`

**Interfaces:**
- Consumes: `session::Context`; `relay::leases`; `Relay::tunnelctl`; `Api::run_scripts`; `fleet::{find_pos, pos_devices}`; `Workstation::{remove, write_ssh_files}`; the Task 2 test stand-ins.
- Produces (`posctl::rekey`): `Plan { pub targets: Vec<(Device, Option<u16>)>, pub skipped: Vec<(String, String)> }` (each target with the port of the relay lease to close first, if any; each skipped POS by name with why); `Outcome { Rekeyed, Skipped(String), Failed(String) }`; `plan(&Context, name: Option<&str>, force: bool) -> Result<Plan>`; `run(&Context, Plan, force: bool) -> Result<Vec<(String, Outcome)>>`.

- [x] **Step 1: Add the module**

In `cli/src/lib.rs`, between `pub mod ninja;` and `pub mod relay;`:

```rust
pub mod rekey;
```

- [x] **Step 2: Write the tests**

Create `cli/src/rekey.rs` holding only its tests module:

```rust
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
```

- [x] **Step 3: Run them to watch them fail**

Run: `cargo test --lib rekey 2>&1 | grep -E "^error" | sort -u | head -5`
Expected: compile errors, such as `` error[E0425]: cannot find function `plan` in this scope ``.

- [x] **Step 4: Write `rekey.rs`**

Above the tests module:

```rust
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
```

- [x] **Step 5: Check and commit**

Run `cargo fmt`, then the check. Expected: `test result: ok. 80 passed`, nothing from clippy or fmt.

```bash
git add cli/src/lib.rs cli/src/rekey.rs
git commit -F - <<'EOF'
feat(cli): rekey one POS or every online one, with --force ending a session first

A POS that is offline or in a session is refused when named and skipped among all. --force closes
the relay lease and runs Close on the POS, with a lease or not, before the rekey, so a session
left on the POS alone doesn't block it. All POSes run together and each fails alone.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

---

### Task 4: The command line and the end-to-end test

**Files:**
- Create: `tests/cli/test_sessions.py`
- Replace: `cli/src/bin/posctl.rs`
- Modify: `tests/cli/test_relay_setup.py`, `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: everything Tasks 1 to 3 produce; `tests/cli/test_relay_setup.py`'s `Setup`, `config_of`, `sh`, `wait_for`.
- Produces: the commands `posctl connect <name> [--idle-timeout <dur>]`, `keepalive <name>`, `status [<name>]`, `close <name>`, `rebuild <name> [--yes]`, `update <name>`, `rekey <name> | --all [--force] [--yes]`. Environment: `POSCTL_SSH_DIR` replaces `~/.ssh`. Output lines the test relies on: `<name> is connected: ssh <alias>`, `Joined the session <operator> opened on <name>: ssh <alias>`, `<name> is renewed. Idle timeout in ...`, `<name> reports: <the POS's close line>.`, `<name> is rebuilt: ssh <alias>`, `<name>: rekeyed`, `No open sessions.`

- [x] **Step 1: Write the end-to-end test**

First two helpers in `tests/cli/test_relay_setup.py`, for both test files: on Windows, Windows' own `ssh` tools whatever shell runs pytest, and a temp dir that isn't pytest's owner-only one (design section 11: Windows' `ssh` refuses a key file under it).

```diff
--- a/tests/cli/test_relay_setup.py
+++ b/tests/cli/test_relay_setup.py
@@ -1,8 +1,10 @@
 # Standard library imports
 import json
 import os
+import shutil
 import socket
 import subprocess
+import tempfile
 import time
 import tomllib
 import uuid
@@ -48,6 +50,26 @@ def free_port() -> int:
     return s.getsockname()[1]
 
 
+def openssh(tool: str) -> str:
+  """OpenSSH's `tool`: on Windows the one Windows ships, which posctl runs too (design 8).
+
+  Under Git Bash `PATH`'s is MSYS's, and Windows' `ssh` refuses a key file MSYS's `ssh-keygen` made.
+  """
+  shipped = Path(os.environ.get("SystemRoot", "")) / "System32" / "OpenSSH" / f"{tool}.exe"
+  return str(shipped) if os.name == "nt" and shipped.exists() else tool
+
+
+def workdir(name: str) -> Path:
+  """A temp dir for homes and key files, which the caller removes.
+
+  Not pytest's `tmp_path`: Python makes those owner-only (mode 0o700), on Windows an ACL whose OWNER RIGHTS
+  entry every file below inherits, and Windows' `ssh` refuses a private key that carries one.
+  """
+  path = Path(tempfile.gettempdir()) / f"posctl-{name}-{uuid.uuid4().hex[:8]}"
+  path.mkdir()
+  return path
+
+
 def config_of(home: Path) -> dict[str, Any]:
   return tomllib.loads((home / "posctl" / "config.toml").read_text(encoding="utf-8"))
 
@@ -63,7 +85,7 @@ class Setup:
     self.volume = f"setup-data-{self.tag}"
     self.bundle = ""
     admin_key = tmp / "admin_key"
-    sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", str(admin_key))
+    sh(openssh("ssh-keygen"), "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", str(admin_key))
     admin_pub = " ".join(admin_key.with_suffix(".pub").read_text(encoding="utf-8").split()[:2])
     # posctl-admin runs only with the admin key built into it, so build one with this test's.
     sh("cargo", "build", "--bins", cwd=ROOT, env={**os.environ, "POSCTL_ADMIN_KEY": admin_pub})
@@ -126,15 +148,16 @@ class Setup:
     known_hosts = home / "known_hosts"
     known_hosts.write_text(f"[127.0.0.1]:{self.port} {config['relay']['public_key']}\n", encoding="utf-8")
     return sh(
-      "ssh", "-F", "none", "-p", str(self.port), "-i", config["operator_key"], "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
+      openssh("ssh"), "-F", "none", "-p", str(self.port), "-i", config["operator_key"], "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
       "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}", "ctl@127.0.0.1", "tunnelctl", "status",
       check=False, timeout=30,
     )  # fmt: skip
 
 
 @pytest.fixture(scope="module")
-def setup(tmp_path_factory: pytest.TempPathFactory):
-  s = Setup(tmp_path_factory.mktemp("setup"))
+def setup():
+  base = workdir("setup")
+  s = Setup(base)
   try:
     relay_line = s.run("posctl-admin", "relay", "keygen", f"127.0.0.1:{s.port}", home=s.admin_home).stdout.strip()
     s.bundle, operators_line = s.run("posctl-admin", "operator", "add", "bob", home=s.admin_home).stdout.splitlines()
@@ -144,6 +167,7 @@ def setup(tmp_path_factory: pytest.TempPathFactory):
   finally:
     if os.environ.get("POS_TUNNEL_KEEP") != "1":
       s.down()
+      shutil.rmtree(base, ignore_errors=True)
 
 
 def test_the_admin_reaches_tunnelctl_with_the_relay_key_pinned(setup: Setup):
```

Then `tests/cli/test_sessions.py`. The stand-in POS is a container from the relay's test image running its own `sshd` for `support`; the fake NinjaOne runs in the test process and turns each script run into what the POS package would do, recorded as NinjaOne records it.

```python
# Standard library imports
import json
import os
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any, override
from urllib.parse import parse_qs, urlsplit

# Third party imports
import pytest
from test_relay_setup import Setup, config_of, openssh, sh, wait_for, workdir

if TYPE_CHECKING:
  # Standard library imports
  import subprocess
  from pathlib import Path

pytestmark = pytest.mark.skipif(os.environ.get("POS_TUNNEL_DOCKER") != "1", reason="Docker tests: set POS_TUNNEL_DOCKER=1")

# `install_script_id` in the config `Setup` writes; any other script is Invoke-PosTunnel.
INSTALL_SCRIPT = 2
# The admin's session key and bob's.
BOTH_OPERATORS = 2


class Pos:
  """A stand-in POS: a container with an sshd for `support` that does what the POS package's actions do."""

  def __init__(self, setup: Setup) -> None:
    self.name = f"setup-pos-{setup.tag}"
    self.relay = setup.relay
    # usermod: an account created locked is refused even for key auth (design 6.1).
    init = (
      "useradd -m -s /bin/sh support && usermod -p '*' support && mkdir -p /run/sshd"
      " && ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key"
      " && ssh-keygen -q -t ed25519 -N '' -C '' -f /root/relay_key && touch /etc/ssh/session_keys"
      " && exec /usr/sbin/sshd -D -e -o ListenAddress=127.0.0.1 -o AuthorizedKeysFile=/etc/ssh/session_keys -o PasswordAuthentication=no"
    )
    sh(
      "docker",
      "run",
      "-d",
      "--name",
      self.name,
      "--network",
      setup.network,
      "--entrypoint",
      "/bin/sh",
      "pos-tunnel-relay:test",
      "-c",
      init,
    )
    wait_for("the stand-in POS", lambda: self.exec("pgrep", "-x", "sshd", check=False).returncode == 0, timeout=30)
    relay_key = config_of(setup.admin_home)["relay"]["public_key"]
    self.exec("sh", "-c", f"echo '[{self.relay}]:2222 {relay_key}' > /root/known_hosts")

  def exec(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return sh("docker", "exec", self.name, *args, check=check)

  def public_key(self, path: str) -> str:
    return " ".join(self.exec("cat", path).stdout.split()[:2])

  def session_keys(self) -> int:
    return len(self.exec("cat", "/etc/ssh/session_keys").stdout.splitlines())

  def run(self, script: int, parameters: str) -> str:
    """Run a library script as the POS would, returning its output (design 7.1 to 7.8)."""
    words = parameters.split()
    named = dict(zip(words[::2], words[1::2], strict=False))
    output = f"FAILED\tinvoke\tunexpected {parameters}"
    match script == INSTALL_SCRIPT, named.get("-Action"), named.get("-Mode", "New"):
      case True, _, _:
        output = "OK\tsignature\r\nOK\tcurrent\tversion 4"
      case _, "Open", "New":
        self.exec("sh", "-c", f"echo 'ssh-ed25519 {named['-SessionKey']}' > /etc/ssh/session_keys")
        sh(
          "docker", "exec", "-d", self.name, "ssh", "-N", "-F", "none", "-i", "/root/relay_key", "-o", "BatchMode=yes",
          "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=/root/known_hosts", "-o", "ExitOnForwardFailure=yes",
          "-R", f"{named['-Port']}:127.0.0.1:22", "-p", "2222", f"tunnel@{self.relay}",
        )  # fmt: skip
        output = f"CHANGED\tsession key\r\nCHANGED\ttunnel\tport {named['-Port']}"
      case _, "Open", "Join":
        self.exec("sh", "-c", f"echo 'ssh-ed25519 {named['-SessionKey']}' >> /etc/ssh/session_keys")
        output = f"CHANGED\tsession key\tadded, {self.session_keys()} session keys\r\nCHANGED\tlease\trenewed"
      case _, "Close", _:
        keys = self.session_keys()
        # -x: the tunnel is the only `ssh`; -f would match this very shell.
        self.exec("sh", "-c", "pkill -x ssh; : > /etc/ssh/session_keys")
        output = f"CHANGED\ttunnel\tstopped\r\nOK\tclose\tsession ended, {keys} session keys"
      case _, "Touch", _:
        output = "CHANGED\tlease\trenewed"
      case _, "Rekey", _:
        self.exec("sh", "-c", "rm -f /root/relay_key /root/relay_key.pub && ssh-keygen -q -t ed25519 -N '' -C '' -f /root/relay_key")
        output = "CHANGED\trelay key pair\tregenerated"
      case _:
        pass
    return output


class Ninja:
  """A fake NinjaOne with one POS (device 1 of organization 4): a script run acts on the stand-in and is recorded as NinjaOne does."""

  def __init__(self, pos: Pos) -> None:
    self.pos = pos
    self.activities: list[dict[str, Any]] = []
    self.lock = threading.Lock()
    ninja = self

    class Handler(BaseHTTPRequestHandler):
      @override
      def log_message(self, format: str, *args: Any) -> None:
        pass

      def reply(self, status: int, body: object) -> None:
        data = b"" if body is None else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

      def do_GET(self) -> None:
        self.reply(*ninja.get(self.path))

      def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.reply(*ninja.post(self.path, body))

    self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    self.url = f"http://127.0.0.1:{self.server.server_port}"
    threading.Thread(target=self.server.serve_forever, daemon=True).start()

  def get(self, path: str) -> tuple[int, object]:
    url = urlsplit(path)
    query = {name: values[0] for name, values in parse_qs(url.query).items()}
    match url.path.split("/")[2:]:
      case ["organization", "4", "devices"]:
        device = {"id": 1, "displayName": "POS 1", "organizationId": 4, "rolePolicyId": 1, "offline": False}
        return 200, [] if int(query.get("after", 0)) else [device]
      case ["device", "1", "custom-fields"]:
        fields = {
          "posTunnelRelayKey": self.pos.public_key("/root/relay_key.pub"),
          "posTunnelHostKey": self.pos.public_key("/etc/ssh/ssh_host_ed25519_key.pub"),
          "posTunnelVersion": "4",
        }
        return 200, fields
      case ["device", "1", "activities"]:
        with self.lock:
          recorded = list(self.activities)
        if "seriesUid" in query:
          listed = [a for a in recorded if a["seriesUid"] == query["seriesUid"]]
        else:
          listed = [a for a in recorded if a["id"] > int(query.get("newerThan", 0))]
        # Newest first, as NinjaOne lists them.
        return 200, {"activities": listed[::-1], "lastNodeActivityId": recorded[-1]["id"] if recorded else None}
      case _:
        return 404, {}

  def post(self, path: str, body: bytes) -> tuple[int, object]:
    if path == "/ws/oauth/token":
      return 200, {"access_token": "t"}
    if path != "/v2/device/1/script/run":
      return 404, {}
    run = json.loads(body)
    output = self.pos.run(run["id"], run["parameters"])
    done = {
      "activityResult": "FAILURE" if output.startswith("FAILED") else "SUCCESS",
      "data": {"message": {"params": {"output_message": output}}},
    }
    with self.lock:
      series = f"series-{len(self.activities)}"
      for kind, status, extra in (("ACTIONSET", "START_REQUESTED", {}), ("ACTION", "STARTED", {}), ("ACTION", "COMPLETED", done)):
        self.activities.append(
          {
            "id": len(self.activities) + 1,
            "deviceId": 1,
            "activityType": kind,
            "statusCode": status,
            "sourceName": "Install-PosTunnel" if run["id"] == INSTALL_SCRIPT else "Invoke-PosTunnel",
            "seriesUid": series,
            "parameters": run["parameters"],
            **extra,
          }
        )
    return 204, None

  def actions(self) -> list[str]:
    """The parameters of every script run so far, in order."""
    with self.lock:
      return [a["parameters"] for a in self.activities if a["statusCode"] == "START_REQUESTED"]


class Stack:
  """The real relay, a stand-in POS and a fake NinjaOne, with the admin's and bob's posctl set up against them."""

  def __init__(self, setup: Setup, pos: Pos, ninja: Ninja) -> None:
    self.setup, self.pos, self.ninja = setup, pos, ninja
    self.admin, self.bob = setup.admin_home, setup.bob_home

  def posctl(self, home: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "POSCTL_CONFIG_HOME": str(home), "POSCTL_SSH_DIR": str(home / "ssh")}
    exe = self.setup.bin / ("posctl.exe" if os.name == "nt" else "posctl")
    # stdin: a pipe, never the terminal pytest may have, so nothing waits on a prompt.
    result = sh(str(exe), *args, env=env, check=False, timeout=300, stdin="")
    if check and result.returncode:
      pytest.fail(f"posctl {' '.join(args)} exited {result.returncode}:\n{result.stdout}{result.stderr}")
    return result

  def ssh(self, home: Path, command: str) -> subprocess.CompletedProcess[str]:
    """What an operator runs: the alias, through the generated config."""
    return sh(
      openssh("ssh"),
      "-F",
      str(home / "ssh" / "posctl" / "config"),
      "-o",
      "ConnectTimeout=20",
      "pos-1",
      command,
      check=False,
      timeout=90,
    )

  def leases(self) -> list[dict[str, Any]]:
    return json.loads(self.setup.ctl_status(self.admin).stdout)


@pytest.fixture(scope="module")
def stack():
  base = workdir("sessions")
  s = Setup(base)
  pos = None
  try:
    relay_line = s.run("posctl-admin", "relay", "keygen", f"127.0.0.1:{s.port}", home=s.admin_home).stdout.strip()
    s.bundle, operators_line = s.run("posctl-admin", "operator", "add", "bob", home=s.admin_home).stdout.splitlines()
    s.up(relay_line, operators_line)
    wait_for("the relay", lambda: s.ctl_status(s.admin_home).returncode == 0, timeout=120)
    pos = Pos(s)
    ninja = Ninja(pos)
    s.run("posctl", "operator", "import", home=s.bob_home, stdin=s.bundle + "\n")
    for home in (s.admin_home, s.bob_home):
      config = home / "posctl" / "config.toml"
      config.write_text(config.read_text(encoding="utf-8").replace("https://example.invalid", ninja.url), encoding="utf-8")
      # With POSCTL_CONFIG_HOME set the sign-in is this file on every platform (design 8).
      (home / "posctl" / "refresh_token").write_text("unused", encoding="utf-8")
    yield Stack(s, pos, ninja)
  finally:
    if os.environ.get("POS_TUNNEL_KEEP") != "1":
      if pos:
        sh("docker", "rm", "-f", pos.name, check=False)
      s.down()
      shutil.rmtree(base, ignore_errors=True)


def test_connect_opens_a_session_the_alias_reaches(stack: Stack):
  result = stack.posctl(stack.admin, "connect", "POS 1", "--idle-timeout", "2h")

  assert "POS 1 is connected: ssh pos-1" in result.stdout, result.stdout + result.stderr
  assert stack.ssh(stack.admin, "whoami").stdout.strip() == "support"
  assert (stack.admin / "ssh" / "config").read_text(encoding="utf-8").startswith("Include posctl/config\n")


def test_status_shows_the_session_with_its_alias(stack: Stack):
  result = stack.posctl(stack.admin, "status")

  header, row = result.stdout.splitlines()
  assert header.split() == ["POS", "ALIAS", "OPENED", "BY", "IDLE", "LEFT", "MAX", "LEFT", "TUNNEL"]
  assert row.split()[:4] == ["POS", "1", "pos-1", "admin"]
  assert row.split()[-1] == "up"


def test_a_second_operator_joins_and_both_reach_the_pos(stack: Stack):
  result = stack.posctl(stack.bob, "connect", "POS 1")

  assert "Joined the session admin opened on POS 1: ssh pos-1" in result.stdout, result.stdout + result.stderr
  assert stack.ssh(stack.bob, "whoami").stdout.strip() == "support"
  assert stack.ssh(stack.admin, "whoami").stdout.strip() == "support"
  assert stack.pos.session_keys() == BOTH_OPERATORS
  # One lease still: the relay records the opener only.
  assert [lease["operator"] for lease in stack.leases()] == ["admin"]


def test_keepalive_renews_the_relay_and_the_pos(stack: Stack):
  result = stack.posctl(stack.bob, "keepalive", "POS 1")

  assert "POS 1 is renewed. Idle timeout in 2h 0m" in result.stdout, result.stdout + result.stderr
  assert stack.ninja.actions()[-1] == "-Action Touch"


def test_close_ends_the_session_for_both_operators(stack: Stack):
  result = stack.posctl(stack.admin, "close", "POS 1")

  assert "POS 1 reports: session ended, 2 session keys." in result.stdout, result.stdout + result.stderr
  assert stack.ssh(stack.bob, "whoami").returncode != 0
  # The relay drops the closed lease at its next pass; bob's alias goes with it.
  wait_for("the lease to go", lambda: "No open sessions." in stack.posctl(stack.bob, "status").stdout, timeout=30)
  assert "Host pos-1" not in (stack.bob / "ssh" / "posctl" / "config").read_text(encoding="utf-8")
  assert not (stack.bob / "posctl" / "sessions" / "1").exists()


def test_rebuild_reopens_with_a_new_lease(stack: Stack):
  stack.posctl(stack.admin, "connect", "POS 1")
  before = stack.leases()[0]["started"]

  refused = stack.posctl(stack.admin, "rebuild", "POS 1", check=False)
  assert refused.returncode != 0
  assert "AI agents: do not run this on your own initiative" in refused.stderr
  assert "pass --yes" in refused.stderr
  assert stack.leases()[0]["started"] == before
  result = stack.posctl(stack.admin, "rebuild", "POS 1", "--yes")

  assert "POS 1 is rebuilt: ssh pos-1" in result.stdout, result.stdout + result.stderr
  assert stack.leases()[0]["started"] != before
  assert stack.ssh(stack.admin, "whoami").stdout.strip() == "support"


def test_rekey_refuses_a_pos_in_a_session_and_force_ends_it_first(stack: Stack):
  relay_key = stack.pos.public_key("/root/relay_key.pub")

  refused = stack.posctl(stack.admin, "rekey", "POS 1", check=False)
  assert refused.returncode != 0
  assert "POS 1 is in a session admin opened" in refused.stderr
  result = stack.posctl(stack.admin, "rekey", "POS 1", "--force")

  assert result.stdout.strip() == "POS 1: rekeyed", result.stdout + result.stderr
  assert stack.ninja.actions()[-2:] == ["-Action Close", "-Action Rekey"]
  assert stack.pos.public_key("/root/relay_key.pub") != relay_key
  # The next session uses the POS's new relay key; connect waits out the lease just closed, which the relay still lists.
  assert "POS 1 is connected" in stack.posctl(stack.admin, "connect", "POS 1").stdout
  assert stack.ssh(stack.admin, "whoami").stdout.strip() == "support"


def test_update_prints_the_installs_report(stack: Stack):
  result = stack.posctl(stack.admin, "update", "POS 1")

  assert result.stdout.splitlines() == ["OK\tsignature", "OK\tcurrent\tversion 4"]
  stack.posctl(stack.admin, "close", "POS 1")
```

- [x] **Step 2: Run it to watch it fail**

With Docker running:

```bash
POS_TUNNEL_DOCKER=1 uv run pytest tests/cli/test_sessions.py -x -q --no-cov 2>&1 | grep -vE "^\s*$" | tail -6
```

Expected: the first test fails with `posctl connect POS 1 --idle-timeout 2h exited 1:` and `Error: not implemented yet`.

- [x] **Step 3: Write `cli/src/bin/posctl.rs`**

```rust
//! `posctl`: on-demand SSH sessions to NinjaOne-managed POS machines. Design: `docs/design.md`.

use std::io::IsTerminal;
use std::time::Duration;

use anyhow::{Result, bail};
use clap::{ArgGroup, Parser, Subcommand};
use posctl::bundle::Bundle;
use posctl::config::{Config, Relay, config_home, parse_host_port, write_private};
use posctl::ninja::{Api, INSTALL_SCRIPT};
use posctl::rekey::{self, Outcome};
use posctl::relay::SshRelay;
use posctl::session::{self, Context, How, MAX_IDLE, PosSide, Timing, span};
use posctl::workstation::Workstation;
use posctl::{fleet, keys, ninja};

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
    /// join the one another operator has open on it.
    Connect {
        name: String,
        /// Idle timeout of a session this opens, at most the 12h default. A session joined keeps its
        /// own.
        #[arg(long, value_parser = parse_idle_timeout)]
        idle_timeout: Option<Duration>,
    },
    /// Renew the session's idle timeout on the relay and the POS.
    Keepalive { name: String },
    /// Show open sessions and their remaining time.
    Status { name: Option<String> },
    /// Close a session for every operator on it and tear down both sides.
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
    /// Give a POS new key pairs: its relay key pair and its SSH server key pair.
    #[command(group(ArgGroup::new("target").required(true).args(["name", "all"])))]
    Rekey {
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

/// `--yes`, or a `y` typed at the terminal. Without a terminal there is nobody to ask, so an agent's
/// shell gets a refusal that names the flag instead of a prompt it can't answer (design section 7.6).
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
        }
        command => {
            let config = Config::load()?;
            let ninja = &config.ninjaone;
            let workstation = Workstation::new(&config)?;
            workstation.check_operator_key()?;
            let api = Api::connect(&ninja.base_url, &ninja.client_id)?;
            // The relay's entry, which `tunnelctl` is reached through.
            workstation.write_ssh_files()?;
            let relay = SshRelay {
                ssh: workstation.ssh.clone(),
                config: workstation.config_file(),
            };
            let ctx = Context {
                api: &api,
                ninja,
                relay: &relay,
                workstation: &workstation,
                timing: Timing::default(),
            };
            let deadlines = |lease: &posctl::relay::Lease| {
                format!(
                    "Idle timeout in {}; the session ends in {} at the latest.",
                    span(lease.idle_remaining),
                    span(lease.absolute_remaining)
                )
            };
            match command {
                Command::Connect { name, idle_timeout } => {
                    let connected =
                        session::connect(&ctx, &name, idle_timeout.unwrap_or(MAX_IDLE))?;
                    let (lease, alias) = (&connected.lease, &connected.alias);
                    match connected.how {
                        How::Opened => println!("{name} is connected: ssh {alias}"),
                        How::Joined => {
                            println!(
                                "Joined the session {} opened on {name}: ssh {alias}",
                                lease.operator
                            );
                            if idle_timeout.is_some() {
                                println!(
                                    "--idle-timeout applies only to a session this opens; this one keeps its own."
                                );
                            }
                        }
                        How::AlreadyOpen => println!(
                            "{name} is already connected (tunnel {}): ssh {alias}",
                            if lease.listening { "up" } else { "down" }
                        ),
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
                        bail!("{failed} POS(es) weren't rekeyed");
                    }
                }
                _ => unreachable!("handled above"),
            }
        }
    }
    Ok(())
}
```

- [x] **Step 4: Run the end-to-end test**

The same command without `test_sessions.py`'s path restriction, so the relay-setup tests run with their new helpers too: `POS_TUNNEL_DOCKER=1 uv run pytest tests/cli -x -q --no-cov 2>&1 | tail -3`. Expected: `12 passed`, in about a minute and a half once the images are built. Then `uv run ruff check tests/cli` and `uv run pyright tests/cli`: no findings.

- [x] **Step 5: Name the CI job for what it now runs**

The job already runs `pytest tests/cli`, so it picks the new file up:

```diff
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -64,7 +64,7 @@ jobs:
         run: Get-WinEvent -LogName OpenSSH/Operational -MaxEvents 300 -ErrorAction SilentlyContinue | Sort-Object TimeCreated | ForEach-Object { "$($_.TimeCreated.ToString('HH:mm:ss')) $($_.Message)" }
 
   cli-integration:
-    name: "posctl: relay setup integration tests (ubuntu-latest)"
+    name: "posctl: relay setup and session integration tests (ubuntu-latest)"
     runs-on: ubuntu-latest
     steps:
       - uses: actions/checkout@v4
```

- [x] **Step 6: Check and commit**

Run `cargo fmt`, then the check. Expected: `test result: ok. 80 passed`, nothing from clippy or fmt.

```bash
git add cli/src/bin/posctl.rs tests/cli/test_sessions.py tests/cli/test_relay_setup.py .github/workflows/ci.yml
git commit -F - <<'EOF'
feat(cli): wire up the session commands, update and rekey

posctl's seven device commands, with their output and the two prompts: rebuild always warns AI
agents and needs --yes without a terminal, and rekey --all says what it will do first. A Docker
test runs them against the real relay, a stand-in POS and a fake NinjaOne, two operators sharing
a session included.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

---

### Task 5: The POS package's join mode (package version 4)

**Files:**
- Replace: `pos/package/Open.ps1`
- Modify: `pos/package/Close.ps1`, `tests/pos/Harness.ps1`, `tests/pos/PosTunnel.Tests.ps1`
- Regenerated by the user: `pos/manifest.json`, `pos/manifest.json.sig`

**Interfaces:**
- Consumes: `Common.ps1`'s `Write-Result`, `Enter-Lock`, `Exit-Lock`, `Set-FileContent`, `Start-Sshd`, `Stop-Session` and its path variables (unchanged); `Invoke-PosTunnel.ps1`, which already passes `-Name value` pairs through, so the library script in NinjaOne stays as pasted.
- Produces: `Open -Mode Join -Port <port> -SessionKey <base64>` printing `CHANGED<TAB>session key<TAB>added, <n> session keys` (or `OK<TAB>session key<TAB>already one of <n>`) and `CHANGED<TAB>lease<TAB>renewed`, or failing with `FAILED<TAB>session<TAB>no session is open` / `the open session is on port <p>` and tearing nothing down. `-IdleSeconds` is no longer mandatory (a join doesn't set it) but is still required and range-checked for a new session. `Close` prints `OK<TAB>close<TAB>session ended, <n> session key(s)`. `posctl` (Task 2) already sends the join and prints `Close`'s line.

- [x] **Step 1: Write the tests**

These reconfigure the machine, so they run only in CI's `pos-integration` job (Step 5). The harness gets a second operator's key:

```diff
--- a/tests/pos/Harness.ps1
+++ b/tests/pos/Harness.ps1
@@ -109,15 +109,16 @@ function Wait-Port([int]$Port, [switch]$Closed, [int]$TimeoutSeconds = 60) {
 
 # An operator's ssh through the tunnel: the stand-in relay's forwarded port, the session key, and the
 # POS's published SSH server public key pinned.
-function Get-TunnelSshArgs([string]$Command) {
+function Get-TunnelSshArgs([string]$Command, [string]$Key = 'session_key') {
     Set-Content "$Work\pos_known_hosts" "[127.0.0.1]:$TunnelPort $(Get-Field posTunnelHostKey)" -Encoding ASCII
-    return @('-F', 'none', '-p', "$TunnelPort", '-i', "$Work\session_key", '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
+    return @('-F', 'none', '-p', "$TunnelPort", '-i', "$Work\$Key", '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
         '-o', "UserKnownHostsFile=$Work\pos_known_hosts", '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=15', 'support@127.0.0.1', $Command)
 }
 
-function Invoke-ThroughTunnel([string]$Command) {
+# -Key: another operator's session key (second_key), for a joined session.
+function Invoke-ThroughTunnel([string]$Command, [string]$Key = 'session_key') {
     $ErrorActionPreference = 'Continue'
-    $output = & "$env:ProgramFiles\OpenSSH\ssh.exe" @(Get-TunnelSshArgs $Command) 2>&1
+    $output = & "$env:ProgramFiles\OpenSSH\ssh.exe" @(Get-TunnelSshArgs $Command $Key) 2>&1
     $result = [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($output | Out-String).Trim() }
     Write-Host "--- ssh support@ $Command -> $($result.ExitCode)`n$($result.Output)"
     return $result
@@ -173,6 +174,7 @@ Export-ModuleMember -Function Ninja-Property-Get, Ninja-Property-Set
     Set-Field posTunnelSigner (New-KeyPair "$Work\signing_key")
     $null = New-KeyPair "$Work\other_signing_key"
     $null = New-KeyPair "$Work\session_key"
+    $null = New-KeyPair "$Work\second_key"
 
     # The stand-in relay: a second sshd, from a copy of Windows' own OpenSSH taken before Setup removes it,
     # with user tunnel allowed only remote forwarding of the POS's port, as section 6.2 configures the
```

And the cases, in the order the suite's shared session needs them:

```diff
--- a/tests/pos/PosTunnel.Tests.ps1
+++ b/tests/pos/PosTunnel.Tests.ps1
@@ -186,13 +186,42 @@ Describe 'Sessions: Invoke-PosTunnel, Open, Touch, Close' {
         (Invoke-ThroughTunnel 'hostname').ExitCode | Should -Be 0
     }
 
-    It 'closes at once, ending the live connection' {
+    It 'refuses a join for another port, leaving the session as it was' {
+        $second = ((Get-Content "$Work\second_key.pub" -Raw).Trim() -split ' ')[1]
+
+        $r = Invoke-Action Open @('-Mode', 'Join', '-Port', "$($TunnelPort + 1)", '-SessionKey', $second)
+
+        $r.ExitCode | Should -Be 1
+        $r.Text | Should -Match "FAILED`tsession`tthe open session is on port $TunnelPort"
+        (Invoke-ThroughTunnel 'hostname').ExitCode | Should -Be 0
+        (Invoke-ThroughTunnel 'hostname' 'second_key').ExitCode | Should -Not -Be 0
+    }
+
+    It 'adds a second operator''s key on a join, the first key and the session going on' {
+        $started = (Get-Content "$Root\session.json" -Raw | ConvertFrom-Json).started
+        (Get-Item "$Root\lease").LastWriteTimeUtc = [DateTime]::UtcNow.AddMinutes(-30)
+        $second = ((Get-Content "$Work\second_key.pub" -Raw).Trim() -split ' ')[1]
+        $join = @('-Mode', 'Join', '-Port', "$TunnelPort", '-SessionKey', $second)
+
+        $r = Invoke-Action Open $join
+
+        $r.ExitCode | Should -Be 0
+        $r.Text | Should -Match "CHANGED`tsession key`tadded, 2 session keys"
+        (Invoke-ThroughTunnel 'hostname').ExitCode | Should -Be 0
+        (Invoke-ThroughTunnel 'hostname' 'second_key').ExitCode | Should -Be 0
+        (Get-Content "$Root\session.json" -Raw | ConvertFrom-Json).started | Should -Be $started
+        ([DateTime]::UtcNow - (Get-Item "$Root\lease").LastWriteTimeUtc).TotalSeconds | Should -BeLessThan 60
+        # The same key again changes nothing.
+        (Invoke-Action Open $join).Text | Should -Match "OK`tsession key`talready one of 2"
+    }
+
+    It 'closes at once, ending the live connection and every operator''s key' {
         $live = Start-TunnelSsh 'Start-Sleep 600'
 
         $r = Invoke-Action Close
 
         $r.ExitCode | Should -Be 0
-        $r.Text | Should -Match "OK`tclose`tsession ended"
+        $r.Text | Should -Match "OK`tclose`tsession ended, 2 session keys"
         $live.WaitForExit(30000) | Should -BeTrue
         $state = Get-IdleState
         $state.SshdStatus | Should -Be 'Stopped'
@@ -203,6 +232,19 @@ Describe 'Sessions: Invoke-PosTunnel, Open, Touch, Close' {
         Wait-Port $TunnelPort -Closed | Should -BeTrue
     }
 
+    It 'refuses a join when no session is open, and stays idle' {
+        $second = ((Get-Content "$Work\second_key.pub" -Raw).Trim() -split ' ')[1]
+
+        $r = Invoke-Action Open @('-Mode', 'Join', '-Port', "$TunnelPort", '-SessionKey', $second)
+
+        $r.ExitCode | Should -Be 1
+        $r.Text | Should -Match "FAILED`tsession`tno session is open"
+        $state = Get-IdleState
+        $state.AuthorizedKeys | Should -Be 0
+        $state.SshdStatus | Should -Be 'Stopped'
+        $state.SupportEnabled | Should -BeFalse
+    }
+
     It 'refuses to open, and tears down, when sshd would listen beyond loopback' {
         (Get-Content "$env:ProgramData\ssh\sshd_config" -Raw) -replace 'ListenAddress 127.0.0.1', 'ListenAddress 0.0.0.0' |
             Set-Content "$env:ProgramData\ssh\sshd_config" -Encoding ASCII -NoNewline
```

- [x] **Step 2: Rewrite `pos/package/Open.ps1`**

The new-session path is the old script's, indented under `else`; the join branch and the `catch`'s condition are new.

```powershell
<#
.SYNOPSIS
Opens a session: installs the session key, enables support, starts sshd (loopback only), writes the
session state and lease, points PosTunnel-Link at the relay and starts it. With -Mode Join, adds
another operator's session key to the session that is running and changes nothing else.
.NOTES
Design: docs/design.md, section 7.2. Run through Invoke-PosTunnel, as SYSTEM. -SessionKey is the bare
base64 of an ed25519 public key: no space, so NinjaOne's parameter string needs no quoting.
#>
param(
    [Parameter(Mandatory)][int]$Port,
    [Parameter(Mandatory)][string]$SessionKey,
    [int]$IdleSeconds,
    [ValidateSet('New', 'Join')][string]$Mode = 'New'
)

. "$PSScriptRoot\Common.ps1"

$step = 'parameters'
# 20000 + a device ID of 1..45535 (section 4); idle at most 12 hours (section 5), which a join doesn't
# set. The key pattern is the exact base64 of an ed25519 public key blob, so nothing else can reach
# administrators_authorized_keys.
if ($Port -lt 20001 -or $Port -gt 65535 -or $SessionKey -cnotmatch '^AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43}$' -or
    ($Mode -eq 'New' -and ($IdleSeconds -lt 1 -or $IdleSeconds -gt 43200))) {
    Write-Result 'FAILED' $step 'port, idle seconds or session key is malformed'
    exit 1
}
foreach ($required in $RelayKey, $RelayFile, $KnownHosts, "$OpenSsh\sshd.exe") {
    if (-not (Test-Path -LiteralPath $required)) { Write-Result 'FAILED' 'setup' "missing $required; run Install-PosTunnel"; exit 1 }
}
if (-not (Enter-Lock 600)) { Write-Result 'FAILED' 'lock' 'another PosTunnel script held it for 10 minutes'; exit 1 }
try {
    if ($Mode -eq 'Join') {
        # An explicit mode, not Open adding to whatever it finds: a session left over from a connect that
        # timed out must still be replaced, and only posctl, which sees the relay's leases, can tell the
        # two apart. sshd reads the key file at each login, so live connections go on.
        $step = 'session'
        if (-not (Test-Path -LiteralPath $SessionFile)) { throw 'no session is open' }
        $open = [int](Get-Content -LiteralPath $SessionFile -Raw | ConvertFrom-Json).port
        if ($open -ne $Port) { throw "the open session is on port $open" }

        $step = 'session key'
        $keys = @(Get-Content -LiteralPath $AuthorizedKeys | Where-Object { $_ })
        if ($keys -ccontains "ssh-ed25519 $SessionKey") { Write-Result 'OK' $step "already one of $($keys.Count)" }
        else {
            $keys += "ssh-ed25519 $SessionKey"
            $null = Set-FileContent $AuthorizedKeys (($keys -join "`r`n") + "`r`n") $SystemSid, $AdminsSid
            Write-Result 'CHANGED' $step "added, $($keys.Count) session keys"
        }

        $step = 'lease'
        (Get-Item -LiteralPath $LeaseFile).LastWriteTimeUtc = [DateTime]::UtcNow
        Write-Result 'CHANGED' $step 'renewed'
    } else {
        # The relay refuses a second lease for this port, so a session already here is left over (a connect
        # that timed out, say) and safe to replace. Converging to idle either way also stops a PosTunnel-Link
        # left running without one, which would otherwise keep its old arguments through the Start below.
        $step = 'previous session'
        if (Test-Path -LiteralPath $SessionFile) { Write-Result 'CHANGED' $step 'replacing' }
        Stop-Session

        $step = 'session key'
        $null = Set-FileContent $AuthorizedKeys "ssh-ed25519 $SessionKey`r`n" $SystemSid, $AdminsSid
        Write-Result 'CHANGED' $step

        $step = 'support account'
        Enable-LocalUser -Name $SupportUser
        Write-Result 'CHANGED' $step 'enabled'

        $step = 'sshd'
        $problem = Start-Sshd
        if ($problem) { throw "$problem; tearing down" }
        Write-Result 'CHANGED' $step 'started, loopback only'

        $step = 'session state'
        $session = @{ port = $Port; idle_seconds = $IdleSeconds; started = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
        $null = Set-FileContent $SessionFile (($session | ConvertTo-Json -Compress) + "`r`n")
        $null = Set-FileContent $LeaseFile ''
        (Get-Item -LiteralPath $LeaseFile).LastWriteTimeUtc = [DateTime]::UtcNow
        Write-Result 'CHANGED' $step

        # 127.0.0.1, not localhost, which Windows resolves to ::1 first, where sshd isn't listening.
        # IdentitiesOnly: the relay records every key a POS offers (section 6.5), so only relay_key goes.
        # -F none: no ssh_config can add options.
        $step = 'tunnel'
        $relay = Get-Content -LiteralPath $RelayFile -Raw | ConvertFrom-Json
        $sshArgs = "-N -F none -R $Port`:127.0.0.1:22 -p $($relay.port) -i $RelayKey -o ExitOnForwardFailure=yes " +
            "-o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o BatchMode=yes -o StrictHostKeyChecking=yes " +
            "-o UserKnownHostsFile=$KnownHosts -o IdentitiesOnly=yes tunnel@$($relay.host)"
        $null = Set-ScheduledTask -TaskName $LinkTask -Action (New-ScheduledTaskAction -Execute "$OpenSsh\ssh.exe" -Argument $sshArgs)
        $null = Enable-ScheduledTask -TaskName $LinkTask
        Start-ScheduledTask -TaskName $LinkTask
        Write-Result 'CHANGED' $step "port $Port via $($relay.host):$($relay.port)"
    }
} catch {
    Write-Result 'FAILED' $step $_.Exception.Message
    # Whatever a new session got this far comes down: the operator was told Open failed, and a
    # session.json left behind would have Watch keep sshd and support up until the idle timeout. A failed
    # join tears nothing down: the session is the operator's who opened it.
    if ($Mode -eq 'New') { try { Stop-Session } catch { Write-Result 'FAILED' 'teardown' $_.Exception.Message } }
} finally { Exit-Lock }
exit [int]($script:failed -gt 0)
```

Then make it CRLF (Global Constraints): `sed -i 's/$/\r/' pos/package/Open.ps1`.

- [x] **Step 3: Have `Close` count the session keys**

```diff
--- a/pos/package/Close.ps1
+++ b/pos/package/Close.ps1
@@ -11,8 +11,10 @@ Install-PosTunnel -Force, as SYSTEM.
 if (-not (Enter-Lock 600)) { Write-Result 'FAILED' 'lock' 'another PosTunnel script held it for 10 minutes'; exit 1 }
 try {
     $open = Test-Path -LiteralPath $SessionFile
+    # One key per operator workstation on the session (section 7.2, joining): close ends it for all.
+    $keys = @(Get-Content -LiteralPath $AuthorizedKeys -ErrorAction SilentlyContinue | Where-Object { $_ }).Count
     Stop-Session
-    Write-Result 'OK' 'close' $(if ($open) { 'session ended' } else { 'no session was open' })
+    Write-Result 'OK' 'close' $(if ($open) { "session ended, $keys session key$(if ($keys -ne 1) { 's' })" } else { 'no session was open' })
 } catch {
     Write-Result 'FAILED' 'close' $_.Exception.Message
 } finally { Exit-Lock }
```

- [x] **Step 4: Check locally and commit**

CI's first `pos-integration` step, run here in PowerShell. Expected: `problems: 0`.

```powershell
$bad = 0; foreach ($file in Get-ChildItem pos, tests\pos -Recurse -Filter *.ps1) { if ([IO.File]::ReadAllBytes($file.FullName) | Where-Object { $_ -gt 127 }) { "$($file.Name): not ASCII"; $bad++ }; $errors = $null; $null = [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$errors); foreach ($e in $errors) { "$($file.Name):$($e.Extent.StartLineNumber): $($e.Message)"; $bad++ } }; "problems: $bad"
```

And in Git Bash, every `.ps1` touched is CRLF throughout. Expected: the two numbers on each line are equal.

```bash
for f in pos/package/Open.ps1 pos/package/Close.ps1 tests/pos/Harness.ps1 tests/pos/PosTunnel.Tests.ps1; do echo "$f $(wc -l < $f) $(tr -cd '\r' < $f | wc -c)"; done
```

```bash
git add pos/package/Open.ps1 pos/package/Close.ps1 tests/pos/Harness.ps1 tests/pos/PosTunnel.Tests.ps1
git commit -F - <<'EOF'
feat(pos): Open -Mode Join adds another operator's key to the running session

Operators share a session instead of waiting for one another. A join requires a session on the
port it names, adds the key as another line of administrators_authorized_keys and renews the
lease; nothing is restarted, and a failed join tears nothing down. It is an explicit mode because
only posctl, which sees the relay's leases, can tell a live session from one left over. Close
reports how many session keys it removed.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

- [x] **Step 5: The user signs the package (version 4)**

The release signing key has a passphrase, so the user runs this in PowerShell from the repository root; it rewrites `pos/manifest.json` (version 3 to 4, new hashes for `Open.ps1` and `Close.ps1`) and its `.sig`:

```powershell
$env:POS_TUNNEL_SIGNING_KEY = "$env:USERPROFILE\.ssh\pos-tunnel-release"; uv run poe sign-pos
```

Then verify and commit. Expected from the first command: no output and exit 0; from the second: `"version": 4,`.

```bash
uv run --no-project scripts/sign_pos.py --check
grep -m1 version pos/manifest.json
git add pos/manifest.json pos/manifest.json.sig
git commit -F - <<'EOF'
chore(pos): sign POS package version 4

Open's join mode and Close's session-key count.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

---

### Task 6: The README, CI, the test POS, and the pull request

**Files:**
- Modify: `README.md`; `docs/design.md` only if a step here finds the spec wrong

**Interfaces:**
- Consumes: the whole branch.
- Produces: a pushed branch with every CI job green, a run against the real test POS, and an open pull request.

- [x] **Step 1: Bring the README up to date**

```diff
--- a/README.md
+++ b/README.md
@@ -5,8 +5,8 @@ dial out to a hardened SSH relay; the operator (or a coding agent on the operato
 connects through the relay. Sessions have a 12-hour idle timeout, renewable up to a 72-hour maximum,
 and leave nothing enabled on the POS when they end.
 
-**Status:** the relay, the POS package and `posctl-admin` are implemented; `posctl`'s session commands
-(`connect`, `keepalive`, `status`, `close`, `rebuild`, `update`, `rekey`) are not yet.
+**Status:** the relay, the POS package, `posctl-admin` and `posctl` are implemented. Two operators
+sharing a session needs POS package version 4 on the POS.
 
 - [`docs/design.md`](docs/design.md): the design (threat model, keys, timers, flows).
 - [`cli/`](cli/): `posctl`, the Rust CLI run on the operator workstation.
@@ -22,12 +22,17 @@ private index), released with `poe release`. After changing anything in `pos/pac
 `poe sign-pos` (needs `POS_TUNNEL_SIGNING_KEY`) and commit the re-signed `pos/manifest.json`; CI
 rejects an unsigned or stale manifest.
 
-## Usage (planned)
+## Usage
 
 ```powershell
 posctl login
 posctl connect "Store 42 Register 1"      # exact, case-sensitive NinjaOne display name
 ssh pos-store-42-register-1 "Get-Service"
+posctl status
 posctl keepalive "Store 42 Register 1"
 posctl close "Store 42 Register 1"
 ```
+
+`connect` on a POS another operator is already on joins their session, and `close` ends it for
+everyone on it. `rebuild`, `update` and `rekey` are in `posctl --help`. An operator key with a
+passphrase has to be in `ssh-agent` (`ssh-add`); `posctl` says so when it isn't.
```

```bash
git add README.md
git commit -F - <<'EOF'
docs: posctl's session commands are implemented

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

- [ ] **Step 2: Push and watch CI (needs the user's go-ahead to push)**

```bash
git push -u origin feat/posctl-sessions
sha=$(git rev-parse HEAD)
until run=$(gh run list --commit "$sha" --workflow CI --limit 1 --json databaseId --jq '.[0].databaseId') && [ -n "$run" ]; do sleep 5; done
until [ "$(gh run view "$run" --json status --jq .status)" = completed ]; do sleep 15; done
gh run view "$run" --json jobs --jq '.jobs[] | "\(.name): \(.conclusion)"'
```

Expected: all four jobs `success`. `POS package: integration tests as SYSTEM (windows-latest)` is the first run of Task 5's join cases; if one fails, read it with `gh run view "$run" --log-failed | tail -60`, fix the script or the test (the test is not the authority: decide which side is wrong from the spec), and push again. `posctl: relay setup and session integration tests (ubuntu-latest)` is the first run of the Docker test on Linux. `gh` sometimes loses the network mid-watch; query the run again.

**Status (2026-10-13):** pushed before Task 5 Step 5, so that the join cases ran before the user signs. Run 38439652660: the three test jobs `success`, the join cases included; `POS package: manifest matches the files, signature valid` fails until the package is signed, as it should.

- [x] **Step 3: Run the session commands against the test POS**

Against `POS 000 Test` only, with the branch's build (`cargo build` first; the Docker test leaves a `posctl-admin.exe` built with a test admin key, which `cargo build` replaces). `$P` is `D:/cargo-target/debug/posctl.exe`. The POS still has package version 3, so everything but joining is covered. Expected, in order:

```bash
P=D:/cargo-target/debug/posctl.exe
$P status                                    # No open sessions.
$P connect "POS 000 Test" --idle-timeout 1h  # POS 000 Test is connected: ssh pos-000-test
ssh pos-000-test hostname                    # SFTX13 (Git Bash's ssh)
/c/Windows/System32/OpenSSH/ssh.exe pos-000-test whoami   # sftx13\support
$P status                                    # one row: POS 000 Test  pos-000-test  Jacob  ...  up
$P connect "POS 000 Test"                    # POS 000 Test is already connected (tunnel up): ...
$P keepalive "POS 000 Test"                  # POS 000 Test is renewed. Idle timeout in 1h 0m; ...
$P rebuild "POS 000 Test" </dev/null         # the warning, then: pass --yes to go ahead (exit 1)
$P rebuild "POS 000 Test" --yes </dev/null   # POS 000 Test is rebuilt: ssh pos-000-test
$P update "POS 000 Test"                     # DEFERRED<TAB>session ..., then an error (exit 1)
$P rekey "POS 000 Test"                      # Error: POS 000 Test is in a session Jacob opened: ...
$P rekey "POS 000 Test" --force              # POS 000 Test: rekeyed
$P connect "POS 000 Test" --idle-timeout 30m # connected again, with the republished keys
$P close "POS 000 Test"                      # ... lease ... is closed ... / POS 000 Test reports: session ended.
$P update "POS 000 Test"                     # OK lines down to: OK<TAB>current<TAB>version 3 (exit 0)
$P status                                    # No open sessions.
```

Anything else is a finding: stop and report it before going on. Leave no session open.

**Result (2026-10-13):** every line as expected except the `connect` after `rekey --force`, which failed with `its tunnel didn't reach the relay within 3m`. Two faults, both fixed on this branch with tests before going on (they are defects in this plan's own design, and neither needs anything of the user's):

- NinjaOne's API still returned the old keys 39 s after the `Rekey` run's result, so `connect` gave the relay the old relay public key. `rekey` and `update` now wait until NinjaOne shows the fields the POS's report says it wrote (`12e9fa6`). Checked on the test POS: `rekey --force` (63 s), then `connect` the moment it returned (21 s).
- Found while measuring that: a second `posctl`'s sign-in refresh ends the first one's access token (`401 not_authenticated` on its next call). A call answered 401 now signs in again and is repeated (`371c56d`). Checked on the test POS: a `rekey` that two `status` commands overlapped finished.

- [x] **Step 4: Correct the spec if a step found it wrong**

If Step 2 or Step 3 showed behaviour that `docs/design.md` describes differently, change the section and commit it as `docs(design): ...` with what was observed. If nothing did, there is nothing to commit.

**Result:** `c6414e1` records both faults and their answers in sections 7.7, 7.8, 8, 9 and 11.

**Branch review (2026-10-13):** a fresh reviewer read the whole branch before the package was signed: nothing critical, and nothing in the POS package. Fixed with tests (`e5c7382`, `958e9eb`, `912fc65`; spec in `3a503d0`):

- A `connect` that is cut off left a lease the next `connect` misread as someone else's session. It now notes the lease it opened and the next `connect` here replaces it. Checked on the test POS by killing `connect` at 6 s and at 9 s; the first try showed the note being deleted by the dying command's own undo, which is fixed too.
- A waiting `connect` could adopt, then close, a lease another operator had opened on the port meanwhile. It now goes by the lease's `started`.
- `Include posctl/config` went in front of a byte-order mark in `~/.ssh/config`, which broke every `ssh` on the workstation. The mark stays first.
- The generated entries now say `ForwardAgent no`, and control characters are dropped from a POS's report.

Left for later, in the order they matter: tolerate a failed poll before the first fleet-wide `rekey --all`; a joiner should wait for the tunnel; an overall timeout on relay calls.

- [x] **Step 5: Open the pull request (needs the user's go-ahead)** — https://github.com/AetherBreaker/pos-tunnel/pull/2, opened before the signature so the review could start; its manifest check is red until Task 5 Step 5

```bash
gh pr create --base main --head feat/posctl-sessions --title "feat(cli): posctl session commands; operators share a session" --body-file - <<'EOF'
`posctl connect`, `keepalive`, `status`, `close`, `rebuild`, `update` and `rekey`, as specified in `docs/design.md` sections 7.2 to 7.8 and 8.

- Every command waits for the POS script's own result, read from the device's activity list.
- A second operator's `connect` joins the open session with a key of its own (`Open -Mode Join`, POS package version 4); `close` ends it for everyone.
- An operator key with a passphrase goes through `ssh-agent`; `connect` adds the `Include` line itself.
- With `POSCTL_CONFIG_HOME` set, the NinjaOne sign-in is a file in that directory.

Run against the deployed relay and `POS 000 Test` (package version 3). Joining on a real POS waits for the release that carries package version 4.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
```

Integration is a rebase merge, by the user, after their review.

---

## After this plan

- **Release** (the user): `poe release` from `main` after the merge publishes the wheel and attaches POS package version 4.
- **Version 4 on the test POS:** `posctl update "POS 000 Test"`; its report ends `CHANGED<TAB>current<TAB>version 4`.
- **Joining on the real POS.** A second identity on this workstation stands in for a second operator: with `POSCTL_CONFIG_HOME` pointing at a folder holding a copy of `posctl\config.toml`, `posctl login` (the user signs in; that identity's token is a file there), then `posctl connect "POS 000 Test"` while the first identity's session is open. Expected: `Joined the session Jacob opened on POS 000 Test`, and `close` reporting `session ended, 2 session keys`. Record it in design section 11 and drop the item from its "Still open" list.
- **Then the fleet:** `posctl-admin relay point` for every POS, and `Install-PosTunnel` scheduled daily in the POS policy (design section 12, step 5).
- Delete `probe/posctl-sessions` once the branch is merged.

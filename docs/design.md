# pos-tunnel design

On-demand SSH access to Windows POS machines managed by NinjaOne RMM, relayed through a small SSH
server on a VPS. The intended user is an operator and a coding agent (Claude Code) running on the
operator's workstation, for occasional troubleshooting.

NinjaOne never carries the SSH traffic. It is the control plane: its API tells a POS to dial out to the
relay, and the operator connects through the relay to that dial-out.

```
operator workstation                    relay (VPS container)                 POS (Windows)
  posctl ──NinjaOne API──────────────────────────────────────────────────────▶ Open script (SYSTEM)
  posctl ──ssh ctl@relay──▶ tunnelctl open/renew/close
                            127.0.0.1:<port> ◀──ssh -N -R (tunnel@relay)───── Link task
  ssh pos-x ──ProxyJump jump@relay──▶ 127.0.0.1:<port> ═══════════════════════▶ sshd on 127.0.0.1:22
```

## 1. Components

| Component                | Where                                        | What                                                                                                                                                                                                                                                                                |
| ------------------------ | -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `posctl`                 | operator workstation                         | Rust CLI, shipped as a maturin binary wheel on the private index (`uv tool install pos-tunnel`). Session commands for every operator. Calls the NinjaOne API, drives the relay via `tunnelctl`, writes local SSH config.                                                            |
| `posctl-admin`           | admin's workstation                          | Second binary in the same wheel: key generation and fleet configuration (section 7.9). Kept apart so its commands never show in `posctl --help`.                                                                                                                                    |
| NinjaOne library scripts | NinjaOne → POS                               | Two small PowerShell scripts pasted into NinjaOne once and never changed: `Install-PosTunnel` (downloads, verifies and installs the POS package) and `Invoke-PosTunnel` (runs an action from the installed package). Section 7.1.                                                   |
| POS package              | GitHub Releases → `C:\ProgramData\PosTunnel` | PowerShell, run as SYSTEM: `Setup`, `Open`, `Close`, `Touch`, and `Watch`, which owns the session lifecycle on the POS. Signed release asset.                                                                                                                                       |
| relay                    | Docker container on the Coolify VPS          | Own repo (`AetherBreaker/pos-tunnel-relay`, submodule at `relay/`). `sshd` on its own published port (2222), separate from the host's `sshd` (Coolify manages the host over SSH as root; it must not be touched), plus a Python daemon that owns leases, tracks connections from `sshd`'s log and decides enforcement; `tunnelctl` and `tunnel-keys` are thin clients of it, and a root `cron` job does the killing. |

## 2. Threat model

- **POS machines are untrusted.** Firewall off; the till account is a passwordless local administrator
  that logs in automatically (the POS software requires admin), so anyone at the till has admin.
  Assume an attacker on a
  POS can read anything on it, including its relay private key, and can write its NinjaOne custom fields.
- **Goal:** a compromised POS can affect only its own session. It must not be able to reach another
  POS's tunnel, bind another POS's port, read or change any lease or key on the relay, run code on the
  relay, or keep its own tunnel alive past the relay's deadline.
- **Accepted:** a compromised POS can deny or tamper with its own session, including faking what it
  returns. Anything a POS returns is untrusted data to the agent, never instructions.
- **Trusted:** the operator workstations, the NinjaOne tenant and API credentials, the relay container.
  NinjaOne is the root of trust for fleet configuration: the relay's address and public key and the
  release signing public key reach every POS through it (section 3, fleet fields).

## 3. Identities and keys

All key pairs are ed25519.

| Key pair                                         | Generated                                                                                                                  | Private key                                                                   | Public key reaches its holder via                                                                                                                           | Authorizes                                                                                                                                       |
| ------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| POS relay key pair (per device)                  | by `Setup`, once per device; again on `posctl rekey` or a from-scratch reinstall (section 7.1, `Install-PosTunnel` step 1) | POS: `C:\ProgramData\PosTunnel\relay_key`                                     | custom field `posTunnelRelayKey` → `posctl` → `tunnelctl open`                                                                                              | `tunnel@relay`, only while a session is open                                                                                                     |
| POS SSH server key pair (per device)             | by `sshd` on its first start after `Setup` installs OpenSSH; again on `posctl rekey`                                       | POS: `C:\ProgramData\ssh\ssh_host_ed25519_key`                                | custom field `posTunnelHostKey` → `posctl` → local `known_hosts`                                                                                            | operator verifies it is talking to that POS's `sshd`                                                                                             |
| Session key pair                                 | by `posctl`, on every `connect` and `rebuild`                                                                              | operator workstation, session state dir                                       | `Open` script parameter (public keys are safe in NinjaOne activity logs)                                                                                    | `support@POS` for this session only                                                                                                              |
| Operator key pair (per operator)                 | by `posctl-admin operator add` (the admin's own: by hand, section 12)                                                      | that operator's workstation, installed with `posctl operator import`          | relay env var `OPERATOR_KEYS` → `/etc/ssh/operator_keys` (root-owned) at container start                                                                    | `ctl@relay` (forced `tunnelctl`) and `jump@relay` (forwarding only); names the operator in `tunnelctl`'s log. Identity, not a security boundary. |
| Relay SSH server key pair                        | by `posctl-admin relay keygen`; again only to rotate it or move the relay                                                  | relay env var `RELAY_SSH_PRIVATE_KEY`; a copy in `posctl-admin`'s config dir  | `relay point` → fleet field → `Setup` → POS `known_hosts`; `posctl` config via `relay keygen --activate` (admin), `operator import` or `relay set` (others) | POS and operator verify the relay                                                                                                                |
| Release signing key pair                         | by `posctl-admin signing keygen`; again only if lost or leaked                                                             | admin workstation only — never CI, so a compromised GitHub account can't sign | `signing keygen` → fleet field → `Install-PosTunnel`; and `pos/allowed_signers`, for CI's check                                                             | POS package releases (namespace `pos-tunnel-release`)                                                                                            |
| NinjaOne API client credentials (not a key pair) | in NinjaOne's console                                                                                                      | OS keyring (`posctl login`)                                                   | —                                                                                                                                                           | running SYSTEM scripts on every POS; the admin's also writes the fleet fields                                                                    |

All fields are NinjaOne global custom fields (text).

**Device fields** (`posTunnelRelayKey`, `posTunnelHostKey`, `posTunnelVersion`): definition scope
Device; Automations read/write (`Setup` and `Rekey` write them), API read-only. Written by the POS and
untrusted. They can only ever affect that POS's own session: `posctl` binds them to that device's
port, and `tunnelctl` validates key strings strictly (section 6.3).

**Fleet fields** (`posTunnelRelay` = `<host>:<port>`, `posTunnelRelayServerKey`, `posTunnelSigner`):
definition scope Organization only; Automations read-only, API read/write. `posctl-admin` writes
them on every organization that holds a POS (`PATCH /v2/organization/{id}/custom-fields`); a POS's
`Ninja-Property-Get` resolves device → end user → location → organization, so it reads its
organization's value. A POS that could write one would point the whole fleet at its own relay or
signing key; two NinjaOne controls each prevent it: scripts can't update a field whose definition
scope isn't Device, and Automations is read-only. Not NinjaOne Documentation fields, whose
organization values script "delegate" devices can write.

`posctl-admin` owns these settings: before any fleet-field write it reads all six definitions
(`GET /v2/custom-fields/field-name/{name}`: `definitionScope`, `scriptPermission`,
`apiPermission`), creates any that are missing (`POST /v2/custom-fields`) with the settings above,
and refuses, naming the field and setting, if an existing one differs. It never changes an existing
definition, since a changed setting may be tampering.

## 4. Ports and naming

- Tunnel port = `20000 + <NinjaOne device ID>`. Fixed per device, no allocation state, no collisions.
  `posctl` refuses device IDs above 45535.
- Local SSH alias: `pos-<slug of display name>`. The display name argument is matched exactly
  (case-sensitive) against NinjaOne's device display name; zero or multiple matches is an error listing
  what was found. A device with no display name is not addressable by name.

## 5. Timers

| Timer            | Value                                             | Authoritative on                  | Mirror                           |
| ---------------- | ------------------------------------------------- | --------------------------------- | -------------------------------- |
| Idle timeout     | 12h default; `--idle-timeout` may only shorten it | relay lease (relay daemon)        | POS lease file mtime (`Watch`)   |
| Absolute maximum | 72h from `connect`                                | relay lease                       | POS session start time (`Watch`) |

- Each side computes its deadlines from **its own clock**. `posctl` never sends a timestamp, so clock
  skew between the three machines doesn't matter.
- The relay rejects an idle timeout above 12h regardless of what `posctl` sends.
- The POS mirror exists only to clean up locally. An attacker extending it gains nothing: the relay
  still cuts the tunnel at its own deadline, and the POS is already theirs.
- Resetting the 72h maximum requires `posctl rebuild` (section 7.6).

## 6. Relay

### 6.1 Container

- Its own public repo, `AetherBreaker/pos-tunnel-relay`, a submodule of this one at `relay/`: a
  devkit-managed Python project (package `pos_tunnel_relay`), so `setup-project` owns its
  Dockerfile and compose file. The image is devkit-container's template (Debian bookworm,
  `uv:python3.14-bookworm-slim`); its `final` window adds `openssh-server` and `cron`.
- Entrypoint: devkit-container's `run`, supervised. As root, the startup script `relay-startup`
  runs first, then the supervisor drops to uid 999 and starts the daemon (`run-app-pos-tunnel-relay`,
  section 6.5). The container exits when the daemon exits.
- `relay-startup`:
  1. Refuse to start unless `RELAY_SSH_PRIVATE_KEY` and `OPERATOR_KEYS` are set; never generate a
     key pair.
  2. Write the relay private key to a root-only file under `/run/relay/`, and the operator keys to
     `/etc/ssh/operator_keys` (root-owned, 0644, one `ssh-ed25519 <base64> <name>` line each).
  3. Recreate `/run/pos-tunnel/` empty, owned by 999 (a restart keeps the container's filesystem,
     and pids start over, so old state would name unrelated processes); write the `tunnel` banner
     there saying the relay is starting; link `/dev/log` to `/run/pos-tunnel/log.sock` (Docker
     recreates `/dev` at each start, and 999 can't).
  4. Start `sshd` (daemonized, logging to syslog) and `cron`, and record each one's pid and start
     time in `/run/pos-tunnel/daemons.json`.

  Both key variables are in `scrub_env`, so the daemon never sees them.
- Compose: published port 2222/tcp directly (not through Coolify's HTTP proxy — SSH is not TLS, so
  SNI routing can't apply); Vultr firewall group and host `ufw` (if enabled) must allow it.
  `restart: always`, set by hand (setup-project only inserts `restart` when missing).
- Persisted: devkit's `/app/persisted_data` bind mount holds `state/` (leases), `logs/` (the
  heartbeat) and `aeth_ext`'s delivery history. No key material: losing it changes no identity.
- Environment, both single-line so `posctl-admin`'s output pastes straight into Coolify's `.env`
  view: `RELAY_SSH_PRIVATE_KEY` (base64 of the OpenSSH private key file) and `OPERATOR_KEYS`
  (`<name>=<ed25519 base64>`, comma-separated).
- Users: `tunnel` and `jump` have `nologin` as their shell; `ctl` needs `/bin/sh`, because `sshd`
  runs a `ForceCommand` through the login shell; `keyreader` runs `tunnel-keys`. Accounts are
  created locked, which `sshd` rejects even for key auth, so each gets password `*` (unusable, but
  not locked).
- Container restarts drop live tunnels; POS `Watch` reconnects them within 2 minutes.
- DNS: a dedicated A record for the relay (not the Coolify UI hostname), not proxied through Cloudflare.

### 6.2 Users and `sshd_config`

| User     | Who       | Allowed                                                                                                                                         |
| -------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `tunnel` | every POS | remote forwarding of its own port only. No shell, no command, no local forwarding.                                                              |
| `jump`   | operator  | local forwarding (`ProxyJump`) to `localhost` only. No shell.                                                                                   |
| `ctl`    | operator  | `tunnelctl` only (forced command; arguments via `SSH_ORIGINAL_COMMAND`; `ExposeAuthInfo` tells it which operator key logged in). No forwarding. |

Global: key auth only, no root login, `AllowUsers tunnel jump ctl`, `GatewayPorts no`, no agent/X11/
stream-local forwarding, `PermitTunnel no`, `ClientAliveInterval 30`/`ClientAliveCountMax 3`,
`LogLevel VERBOSE` (logs key fingerprints). See the relay repo's `sshd_config`.

`AllowTcpForwarding remote` on `tunnel` is the key isolation control: without it, any POS could open
connections to every other POS's tunnel port on the relay's loopback.

Bookworm's OpenSSH is 9.2, which predates `PerSourcePenalties`. On 9.8 or later it must be tuned:
by default it locks a whole source address out after a few failed logins, and the stores behind one
NAT share an address, so the startup gate (section 6.3) would lock out every POS in the store.

### 6.3 POS keys

`tunnel`'s keys come from `AuthorizedKeysCommand`: `tunnel-keys`, run as `keyreader`, asks the
daemon (section 6.5) for the current lines and prints them. `tunnel` has no way to run anything. One
line per open lease:

```
restrict,port-forwarding,permitlisten="localhost:<port>",expiry-time="<idle deadline, UTC>" ssh-ed25519 <base64>
```

- `restrict,port-forwarding` re-enables forwarding only; `sshd_config` narrows that to remote forwarding.
- `permitlisten` limits the key to its own port.
- `expiry-time` blocks *new* logins after the idle deadline; ending live connections is the
  daemon's and killer's job. The daemon renders the line at each request, so a `renew` takes
  effect at once.
- The public key string comes from a POS-writable custom field. The daemon accepts only
  `^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$` (comment dropped) and builds the line itself, so a malicious
  value can't inject options or extra lines.
- **Startup gate:** if the daemon isn't answering (not yet started, or stalled), `tunnel-keys`
  prints nothing after a 5 s timeout, so a POS is refused and retries within 2 minutes rather than
  holding a connection the daemon never saw. Meanwhile the pre-login `Banner` (`Match User tunnel`;
  `sshd` re-reads the file per connection) says the relay is starting and to retry, for anyone
  reading the POS's task log; the daemon clears it once it listens. Operators (`ctl`, `jump`) are
  unaffected.

### 6.4 `tunnelctl`

A thin client: `sshd` runs it as `ctl` with the operator's command in `SSH_ORIGINAL_COMMAND`. It sends
the command and the operator's public key (from `ExposeAuthInfo`'s `SSH_USER_AUTH` file) to the
daemon, prints the reply and exits with its status. It logs nothing itself. If the daemon isn't
answering it says "relay starting: POS logins paused until the relay daemon is ready" and exits with
a distinct status, which `posctl` reports (section 7.2).

The daemon names the operator from `/etc/ssh/operator_keys`, logs every call with that name, the
command and its arguments, and records the name in the lease on `open`.

| Command                                                       | Effect                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `open <port> <device-id> <idle-seconds> <pubkey> [--rebuild]` | Validate (port range, idle ≤ 43200, key format). Refuse if a lease for `<port>` exists, or if another lease holds the same key (`sshd` uses the first matching line, so a second lease's POS would get the first one's port). Store the lease (`device_id`, `idle_seconds`, `started`, `idle_deadline`, `absolute_deadline = started + 72h`, the key and its `fingerprint`, the operator). `--rebuild` is logged distinctly. |
| `renew <port>`                                                | `idle_deadline = min(now + idle_seconds, absolute_deadline)`. Error if no lease or already expired.                                                                                                                                                                                                                                                                                                                          |
| `close <port>`                                                | Set `idle_deadline = now`; the next enforcement pass removes it.                                                                                                                                                                                                                                                                                                                                                             |
| `status [<port>]`                                             | Deadlines, remaining time, and whether the port is listening on the relay's loopback.                                                                                                                                                                                                                                                                                                                                        |

### 6.5 Daemon and killer

**Daemon** (`run-app-pos-tunnel-relay`, Python, uid 999; the supervised app). One process owns all
relay state and logging, so nothing needs a lock:

- **Log intake.** Receives `sshd`'s syslog on `/run/pos-tunnel/log.sock` (via `/dev/log`). Each
  `tunnel` login line carries the pid of that connection's privileged `sshd` process and the key's
  fingerprint: `sshd[17]: Accepted publickey for tunnel from <ip> port <n> ssh2: ED25519
  SHA256:<fp>`. The daemon records each login in memory as pid, start time (from `/proc/<pid>/stat`,
  readable without privileges; pids get reused) and fingerprint.
- **Requests.** Serves `tunnelctl` and `tunnel-keys` on `/run/pos-tunnel/ctl.sock`, one JSON line
  each way. The caller's uid (`SO_PEERCRED`) decides what it may ask: `ctl` the section 6.4
  commands, `keyreader` the key lines only, anyone else nothing.
- **Leases.** One JSON file per lease in `state/leases/`, written to a temporary name and renamed;
  loaded at start, so a restart keeps every lease.
- **Enforcement,** every 5 s: forget connections whose process is gone (no such pid, or a different
  start time); drop each lease past `min(idle_deadline, absolute_deadline)`, which removes its key
  line at once; then request a kill for every connection whose fingerprint belongs to no remaining
  lease. That ends every connection of an expired, closed or hand-deleted lease, spare ones
  included, and nothing else. A `tunnel` `sshd` process it never saw log in is reported and left
  running.
- **Logging.** Every `sshd` line and every audit record goes to the central log server through
  `aeth_ext` (socket mode, configured by TOML like any `aeth_ext` app). `aeth_ext` sends
  synchronously on the logging thread, so the main loop only hands lines to a bounded in-memory
  queue (10,000) drained by a sender thread; on overflow it drops and counts, and reports the count
  once delivery resumes. `aeth_ext` keeps its own 7-day delivery history in `persisted_data`.
- **Liveness.** One single-threaded loop (`selectors`, waking at least every 5 s) does intake,
  requests, enforcement and the heartbeat devkit-container reads, so a stalled loop stops the beats
  and the supervisor's `/fail` ping alerts. It exits non-zero, ending the container, if `sshd` or
  `cron` is no longer the process `daemons.json` names, or the killer's beat is older than 3 minutes.

**Killer** (`relay-killer`, root `cron` job, every minute). Only root can signal `sshd`'s connection
processes, so this is the one privileged step, and it decides nothing:

1. For each request in `/run/pos-tunnel/kill/` (`<pid>-<start time>`): if that pid still has that
   start time and its command line is an `sshd` process of user `tunnel`, kill it. Delete the
   request either way.
2. Fail closed: if the daemon's heartbeat is older than 3 minutes, kill every `tunnel` `sshd`
   process. A stalled daemon can no longer enforce deadlines, so no tunnel outlives it.
3. Write its own beat to `/run/pos-tunnel/killer.beat`.

It logs nothing; the daemon sees each disconnect in `sshd`'s log and records it.

Why this shape:

- The container can't see which process holds a port: `sshd`'s children refuse inspection and
  Docker withholds `CAP_SYS_PTRACE`, so `ss -p` shows no process. The login line is the only link
  from a key to a process.
- `sshd` checks a key only at login, so a POS that opened a spare connection during its lease could
  re-bind its port after the holder was killed. Matching on the fingerprint ends all of them, and
  killing every `tunnel` connection instead would interrupt other sessions.
- One owner for leases, connections and logging: short-lived processes can't each hold an
  `aeth_ext` connection, and a single owner needs no locks.
- Failure modes stay safe: a stalled daemon freezes the relay (no logins, no `tunnelctl`) and the
  killer drops every tunnel; a dead `sshd`, `cron` or killer restarts the container.

Enforcement doesn't depend on the POS cooperating: a client connecting with `ssh -N` never runs a
session command, so nothing that runs inside the session could enforce a deadline.

## 7. Flows

### 7.1 Distribution, install and setup

NinjaOne's API can't create or update library scripts, so the library holds only two scripts that
never change; the real code ships as a signed GitHub release asset. What does change (the relay's
address and public key, the signing public key) reaches POSes through the fleet fields (section 3).

**Signing** (admin workstation): after changing `pos/package/`, `poe sign-pos`
(`scripts/sign_pos.py`) rewrites `pos/manifest.json` (the POS package `version` and a `sha256` per
file) and signs it with `ssh-keygen -Y sign -n pos-tunnel-release` → `pos/manifest.json.sig`; both are
committed. The private key is the one `posctl-admin signing keygen` stored (`POS_TUNNEL_SIGNING_KEY`
overrides the path). The package version is independent of the wheel version and rises only when the files
change, so CLI-only releases don't touch the fleet.

**Release:** `devkit release` as usual. CI builds the `posctl` wheels; the `pos-package` job
(kept through `setup-project` by `[tool.devkit].release-workflow-jobs`) re-verifies the committed
manifest and signature against the files, then attaches `pos-package.zip`, `pos-manifest.json` and
`pos-manifest.json.sig` to the release. CI never holds the signing key; it only packs what was signed.
The `ci.yml` workflow runs the same verification on every push, so a forgotten re-sign fails there
first.

**`Invoke-PosTunnel -Action <Open|Close|Touch|Rekey> …`** (library): runs
`versions\<current>\<Action>.ps1` with the remaining arguments. `posctl` runs every per-session action
through it, so a session never downloads anything.

**`Install-PosTunnel [-Force]`** (library). The release URL (this repo's latest GitHub release) is
hardcoded; the relay values and the signing public key are read from the fleet fields
(`Ninja-Property-Get`). Idempotent: every run converges the device to the latest release and a correct
setup, and a run with nothing to do changes nothing.

1. Secure `C:\ProgramData\PosTunnel` before reading or writing anything in it: owner SYSTEM,
   SYSTEM-only ACL, inheritance off. If it exists in any other form (another owner or ACL, or a
   junction), delete it first (a junction as a link, never followed) and install from scratch: a
   session in progress is lost and `Setup` generates a new relay key. `C:\ProgramData` lets any user
   create a folder and own it, and SYSTEM runs `Watch.ps1` from this one every 2 minutes, so a folder
   a standard user created or wrote into first would be their path to SYSTEM.
2. If a session is open (`session.json` exists): without `-Force`, report "deferred", exit 0, since
   neither an upgrade nor setup repair should change `sshd` or the tasks under a live session. With
   `-Force` (used by `relay point`), run `Watch`'s teardown first.
3. Download `pos-manifest.json` and its `.sig` from the latest release into that folder (never
   `%TEMP%`, which standard users can write to). Verify with `ssh-keygen -Y verify` against the
   `posTunnelSigner` public key (the Win32-OpenSSH `ssh-keygen` once installed; on a fresh POS, the
   one Windows bundles, section 11). Fail on a bad
   signature; the installed version stays active.
4. Manifest version lower than installed → fail (rollback protection: an attacker who can serve files
   could otherwise serve an old, validly signed release). Higher → download `pos-package.zip` into
   that folder and read it in memory: write an entry to `staging\` only if its name is exactly a
   manifest file and its `sha256` matches; any other entry or a missing file fails the install. No
   archive content reaches disk before its hash matches, so a malicious archive can't place files
   (e.g. through `..\` names). Move `staging\` to `versions\<version>`, keep the previous version dir,
   delete older ones. Equal → skip the download.
5. Run `versions\<version>\Setup.ps1` with the relay values. Only after it succeeds, write
   `current` = the version, so a failed upgrade leaves the previous version active.

**Scheduling:** `Install-PosTunnel` runs from the POS NinjaOne policy **daily at 4 AM**, after the
POSes' own 2 AM Windows Update and 3 AM restart, so it neither competes with an update nor is cut
off by the restart. That
installs new devices, rolls out releases, and repairs drift or tampering, all visible in NinjaOne's
activity log and pausable fleet-wide by disabling one policy entry. `posctl update <DisplayName>`
runs it on demand (a newly added device, or rolling a fix out before the next scheduled run). A
self-updating task on the POS was rejected: invisible to NinjaOne and one more thing on the device to
keep healthy.

**`Setup`** (from the package, run by `Install-PosTunnel`). Every step checks before it changes:

1. Write `C:\ProgramData\ssh\sshd_config`: `ListenAddress 127.0.0.1`, `AllowUsers support`, key auth
   only, default `Match Group administrators` file. Always, and before OpenSSH is installed if it
   isn't yet. `AllowUsers`: `administrators_authorized_keys` applies to every administrator, so
   without it the session key would also log in as the till account or `BackupAdmin`. Key auth only:
   `BackupAdmin` has the same known password on every POS.
2. Install OpenSSH if `C:\Program Files\OpenSSH\sshd.exe` is missing: remove Windows' built-in
   OpenSSH Server capability if present (it competes for the `sshd` service name), then install the
   Win32-OpenSSH MSI. Only this first install happens here; NinjaOne's WinGet deployment
   (`Microsoft.OpenSSH.Preview`) updates it afterwards, so security fixes arrive without a package
   release. NinjaOne must not be the first to install it: the MSI installs `sshd` as Automatic and
   starts it, and `sshd` writes the default config (all interfaces, password login) only when none
   exists, so a POS without step 1's file would expose `sshd` to the store LAN. Every later MSI
   upgrade recreates and starts the service the same way; the existing config is never overwritten
   (`wmain_sshd.c` copies the default only if the file is missing), so that `sshd` accepts nothing
   outside a session, and `Watch` stops it. Our scripts call `C:\Program Files\OpenSSH\` binaries by
   full path, never the older copies in `System32`.
3. Service start type Manual, stopped. Registry `DefaultShell` = Windows PowerShell.
4. Create local admin `support` with a random discarded password, disabled. (Key auth uses an S4U
   logon, so the password is never needed.)
5. Generate the relay key pair if absent (`Install-PosTunnel` step 1 has already secured the folder).
6. Write the relay's host and port to `relay.json` and pin its public key in
   `C:\ProgramData\PosTunnel\known_hosts`, replacing any previous values. `Open` builds the tunnel
   command from these.
7. Register tasks: `PosTunnel-Watch` (SYSTEM, every 2 min + at startup, runs this version's
   `Watch.ps1`; always enabled, so it also undoes an MSI upgrade's restart of `sshd` between
   sessions) and `PosTunnel-Link` (disabled).
8. Publish `posTunnelRelayKey`, `posTunnelHostKey`, `posTunnelVersion` custom fields
   (`Ninja-Property-Set`).

State (`relay_key`, `relay.json`, `known_hosts`, `session.json`, `lease`) lives in `C:\ProgramData\PosTunnel`
itself, outside `versions\`, so it survives upgrades.

### 7.2 `posctl connect <DisplayName> [--idle-timeout <dur>]`

1. Resolve the device via the NinjaOne API: exact display-name match among POS devices (section 8),
   exactly one, online.
2. Read its custom fields; error if setup hasn't run.
3. Generate a session key pair into the local session state dir.
4. `ssh ctl@relay tunnelctl open <port> <id> <idle-seconds> <relay pubkey>`.
5. NinjaOne API: run `Invoke-PosTunnel -Action Open -Port … -IdleSeconds … -SessionKey …` as SYSTEM.
6. Poll `tunnelctl status <port>` until listening (timeout ~3 min; NinjaOne script dispatch is slow).
   On timeout: `tunnelctl close`, report. If `tunnelctl` reports the relay starting, `connect` and
   `status` say so and that the POS retries within 2 minutes, and a timeout says to retry `connect`
   rather than failing bare.
7. Write `~/.ssh/posctl/config` entry and `~/.ssh/posctl/known_hosts` line (section 8).
8. Print the alias.

**`Open`** (POS, SYSTEM): validate parameters → write the session key as the sole line of
`administrators_authorized_keys` (SYSTEM+Administrators ACL, or `sshd` ignores it) → enable `support`
→ start `sshd`, then verify its listeners are loopback only (abort and tear down if not — the
Windows firewall is off, so this is the only thing keeping `sshd` off the store LAN) → write
`session.json` (`port`, `idle_seconds`, `started`) and touch `lease` → set `PosTunnel-Link`'s action to
`ssh -N -R <port>:localhost:22 tunnel@<relay> -p <relay port> -i relay_key -o ExitOnForwardFailure=yes
-o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o BatchMode=yes -o UserKnownHostsFile=known_hosts`
→ enable and start `PosTunnel-Link` and run `PosTunnel-Watch`.

**`Watch`** (POS, SYSTEM, every 2 min and at startup):
1. No `session.json` → ensure the idle state and exit: `sshd` Manual and stopped (an OpenSSH MSI
   upgrade sets it Automatic and starts it), `administrators_authorized_keys` empty, `support`
   disabled, `PosTunnel-Link` stopped and disabled.
2. Lease mtime older than `idle_seconds`, or `started` older than 72h → **teardown**: stop
   `PosTunnel-Link`, stop `sshd`, empty `administrators_authorized_keys`, disable `support`, delete
   `session.json` and `lease`, disable `PosTunnel-Link`.
3. `PosTunnel-Link` not running → start it.

`Watch` is the only teardown implementation; everything else triggers it. The startup trigger means a
reboot during a session brings the tunnel back, and a reboot after expiry cleans up.

### 7.3 `posctl keepalive <DisplayName>`

1. `tunnelctl renew <port>`. On failure stop and report — the relay lease is the one that counts.
2. Touch the POS lease over the tunnel: `ssh pos-x` setting `lease`'s `LastWriteTime`.
3. If step 2 fails (tunnel down), run `Invoke-PosTunnel -Action Touch` via the NinjaOne API instead.
4. Print the new idle deadline and the time left before the 72h maximum.

### 7.4 `posctl status [<DisplayName>]`

`tunnelctl status`, plus the POS lease age when the tunnel is up.

### 7.5 `posctl close <DisplayName>`

`tunnelctl close <port>` → NinjaOne API run `Invoke-PosTunnel -Action Close`
(backdates `lease`, starts `PosTunnel-Watch`, which tears down) → remove the local config and
`known_hosts` entries and the session key.

### 7.6 `posctl rebuild <DisplayName>` (break glass)

`close`, wait until `tunnelctl status` shows the port released (the killer runs every minute), then
`connect --rebuild`. New session key, new relay lease, new 72h maximum. Logged distinctly by
`tunnelctl`.

This defeats the 72h maximum, so an agent should not run it on its own. `rebuild` always prints a
warning addressed to AI agents: it resets the 72h maximum, and an agent should not proceed unless the
operator explicitly told it to rebuild this session, and should otherwise ask. Then:

- stdin is a terminal: `y/N` prompt.
- stdin is not a terminal (an agent's shell tool): exit non-zero unless `--yes` was passed.

This urges an agent to reconsider without hard-denying it, and needs no per-workstation agent
configuration.

### 7.7 Setup commands: `login`, `operator import`, `relay set`, `update`

- `login`: prompts for the NinjaOne client ID and secret and stores them in the OS keyring.
- `operator import`: prompts (hidden input, never an argument, so it stays out of shell history) for
  the bundle `posctl-admin operator add` printed, then installs its operator private key and writes
  `config.toml` from it.
- `relay set <host>[:<port>] <public key>`: points this workstation's `posctl` at a relay. The line
  `relay point` prints is this command, ready to send to the other operators.
- `update`: runs `Install-PosTunnel` on the device via the NinjaOne API (section 7.1).

### 7.8 `posctl rekey <DisplayName> | --all`

Runs `Invoke-PosTunnel -Action Rekey` on the device (with `--all`, every POS): regenerates the POS
relay key pair and the POS SSH server key pair (`ssh-keygen -A` after deleting the old ones), then
republishes `posTunnelRelayKey` and `posTunnelHostKey`. Refused on a device with an open session
(skipped and reported under `--all`). For after a reimage or a suspected leak; rekeying a POS that
is still compromised gains nothing, since the attacker reads the new private keys.

### 7.9 `posctl-admin`

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
- `operator add <name>`, `operator remove <name>`, `operator list`: `add` generates an operator key
  pair and prints, once, a single-line bundle for the new operator's `posctl operator import`: base64
  of a small TOML document holding the operator private key and the admin's `config.toml` (NinjaOne
  base URL, script IDs, POS policy ID, relay host, port and public key). It contains a private key, so
  it travels like a password (e.g. a password manager), never by email or chat. `posctl-admin` keeps
  only the public keys, the admin's own included. All three print the full `OPERATOR_KEYS=` line;
  redeploy the relay to apply it. The new operator still runs `posctl login` with their own NinjaOne
  credential.

## 8. Operator workstation

- Config `posctl/config.toml` in the platform config dir: NinjaOne API base URL (region-specific),
  library script IDs for `Install-PosTunnel` and `Invoke-PosTunnel`, and the POS policy ID; relay
  host, port and public key (set by `relay keygen --activate` on the admin's workstation,
  `operator import` or `relay set` on others); operator private key path.
- NinjaOne API (OAuth client credentials; scopes `monitoring` to read, `management` to run scripts
  and write fields; base URL `app`, `us2`, `eu`, `ca` or `oc` `.ninjarmm.com`):
  - `GET /v2/devices`: `displayName`, `offline`, `policyId` (an override) else `rolePolicyId`. A POS
    is a device whose effective policy is the POS policy. The device filter has no policy term, so
    `posctl` filters client-side; this defines "every POS" and limits `connect`'s name match.
  - `GET /v2/device/{id}/custom-fields`: the device fields.
  - `POST /v2/device/{id}/script/run` with `type: SCRIPT`, the library script `id`, `runAs: system`
    and `parameters`: one string NinjaOne passes to the script's `param` block (strings only;
    ``& | ; $ > < ` !`` forbidden, which none of our values contain).
  - `PATCH /v2/organization/{id}/custom-fields`: the fleet fields (`posctl-admin`).
  - Scripts are read-only through the API (`GET /v2/automation/scripts`), hence the fixed library
    scripts (section 7.1).
- `~/.ssh/config` needs `Include posctl/config` above any `Host` block (once, by hand).
- Generated entry:

```
Host pos-<slug>
  HostName localhost
  Port <port>
  User support
  ProxyJump posctl-relay
  IdentityFile <session dir>/session_key
  IdentitiesOnly yes
  HostKeyAlias pos-<device id>
  UserKnownHostsFile ~/.ssh/posctl/known_hosts
  StrictHostKeyChecking yes
  BatchMode yes
```

  plus a `posctl-relay` entry (`jump@<relay>:<port>`, operator private key, relay public key pinned).

- Windows OpenSSH has no `ControlMaster`, so each command is a full handshake through the jump
  (roughly 1–2 s).

## 9. Limitations

- S4U logon: the `support` session has no network credentials (no access to network shares).
- One session per device at a time.
- Up to ~2 minutes to recover a dropped tunnel (`Watch` interval).
- The POSes restart nightly at 3 AM: an open session survives (`Watch` restores the tunnel at
  startup), but its tunnel is down for a few minutes.
- If the relay daemon exits, the container restarts and every tunnel drops until the POSes
  reconnect. If it stalls, the relay freezes (no logins, no `tunnelctl`), the killer drops every
  tunnel, and it stays down until someone restarts it (devkit-container's supervisor alerts but
  doesn't restart an unhealthy app yet).
- The relay can't start while the central log server is unreachable (`aeth_ext` exits at startup);
  `restart: always` brings it up within about a minute of the log server returning.
- `connect` takes as long as NinjaOne takes to dispatch a script (typically tens of seconds).
- `relay point` ends every open session.
- Commands run in a session aren't recorded: the relay sees only encrypted traffic, and recording on
  the POS was judged not worth its cost.

## 10. Alternatives considered

- **Overlay network (Tailscale, ZeroTier, Cloudflare Tunnel):** another agent on every POS and a
  third-party coordination service in the access path; Tailscale SSH has no Windows server anyway.
- **Joining the existing WireGuard hub:** would put untrusted POS machines on the same network as the
  office database PC.
- **NinjaOne API only (no SSH):** no network exposure, but tens of seconds per command and awkward
  output retrieval. Kept as the fallback path for `Touch`/`Close` only.
- **Rust binary on the POS:** adds allowlisting, signing and fleet update problems for no gain over
  NinjaOne scripts plus a signed release.
- **SSH certificates** (a CA key pair whose private key signs other public keys): for session auth, a
  long-lived CA private key that opens every POS, which per-session keys avoid; for the relay's
  identity, `relay point` already updates the fleet in one command; for POS identities, signing what
  the custom field reports is no stronger than reading it; for two operators, a key list is simpler.
- **A package hash held in NinjaOne instead of release signing:** a manual NinjaOne edit per release.
  A signing public key distributed through NinjaOne keeps the same root of trust with no per-release
  step.
- **Admin-only commands hidden in `posctl`:** the admin's own agent runs with the admin's key, so it
  would see them; a separate binary keeps them out of `posctl --help` for everyone.
- **Package managers (WinGet via NinjaOne, PowerShell Gallery, Chocolatey) or NinjaOne "Install
  Application" from a URL:** NinjaOne's WinGet integration documents only the public catalog; the
  others add a registry account or package manager to trust, and none gives an integrity check
  stronger than the signed release.

## 11. To verify during implementation

Verified so far: the NinjaOne items in sections 3 and 8 (from NinjaOne's documentation and its
OpenAPI spec, not yet against the tenant); `permitlisten="localhost:<port>"` accepting the Windows
client's `-R <port>:localhost:22`; `ExposeAuthInfo` handing `tunnelctl` the operator's public key
under its `ForceCommand` (both against OpenSSH 10 on Alpine, before the relay moved to bookworm's
9.2). Still open:

- NinjaOne's parameter string: whether named parameters (`-Port 20001`) work or only positional
  ones (its documentation shows positional only).
- `ssh-keygen -Y verify` with the `ssh-keygen` Windows bundles, on the oldest Windows build in the
  fleet: `Install-PosTunnel` uses it on a fresh POS, before `Setup` has installed Win32-OpenSSH.
  OpenSSH before 8.1 lacks `-Y`.
- NinjaOne's WinGet patching updating a Win32-OpenSSH MSI it didn't install itself.
- Which POSes already have Windows' built-in OpenSSH Server capability (`Setup` removes it).
- `ssh-keygen -A` regenerating the Win32-OpenSSH server key pair in `C:\ProgramData\ssh` (`rekey`).
- On OpenSSH 9.2 (the relay's): the two checks above again; the login line's format and that its
  pid is the connection's privileged process, whose command line names user `tunnel` (section 6.5);
  `sshd` blocking on a full `/dev/log` rather than dropping the line (what makes a stalled daemon
  freeze logins instead of letting one through unrecorded).

## 12. Deployment order

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

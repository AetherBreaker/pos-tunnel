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

| Component | Where | What |
|---|---|---|
| `posctl` | operator workstation | Rust CLI, shipped as a maturin binary wheel on the private index (`uv tool install pos-tunnel`). Session commands for every operator. Calls the NinjaOne API, drives the relay via `tunnelctl`, writes local SSH config. |
| `posctl-admin` | admin's workstation | Second binary in the same wheel: key generation and fleet configuration (section 7.9). Kept apart so its commands never show in `posctl --help`. |
| NinjaOne library scripts | NinjaOne → POS | Two small PowerShell scripts pasted into NinjaOne once and never changed: `Install-PosTunnel` (downloads, verifies and installs the POS package) and `Invoke-PosTunnel` (runs an action from the installed package). Section 7.1. |
| POS package | GitHub Releases → `C:\ProgramData\PosTunnel` | PowerShell, run as SYSTEM: `Setup`, `Open`, `Close`, `Touch`, and `Watch`, which owns the session lifecycle on the POS. Signed release asset. |
| relay | Docker container on the Coolify VPS | Alpine `sshd` on its own published port (2222), separate from the host's `sshd` (Coolify manages the host over SSH as root; it must not be touched). Plus `tunnelctl` (lease/key management), `reaper` (enforcement) and a log watcher (which connection logged in with which key). |

## 2. Threat model

- **POS machines are untrusted.** Firewall off, employees may have local admin. Assume an attacker on a
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

| Key pair | Generated | Private key | Public key reaches its holder via | Authorizes |
|---|---|---|---|---|
| POS relay key pair (per device) | by `Setup`, once per device; again on `posctl rekey` or a from-scratch reinstall (section 7.1, `Install-PosTunnel` step 1) | POS: `C:\ProgramData\PosTunnel\relay_key` | custom field `posTunnelRelayKey` → `posctl` → `tunnelctl open` | `tunnel@relay`, only while a session is open |
| POS SSH server key pair (per device) | by Windows OpenSSH when `Setup` installs it; again on `posctl rekey` | POS: Windows OpenSSH's key files | custom field `posTunnelHostKey` → `posctl` → local `known_hosts` | operator verifies it is talking to that POS's `sshd` |
| Session key pair | by `posctl`, on every `connect` and `rebuild` | operator workstation, session state dir | `Open` script parameter (public keys are safe in NinjaOne activity logs) | `support@POS` for this session only |
| Operator key pair (per operator) | by `posctl-admin operator add` (the admin's own: by hand, section 12) | that operator's workstation, installed with `posctl operator import` | relay env var `OPERATOR_KEYS` → `/etc/ssh/operator_keys` (root-owned) at container start | `ctl@relay` (forced `tunnelctl`) and `jump@relay` (forwarding only); names the operator in `tunnelctl`'s log. Identity, not a security boundary. |
| Relay SSH server key pair | by `posctl-admin relay keygen`; again only to rotate it or move the relay | relay env var `RELAY_SSH_PRIVATE_KEY`; a copy in `posctl-admin`'s config dir | `relay point` → fleet field → `Setup` → POS `known_hosts`; `posctl` config via `relay keygen --activate` (admin), `operator import` or `relay set` (others) | POS and operator verify the relay |
| Release signing key pair | by `posctl-admin signing keygen`; again only if lost or leaked | admin workstation only — never CI, so a compromised GitHub account can't sign | `signing keygen` → fleet field → `Install-PosTunnel`; and `pos/allowed_signers`, for CI's check | POS package releases (namespace `pos-tunnel-release`) |
| NinjaOne API client credentials (not a key pair) | in NinjaOne's console | OS keyring (`posctl login`) | — | running SYSTEM scripts on every POS; the admin's also writes the fleet fields |

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

| Timer | Value | Authoritative on | Mirror |
|---|---|---|---|
| Idle timeout | 12h default; `--idle-timeout` may only shorten it | relay lease (`tunnelctl`, reaper) | POS lease file mtime (`Watch`) |
| Absolute maximum | 72h from `connect` | relay lease | POS session start time (`Watch`) |

- Each side computes its deadlines from **its own clock**. `posctl` never sends a timestamp, so clock
  skew between the three machines doesn't matter.
- The relay rejects an idle timeout above 12h regardless of what `posctl` sends.
- The POS mirror exists only to clean up locally. An attacker extending it gains nothing: the relay
  still cuts the tunnel at its own deadline, and the POS is already theirs.
- Resetting the 72h maximum requires `posctl rebuild` (section 7.6).

## 6. Relay

### 6.1 Container

- `openssh-server`, `iproute2` (for `ss`), a cron daemon, and Python for the log watcher. Entrypoint:
  devkit-container's `run` in supervised mode, with the log watcher (section 6.5) as the supervised
  app and `crond` and `sshd` (logging to syslog, not stderr) started before it. The container exits
  when the watcher exits or stalls. How the relay fits devkit-container is open (section 11).
- Published port 2222/tcp directly (not through Coolify's HTTP proxy — SSH is not TLS, so SNI routing
  can't apply). Vultr firewall group and host `ufw` (if enabled) must allow it.
- Volume `/data`: `state/` (lease files, the POS key file, the log). No key material: losing the
  volume changes no identity.
- Environment, both single-line so `posctl-admin`'s output pastes straight into Coolify's `.env` view:
  `RELAY_SSH_PRIVATE_KEY` (base64 of the OpenSSH private key file) and `OPERATOR_KEYS`
  (`<name>=<ed25519 base64>`, comma-separated). At each start the entrypoint writes the private key
  to a root-only file under `/run` and the operator keys to `/etc/ssh/operator_keys` (root-owned;
  not on the volume, because `sshd`'s `StrictModes` rejects a `jump` key file inside a `ctl`-owned
  directory). It refuses to start if either is missing, and never generates a key pair.
- Users: `tunnel` and `jump` have `/sbin/nologin` as their shell; `ctl` needs `/bin/sh`, because
  `sshd` runs a `ForceCommand` through the login shell. Alpine creates accounts locked, which `sshd`
  rejects even for key auth, so each gets password `*` (unusable, but not locked).
  Container restarts drop live tunnels; POS `Watch` reconnects them within 2 minutes.
- DNS: a dedicated A record for the relay (not the Coolify UI hostname), not proxied through Cloudflare.

### 6.2 Users and `sshd_config`

| User | Who | Allowed |
|---|---|---|
| `tunnel` | every POS | remote forwarding of its own port only. No shell, no command, no local forwarding. |
| `jump` | operator | local forwarding (`ProxyJump`) to `localhost` only. No shell. |
| `ctl` | operator | `tunnelctl` only (forced command; arguments via `SSH_ORIGINAL_COMMAND`; `ExposeAuthInfo` tells it which operator key logged in). No forwarding. |

Global: key auth only, no root login, `AllowUsers tunnel jump ctl`, `GatewayPorts no`, no agent/X11/
stream-local forwarding, `PermitTunnel no`, `ClientAliveInterval 30`/`ClientAliveCountMax 3`,
`LogLevel VERBOSE` (logs key fingerprints). See `relay/sshd_config`.

`AllowTcpForwarding remote` on `tunnel` is the key isolation control: without it, any POS could open
connections to every other POS's tunnel port on the relay's loopback.

### 6.3 POS keys

`tunnel`'s keys come from `AuthorizedKeysCommand`, run as a dedicated `keyreader` user reading
`/data/state/tunnel_keys` (owned by `ctl`, group `keyreader`, mode 0640). `tunnel` itself can't
read the file, and has no way to run anything that could. One line per open session:

```
restrict,port-forwarding,permitlisten="localhost:<port>",expiry-time="<idle deadline, UTC>" ssh-ed25519 <base64>
```

- `restrict,port-forwarding` re-enables forwarding only; `sshd_config` narrows that to remote forwarding.
- `permitlisten` limits the key to its own port.
- `expiry-time` blocks *new* logins after the deadline; it does not end a live connection (the reaper
  does). `renew` rewrites it.
- The public key string comes from a POS-writable custom field. `tunnelctl` accepts only
  `^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$` (comment dropped) and builds the line itself, so a malicious value
  can't inject options or extra lines.

### 6.4 `tunnelctl`

Runs as `ctl`. All state under `/data/state` (dir owned by `ctl:keyreader`, 0750; lease files
0600, so `keyreader` can read only the keys file). Every call is appended to the log with the
operator's name (its key's entry in `OPERATOR_KEYS`), the command and arguments; `open` also records
the name in the lease.

| Command | Effect |
|---|---|
| `open <port> <device-id> <idle-seconds> <pubkey> [--rebuild]` | Validate (port range, idle ≤ 43200, key format). Refuse if a lease for `<port>` exists, or if `tunnel_keys` already holds the same key (`sshd` uses the first matching line, so a second lease's POS would get the first one's port). Write lease file `leases/<port>` (`device_id`, `idle_seconds`, `started`, `idle_deadline`, `absolute_deadline = started + 72h`, and the key's `fingerprint`, which the reaper matches against logins) and the key line. `--rebuild` is logged distinctly. |
| `renew <port>` | `idle_deadline = min(now + idle_seconds, absolute_deadline)`; rewrite `expiry-time`. Error if no lease or already expired. |
| `close <port>` | Set `idle_deadline = now`; the reaper removes it within a minute. |
| `status [<port>]` | Deadlines, remaining time, and whether the port is listening. |

`ctl` can't kill another user's processes, so `tunnelctl` never ends connections itself; it only marks
leases. Enforcement is the reaper's job.

### 6.5 Reaper and log watcher

`sshd` logs through syslog, where each login line carries the process ID of that connection's
privileged `sshd` process and the key's fingerprint:
`sshd-session[17]: Accepted publickey for tunnel from <ip> port <n> ssh2: ED25519 SHA256:<fp>`.

**Log watcher** (Python, using `aeth_ext`; the container's supervised app, section 6.1). Receives
`sshd`'s syslog messages on `/dev/log` and sends every line to the central log server through
`aeth_ext`, for activity monitoring. It writes no log files and sends nothing to Docker's log beyond
what `aeth_ext` itself emits there (emergency logging, log-server probes): Docker's and Coolify's log
handling cost performance this doesn't need. For each `tunnel` login it creates one file in `/run/pos-tunnel/connections/`,
named `<pid>-<start time>` (start time from `/proc/<pid>/stat`, readable without privileges) and
holding the fingerprint; written under a temporary name and renamed into place, so a reader never
sees a partial file. It never deletes. It writes its heartbeat from its receive loop, not a thread,
so a stalled loop stops the beats: `sshd` waits for each log line to be received, so a stalled
watcher stalls new logins, and the supervisor stops a watcher whose heartbeat goes stale, taking the
container with it.

**Reaper** (root `crond` job, every minute; serializes with `tunnelctl` on a `flock` over the state
dir, never with the watcher):

1. Delete each connection file whose process is gone: no such pid, or a different start time (pids
   get reused).
2. For each lease past `min(idle_deadline, absolute_deadline)`: delete its key line and lease file,
   log it. The key line goes first, so the POS can't log back in once step 3 ends its connections.
3. For each connection file whose fingerprint belongs to no remaining lease: kill that process and
   its children, delete the file, log it. This ends every connection of an expired, closed or
   hand-deleted lease, spare ones included, and nothing else.
4. Report each `tunnel` `sshd` process that has no connection file (its login was never recorded),
   and leave it running.

Why this shape:

- The container can't see which process holds a port: `sshd`'s children refuse inspection and
  Docker withholds `CAP_SYS_PTRACE`, so `ss -p` shows no process.
- `sshd` checks a key only at login, so a POS that opened a spare connection during its lease could
  re-bind its port after the holder was killed. Matching on the fingerprint ends all of them.
- Killing every `tunnel` connection instead would interrupt other sessions.
- One file per connection, created by rename and removed by unlink, needs no lock between the
  watcher and the reaper, so neither can stall the other, and nothing grows with uptime.
- `/run/pos-tunnel/` is emptied at every container start: a restart has already ended every
  connection, and pids start over from 1, so old files would name unrelated processes.

The reaper doesn't depend on the POS cooperating: a client connecting with `ssh -N` never runs a
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
   `posTunnelSigner` public key (the OpenSSH client ships with Windows 10 and 11). Fail on a bad
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

**Scheduling:** `Install-PosTunnel` runs from the POS NinjaOne policy **daily**, off-hours. That
installs new devices, rolls out releases, and repairs drift or tampering, all visible in NinjaOne's
activity log and pausable fleet-wide by disabling one policy entry. `posctl update <DisplayName>`
runs it on demand (a newly added device, or rolling a fix out before the next scheduled run). A
self-updating task on the POS was rejected: invisible to NinjaOne and one more thing on the device to
keep healthy.

**`Setup`** (from the package, run by `Install-PosTunnel`). Every step checks before it changes:

1. Install OpenSSH Server: `Add-WindowsCapability`; fall back to the Win32-OpenSSH MSI if that fails.
2. `sshd_config`: `ListenAddress 127.0.0.1`, key auth only, default `Match Group administrators` file.
   Service start type Manual, stopped. Registry `DefaultShell` = Windows PowerShell.
3. Create local admin `support` with a random discarded password, disabled. (Key auth uses an S4U
   logon, so the password is never needed.)
4. Generate the relay key pair if absent (`Install-PosTunnel` step 1 has already secured the folder).
5. Write the relay's host and port to `relay.json` and pin its public key in
   `C:\ProgramData\PosTunnel\known_hosts`, replacing any previous values. `Open` builds the tunnel
   command from these.
6. Register tasks, disabled: `PosTunnel-Watch` (SYSTEM, every 2 min + at startup, runs this
   version's `Watch.ps1`) and `PosTunnel-Link`.
7. Publish `posTunnelRelayKey`, `posTunnelHostKey`, `posTunnelVersion` custom fields
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
   On timeout: `tunnelctl close`, report.
7. Write `~/.ssh/posctl/config` entry and `~/.ssh/posctl/known_hosts` line (section 8).
8. Print the alias.

**`Open`** (POS, SYSTEM): validate parameters → write the session key as the sole line of
`administrators_authorized_keys` (SYSTEM+Administrators ACL, or `sshd` ignores it) → enable `support`
→ start `sshd`, then verify its listeners are loopback only (abort and tear down if not — the
Windows firewall is off, so this is the only thing keeping `sshd` off the store LAN) → write
`session.json` (`port`, `idle_seconds`, `started`) and touch `lease` → set `PosTunnel-Link`'s action to
`ssh -N -R <port>:localhost:22 tunnel@<relay> -p <relay port> -i relay_key -o ExitOnForwardFailure=yes
-o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o BatchMode=yes -o UserKnownHostsFile=known_hosts`
→ enable and start `PosTunnel-Watch`.

**`Watch`** (POS, SYSTEM, every 2 min and at startup):
1. No `session.json` → disable own tasks, exit.
2. Lease mtime older than `idle_seconds`, or `started` older than 72h → **teardown**: stop
   `PosTunnel-Link`, stop `sshd`, empty `administrators_authorized_keys`, disable `support`, delete
   `session.json` and `lease`, disable both tasks.
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

`close`, wait until `tunnelctl status` shows the port released (the reaper runs every minute), then
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
- If the relay's log watcher exits or stalls, the container stops and every tunnel drops until it
  restarts.
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
under its `ForceCommand` (both against the relay image). Still open:

- NinjaOne's parameter string: whether named parameters (`-Port 20001`) work or only positional
  ones (its documentation shows positional only).
- `Add-WindowsCapability` on the actual POS image.
- `ssh-keygen -Y verify` on the oldest Windows build in the fleet (Windows 10's bundled OpenSSH
  client is the oldest candidate).
- `ssh-keygen -A` regenerating Windows OpenSSH's server key pair in `C:\ProgramData\ssh` (`rekey`).
- devkit-container for the relay (section 6.1):
  - Its supervisor only reports a stale app heartbeat (log line and `/fail` ping); it must also stop
    the watcher and exit. Expected to be a small update.
  - `sshd` and `crond` are long-running root daemons, but its startup scripts must exit, so they
    would start in the background, and nothing would notice `sshd` dying.
  - Its Dockerfile template is Debian-based; the relay image is Alpine.
  - Startup order: startup scripts run before the app, so `sshd` accepts logins a few seconds
    before the watcher listens. A POS logging in then goes unrecorded; the reaper reports it
    (section 6.5, step 4) but can't end it at expiry.

## 12. Deployment order

1. Admin key: generate the admin's operator key pair by hand (`ssh-keygen -t ed25519`) and build its
   public key into `posctl-admin`.
2. NinjaOne: paste `Install-PosTunnel` and `Invoke-PosTunnel` into the library; create the admin's
   API client (`posctl-admin` creates the custom fields on its first fleet-field write);
   `posctl login`; write `config.toml`, add the `Include`.
3. Release: `posctl-admin signing keygen`; `poe sign-pos`; commit; `poe release`.
4. Relay: `posctl-admin relay keygen --activate <host>[:<port>]` and `operator list` (or `add` for a second
   operator); paste both lines into Coolify; deploy; add the DNS record; open 2222 in the Vultr
   firewall.
5. With only one test device in the POS policy: `posctl-admin relay point <host>`, then test end to
   end. Then add the fleet to the policy and schedule `Install-PosTunnel` daily.

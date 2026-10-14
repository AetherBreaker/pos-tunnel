# pos-tunnel

On-demand SSH access to Windows POS machines managed by NinjaOne RMM, for occasional troubleshooting
by an operator, or a coding agent on the operator's workstation.

NinjaOne never carries the SSH traffic. It is the control plane: its API tells a POS to dial out to a
hardened SSH relay, and the operator connects through the relay to that dial-out. Sessions have a
12-hour idle timeout, renewable up to a 72-hour maximum, and leave nothing enabled on the POS when
they end.

```text
operator workstation                    relay (VPS container)                 POS (Windows)
  posctl ──NinjaOne API──────────────────────────────────────────────────────▶ Open script (SYSTEM)
  posctl ──ssh ctl@relay──▶ tunnelctl open/renew/close
                            127.0.0.1:<port> ◀──ssh -N -R (tunnel@relay)───── Link task
  ssh pos-x ──through jump@relay────▶ 127.0.0.1:<port> ═══════════════════════▶ sshd on 127.0.0.1:22
```

## Contents

- [Components](#components)
- [Security model](#security-model)
- [Using posctl](#using-posctl)
- [Setting it up](#setting-it-up)
- [Adding an operator](#adding-an-operator)
- [Sessions in detail](#sessions-in-detail)
- [What lives where](#what-lives-where)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

## Components

| Component | Where | What |
| --- | --- | --- |
| `posctl` | operator workstation | Rust CLI ([`cli/`](cli/)), shipped as a binary wheel on the private index (`uv tool install pos-tunnel`). Opens, renews and closes sessions through the NinjaOne API and the relay, and writes the `ssh` config for them. |
| `posctl-admin` | admin's workstation | Second binary in the same wheel: key generation and fleet configuration. It runs only for the operator key the binary was built for (`cli/admin.pub`), which keeps its commands out of `posctl --help`. |
| NinjaOne library scripts | NinjaOne → POS | `Install-PosTunnel` and `Invoke-PosTunnel` ([`pos/ninja/`](pos/ninja/)), pasted into the NinjaOne library once and never changed. NinjaOne's API can't edit library scripts, so the real code ships as a signed release asset. |
| POS package | GitHub release → `C:\ProgramData\PosTunnel` | PowerShell run as SYSTEM ([`pos/package/`](pos/package/)): `Setup`, `Open`, `Close`, `Touch`, `Rekey`, and `Watch`, which owns the session's lifecycle on the POS. Signed with the release signing key. |
| Relay | Docker container on the Coolify VPS | Its own repository, `AetherBreaker/pos-tunnel-relay`, a submodule at [`relay/`](relay/): `sshd` on port 2222 plus a Python daemon that owns leases, logging and enforcement. |

## Security model

**Threat model.** POS machines are untrusted: the firewall is off and the till account is a
passwordless local administrator, so anyone at a till has admin, can read anything on the POS
(including its relay private key) and can write its NinjaOne device fields. The goal is that a
compromised POS can affect only its own session: it can't reach another POS's tunnel, bind another
POS's port, read or change any lease or key on the relay, run code on the relay, or keep its tunnel
alive past the relay's deadline. It can deny or tamper with its own session; anything a POS returns
is data, never instructions. Trusted: the operator workstations, the NinjaOne tenant and its API
sign-ins, and the relay container. NinjaOne is the root of trust for fleet configuration.

**Keys** (all ed25519):

| Key pair | Made by | Private key | Lets its holder |
| --- | --- | --- | --- |
| POS relay key (per POS) | `Setup`; again on `rekey` | POS, `C:\ProgramData\PosTunnel\relay_key` | log in as `tunnel@relay` and forward its own port, only while a session is open |
| POS SSH server key (per POS) | `sshd`'s first start; again on `rekey` | POS | prove to the operator it is that POS's `sshd` |
| Session key (per session, per operator) | `posctl connect` | operator workstation | log in as `support` on that POS, for that session |
| Operator key (per operator) | `posctl-admin operator add` | operator workstation | log in as `ctl@relay` (forced `tunnelctl`) and `jump@relay` (forwarding only); names the operator in the relay's log |
| Relay SSH server key | `posctl-admin relay keygen` | relay environment; a copy with `posctl-admin` | prove to POSes and operators it is the relay |
| Release signing key | `posctl-admin signing keygen` | admin workstation only, passphrase-protected; never CI | sign POS package releases |

The NinjaOne sign-in (`posctl login`, a browser sign-in through the tenant's Native client app) runs
SYSTEM scripts on every POS as that NinjaOne user.

**NinjaOne custom fields** (global, text). Device fields (`posTunnelRelayKey`, `posTunnelHostKey`,
`posTunnelVersion`) are written by the POS and untrusted: `posctl` binds them to that device's port,
and the relay accepts only a well-formed `ssh-ed25519` key. Fleet fields (`posTunnelRelay`,
`posTunnelRelayServerKey`, `posTunnelSigner`) are organization-scoped and read-only to scripts, so no
POS can point the fleet at its own relay or signing key. `posctl-admin` creates missing definitions
and refuses to write if an existing one has different settings, since that may be tampering.

**On the relay.** `tunnel` may only forward its own port to the relay's loopback (`permitlisten`,
remote forwarding only), so no POS can connect to another's tunnel. `jump` forwards to `localhost`
only; `ctl` runs only `tunnelctl`. The daemon ends every connection of a lease that expired or was
closed, and a root `cron` job does the killing; if the daemon stalls, the killer drops every tunnel
(fail closed). Container restarts drop tunnels; POSes reconnect within 2 minutes.

**On the workstation.** The generated `ssh` entries pin each POS's and the relay's public keys, use
`BatchMode`, and set `ForwardAgent no`, so neither the relay nor a POS is ever handed the operator's
agent. A POS's script output is printed as its report with control characters removed.

**On the POS.** `sshd` listens on loopback only, which `Open` checks before every session; outside a
session it is stopped, `support` is disabled and no key is authorized. The state folder is SYSTEM-only;
`Install-PosTunnel` verifies every release's signature against the fleet's signing key and refuses an
older release than the installed one.

## Using posctl

```powershell
posctl connect "Store 42 Register 1"      # exact, case-sensitive NinjaOne display name
ssh pos-store-42-register-1 "Get-Service"
posctl status
posctl keepalive "Store 42 Register 1"
posctl close "Store 42 Register 1"
```

| Command | What it does |
| --- | --- |
| `posctl connect <name> [--idle-timeout <dur>]` | Opens a session, or joins the one another operator has open on that POS, and prints the `ssh` alias. `--idle-timeout` shortens the 12h idle timeout of a session this opens (whole seconds, `1s` to `12h`). Usually under half a minute; up to six (a slow POS, a POS's first session). |
| `posctl keepalive <name>` | Restarts the idle timeout on the relay and on the POS. |
| `posctl status [<name>]` | Open sessions: the alias where this workstation holds the session, who opened it, the time left, and whether the tunnel is up. |
| `posctl close <name>` | Ends the session for everyone on it, on the relay first, then on the POS. |
| `posctl rebuild <name> [--yes]` | Break glass: closes the session and opens a new one, which resets the 72h maximum. Asks first; without a terminal it needs `--yes`. An AI agent should run it only when the operator explicitly asks. |
| `posctl update <name>` | Runs `Install-PosTunnel` on that POS now, instead of waiting for the daily run. Deferred while a session is open. |
| `posctl rekey <name> \| --all [--force] [--yes]` | New relay and SSH server key pairs for one POS, or every online one. A POS in a session is refused (named) or skipped (`--all`); `--force` ends its session first. `--all` asks first. Takes about a minute per run: a POS counts as rekeyed once NinjaOne shows its new keys. |
| `posctl login` | Signs in to NinjaOne in the browser. |
| `posctl operator import` | Sets up this workstation from the bundle the admin sent (prompts for it). |
| `posctl relay set <host>[:<port>] <public key>` | Points this workstation at a relay (the line `posctl-admin relay point` prints). |

`connect` adds `Include posctl/config` at the top of `~/.ssh/config` the first time, so the alias works
from any `ssh`, Windows' or Git Bash's. A coding agent should give `connect` its full six minutes; a
`connect` that is cut off anyway leaves a lease the next `connect` on that workstation recognises,
ends and replaces. Commands of one operator can run at the same time.

## Setting it up

Done once, by the admin, in this order:

1. **Admin key.** Generate the admin's operator key pair by hand (`ssh-keygen -t ed25519`; if it has a
   passphrase, add it to `ssh-agent`) and commit its public key as `cli/admin.pub`, which
   `posctl-admin` is built with.
2. **NinjaOne.** Paste `pos/ninja/Install-PosTunnel.ps1` and `pos/ninja/Invoke-PosTunnel.ps1` into the
   script library. Create a Native client app: redirect `http://127.0.0.1`, scopes Monitoring,
   Management and Offline Access, grant types Authorization Code and Refresh Token. Then:

   ```powershell
   posctl-admin init --base-url https://app.ninjarmm.com --client-id <client ID> --organization <name> --policy <POS policy name> --operator-key <path> --name <your name>
   ```

   It signs in, finds the organization, the POS policy and both scripts by exact name, and writes this
   workstation's config. That organization is the only one the system touches.
3. **Signing key and first release.** `posctl-admin signing keygen` makes the passphrase-protected key,
   rewrites `pos/allowed_signers` and publishes the public key to `posTunnelSigner`. Then sign the
   package and release (see [Development](#development)). `posctl-admin signing publish <tag>` makes
   the fleet trust the key a given release was signed with.
4. **Relay.** `posctl-admin relay keygen <host>[:<port>]` prints the `RELAY_SSH_PRIVATE_KEY=` line, and
   `posctl-admin operator list` the `OPERATOR_KEYS=` line. In Coolify, create a Docker Compose
   application from `pos-tunnel-relay` with both lines in its environment and deploy it. Add a DNS A
   record for the relay (not proxied through Cloudflare), and open port 2222 in the VPS firewall.
5. **Point the fleet.** `posctl-admin relay point --device <test POS>` writes the fleet's relay fields
   and installs on that one POS; test end to end. Then `posctl-admin relay point` for every POS, and
   schedule `Install-PosTunnel` daily at 4 AM in the POS policy (after the POSes' 2 AM updates and 3 AM
   restart). That daily run installs new devices, rolls out releases and repairs drift.

`relay point` also rotates the relay's key pair or moves it to a new host: `relay keygen --replace`,
redeploy, then `relay point`. It ends every open session, and prints the `posctl relay set` line to
send the other operators.

## Adding an operator

1. The admin runs `posctl-admin operator add <name>`. It prints a one-line bundle holding the new
   operator's private key and the workstation config, once. Send it like a password (a password
   manager), never by email or chat.
2. The admin pastes the printed `OPERATOR_KEYS=` line into the relay's environment in Coolify and
   redeploys.
3. The operator runs `uv tool install pos-tunnel`, then `posctl operator import` (paste the bundle at
   the prompt), then `posctl login` as their own NinjaOne user.

An operator key with a passphrase must be in `ssh-agent`, since `posctl` runs `ssh` non-interactively;
`posctl` says so, with the commands, when it isn't. `posctl-admin operator remove <name>` takes an
operator off (redeploy the relay with the line it prints).

## Sessions in detail

- **Port and alias.** A POS's tunnel port is `20000 + its NinjaOne device ID`. Its alias is its display
  name's slug, prefixed `pos-`: `POS 000 Test` is `pos-000-test`.
- **Timers.** The idle timeout (12h, or shorter with `--idle-timeout`) and the 72h maximum are
  enforced by the relay; the POS mirrors them only to clean up after itself. Each side uses its own
  clock, so clock skew doesn't matter. Only `rebuild` resets the 72h maximum.
- **`connect`.** Generates a session key pair, opens a lease on the relay with the POS's relay public
  key, runs `Open` on the POS through NinjaOne, waits for the POS's report and the tunnel, writes the
  alias and logs in once through it. A failure after the lease is opened undoes it.
- **Sharing.** A second operator's `connect` joins with a key of its own (`Open -Mode Join`, POS package
  version 4 or later); the relay is unchanged. `close` ends the session for everyone on it. Two
  `connect`s for an idle POS can race: the relay grants one, and the other is told to `connect` again,
  which joins.
- **`keepalive`** renews the relay first, then the POS through NinjaOne (`support` can't write the
  POS's SYSTEM-only lease file). A POS that doesn't confirm is reported: it would end its side at its
  own deadline.
- **Script results.** NinjaOne's `script/run` returns nothing, so `posctl` follows a run through the
  device's activity list, told apart from another operator's by the requesting user. NinjaOne shows a
  field a script wrote about 40 s after the run's result, so `rekey` and `update` wait for it before
  reporting success.

## What lives where

**Operator workstation** (Windows; the config folder is `%APPDATA%\posctl`):

- `posctl\config.toml`: NinjaOne base URL and client ID, organization, POS policy and script IDs; the
  relay's host, port and public key; the operator key's path.
- `posctl\sessions\<device ID>\`: each session's key and `session.toml`.
- Windows Credential Manager, service `posctl`: the NinjaOne refresh token, and the access token and
  NinjaOne user ID that commands share. `posctl login` replaces them.
- `~\.ssh\posctl\config` and `known_hosts`: generated, rewritten by every session command. Don't edit.
- `POSCTL_CONFIG_HOME` moves the config folder, and the sign-in into plain files in it (a second
  identity on one machine, tests). `POSCTL_SSH_DIR` replaces `~\.ssh` (tests).
- `posctl` runs Windows' own OpenSSH client (`System32\OpenSSH`), never Git Bash's, which can't reach
  the Windows `ssh-agent`.

**POS** (`C:\ProgramData\PosTunnel`, SYSTEM-only):

- `versions\<version>\`: the installed package; `current` names the active version.
- `relay_key`, `relay.json`, `known_hosts`: the POS's relay key pair and the relay it dials.
- `session.json`, `lease`: present only during a session.
- Scheduled tasks `PosTunnel-Watch` (every 2 minutes and at startup: keeps a session's `sshd` and
  tunnel up, ends it at its deadlines, keeps everything off between sessions) and `PosTunnel-Link`
  (the tunnel, enabled only during a session).
- OpenSSH is Win32-OpenSSH in `C:\Program Files\OpenSSH`, installed by `Setup` with its config written
  first; NinjaOne's WinGet patching is meant to keep it updated afterwards. Sessions log in as
  `support`, a local administrator that is disabled outside sessions.

## Limitations

- One session per POS at a time, shared by every operator on it. `status` names who opened it, not who
  joined.
- A dropped tunnel takes up to about 2 minutes to come back. The POSes restart nightly at 3 AM: a
  session survives, but its tunnel is down for a few minutes.
- `connect`, `keepalive` and `close` each take as long as NinjaOne takes to dispatch a script, usually
  tens of seconds.
- NinjaOne shows a POS's new keys about a minute after a rekey or a first install; a `connect` from
  another workstation in that minute fails and works when run again.
- `relay point` ends every open session.
- The `support` session has no network credentials (no network shares).
- Commands run in a session aren't recorded.
- If the relay's daemon stalls, the relay freezes and drops every tunnel until the container is
  restarted. It can't start while its central log server is unreachable.
- A session's alias exists only on the workstations that ran `connect` for it.

## Troubleshooting

| Message | What to do |
| --- | --- |
| `... has a passphrase and ssh-agent doesn't hold it` | Run the PowerShell commands it prints, once. |
| `the relay is starting ...` | The relay's daemon is coming up; POSes retry within 2 minutes. Run the command again in a few minutes. |
| `... opened the session, but its tunnel didn't reach the relay` | The POS couldn't dial the relay: check the POS is online, and the relay's port and DNS. |
| `... didn't report on the session within 3m` | NinjaOne didn't run the script in time (the POS may be asleep or offline). Try again. |
| `The relay lease for ... may still be open` | Run `posctl connect` again (it replaces the lease) or `posctl close`. |
| `... has no open session` | Nothing to renew: `posctl connect` opens one. |
| `... its POS package is too old to share one` | The POS predates joining: once the session ends, `posctl update` it. |
| `the install on ... was deferred` | A session is open, or a restart is pending: the next run installs. |
| `... NinjaOne didn't show them within 3m` | The POS has its new keys; wait a minute before `connect`. Don't rekey again. |
| `... its report came without the lines for ...` | NinjaOne cut the POS's report short; wait a minute before `connect`. |
| `not signed in to NinjaOne` or `... run posctl login` | `posctl login`. |

## Development

A devkit project managed by `uv`; the CLI is a Rust workspace (`cli/`), packaged as a maturin binary
wheel.

- **Checks:** `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`;
  `uv run ruff check` and `uv run pyright` for the Python.
- **Docker tests** (`tests/cli`): the real relay image, a stand-in POS and a fake NinjaOne, two
  operators. Need Docker: `$env:POS_TUNNEL_DOCKER = "1"; uv run pytest tests/cli --no-cov`.
- **POS tests** (`tests/pos`, Pester): they reconfigure the machine, so they run only in CI, as SYSTEM
  on `windows-latest`.
- **CI** (`.github/workflows/ci.yml`) runs all of the above, and checks the POS package manifest
  matches the files and is signed.
- **Signing the POS package:** after changing anything in `pos/package/`, run
  `$env:POS_TUNNEL_SIGNING_KEY = "$env:USERPROFILE\.ssh\pos-tunnel-release"; uv run poe sign-pos` and
  commit `pos/manifest.json` and its `.sig`. The package version rises only when its files change, so
  a CLI-only release doesn't touch the fleet. CI never holds the signing key.
- **Releasing:** `poe release` from `main`. CI builds the wheels and attaches the signed POS package
  (`pos-package.zip`, `pos-manifest.json`, `.sig`) to the release, which POSes install from at their
  next daily run or `posctl update`.
- **The relay** is developed and deployed from its own repository (`relay/`), by Coolify.

# pos-tunnel

On-demand SSH access to Windows POS machines managed by NinjaOne RMM. NinjaOne's API tells a POS to
dial out to a hardened SSH relay; the operator (or a coding agent on the operator's workstation)
connects through the relay. Sessions have a 12-hour idle timeout, renewable up to a 72-hour maximum,
and leave nothing enabled on the POS when they end.

**Status:** the relay, the POS package, `posctl-admin` and `posctl` are implemented. Two operators
sharing a session needs POS package version 4 on the POS.

- [`docs/design.md`](docs/design.md): the design (threat model, keys, timers, flows).
- [`cli/`](cli/): `posctl`, the Rust CLI run on the operator workstation.
- [`pos/`](pos/): PowerShell, run on the POS as SYSTEM. `ninja/` holds the two scripts pasted into
  the NinjaOne library once; `package/` is the signed release asset they install and run.
- [`relay/`](relay/): the relay container, a submodule (`AetherBreaker/pos-tunnel-relay`): `sshd`
  plus a Python daemon that owns leases and enforcement, deployed by Coolify from that repo.

## Development

A devkit project: `posctl` is packaged as a maturin binary wheel (`uv tool install pos-tunnel` from the
private index), released with `poe release`. After changing anything in `pos/package/`, run
`poe sign-pos` (needs `POS_TUNNEL_SIGNING_KEY`) and commit the re-signed `pos/manifest.json`; CI
rejects an unsigned or stale manifest.

## Usage

```powershell
posctl login
posctl connect "Store 42 Register 1"      # exact, case-sensitive NinjaOne display name
ssh pos-store-42-register-1 "Get-Service"
posctl status
posctl keepalive "Store 42 Register 1"
posctl close "Store 42 Register 1"
```

`connect` usually takes under half a minute and can take six (a slow POS, a first login); a coding
agent should give it that long rather than cut it off. If it is cut off, the next `connect` ends
what was left and starts again.

`connect` on a POS another operator is already on joins their session, and `close` ends it for
everyone on it. `rebuild`, `update` and `rekey` are in `posctl --help`. An operator key with a
passphrase has to be in `ssh-agent` (`ssh-add`); `posctl` says so when it isn't.

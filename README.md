# pos-tunnel

On-demand SSH access to Windows POS machines managed by NinjaOne RMM. NinjaOne's API tells a POS to
dial out to a hardened SSH relay; the operator (or a coding agent on the operator's workstation)
connects through the relay. Sessions have a 12-hour idle timeout, renewable up to a 72-hour maximum,
and leave nothing enabled on the POS when they end.

**Status:** the relay and the POS package are implemented; `posctl` is not (everything below `cli/` is
scaffolding).

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

## Usage (planned)

```powershell
posctl login
posctl connect "Store 42 Register 1"      # exact, case-sensitive NinjaOne display name
ssh pos-store-42-register-1 "Get-Service"
posctl keepalive "Store 42 Register 1"
posctl close "Store 42 Register 1"
```

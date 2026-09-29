# pos-tunnel

On-demand SSH access to Windows POS machines managed by NinjaOne RMM. NinjaOne's API tells a POS to
dial out to a hardened SSH relay; the operator (or a coding agent on the operator's workstation)
connects through the relay. Sessions have a 12-hour idle timeout, renewable up to a 72-hour maximum,
and leave nothing enabled on the POS when they end.

**Status:** design complete, implementation not started. Everything below `cli/`, `pos/` and `relay/`
is scaffolding.

- [`docs/design.md`](docs/design.md): the design (threat model, keys, timers, flows).
- [`cli/`](cli/): `posctl`, the Rust CLI run on the operator workstation.
- [`pos/`](pos/): PowerShell, run on the POS as SYSTEM. `ninja/` holds the two scripts pasted into
  the NinjaOne library once; `package/` is the signed release asset they install and run.
- [`relay/`](relay/): the relay container (Alpine `sshd`, `tunnelctl`, reaper), deployed with Docker
  Compose (Coolify: base directory `/relay`, set `OPERATOR_PUBKEY`).

## Usage (planned)

```powershell
posctl login
posctl connect "Store 42 Register 1"      # exact, case-sensitive NinjaOne display name
ssh pos-store-42-register-1 "Get-Service"
posctl keepalive "Store 42 Register 1"
posctl close "Store 42 Register 1"
```

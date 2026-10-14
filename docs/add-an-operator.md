# Setting up another operator

An operator runs `posctl` on their own Windows PC to open SSH sessions to the POSes. Setting one up
takes three things: an operator key pair you (the admin) make for them, that key on the relay, and
their own NinjaOne sign-in.

## Before you start

- **Their PC:** Windows 10 or 11 with Windows' OpenSSH client, built in on Windows 11. This prints
  `True` when it's there:

  ```powershell
  Test-Path "$env:SystemRoot\System32\OpenSSH\ssh.exe"
  ```

  If it prints `False`: in Settings, search for **Optional features** and add **OpenSSH Client**.
- **Their NinjaOne account:** a NinjaOne user of their own that can see the POS organization's devices
  and run scripts on them. posctl runs its scripts on the POSes as that user.
- **Their operator name:** letters, digits, `.`, `_` and `-` only, for example `jane.doe`. The relay
  logs it, and `posctl status` shows it under OPENED BY.

## 1. Make their key and bundle (you, on your PC)

```powershell
$name = "jane.doe"
posctl-admin operator add $name
```

It prints two lines:

- **The bundle**, one long line holding their private key and this setup's configuration (NinjaOne URL
  and client ID, the organization, the relay and its public key). It is shown once. Send it like a
  password, through a password manager, never by email or chat.
- **An `OPERATOR_KEYS=` line** listing every operator's public key, theirs included.

If the bundle gets lost before it reaches them, run `posctl-admin operator remove $name` and then
`posctl-admin operator add $name` again, and use the `OPERATOR_KEYS=` line the second command prints.

## 2. Put their key on the relay (you, in Coolify)

1. Open the relay's application in Coolify, then its environment variables.
2. Set `OPERATOR_KEYS` to everything after `OPERATOR_KEYS=` in the printed line.
3. Redeploy. Open sessions survive it; their tunnels drop and come back within about 2 minutes.

Until the redeploy, the relay refuses their key and their `posctl connect` fails.
`posctl-admin operator list` prints the current line again at any time.

## 3. Set up their PC (them)

This section can be sent to them as it is.

1. **Install uv**, unless `uv --version` already works, then open a new PowerShell window:

   ```powershell
   powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
   ```

2. **Install posctl:**

   ```powershell
   uv tool install pos-tunnel --index https://pypi.sweetfiretobacco.com/jacob.ogden/internal/+simple
   ```

   If uv warns that its bin folder isn't on `PATH`, run `uv tool update-shell` and open a new window.
   `posctl --version` then works. `uv tool upgrade pos-tunnel` installs newer releases later.

3. **Import the bundle** the admin sent:

   ```powershell
   posctl operator import
   ```

   Paste the bundle at the prompt (the input stays hidden) and press Enter. It stores the key and the
   configuration in `%APPDATA%\posctl`.

4. **Sign in to NinjaOne** with your own NinjaOne account, in the browser that opens:

   ```powershell
   posctl login
   ```

   The sign-in is kept in Windows Credential Manager.

5. **Tab completion** (posctl releases after 1.0.0), then open a new window:

   ```powershell
   posctl completions install
   ```

## 4. Check it works (them)

```powershell
posctl connect "POS 000 Test"
ssh pos-000-test hostname
posctl close "POS 000 Test"
```

`connect` usually takes under half a minute and prints the `ssh` alias to use; `ssh` should print the
POS's computer name. `posctl --help` lists the other commands.

## If something goes wrong

| Message | What to do |
| --- | --- |
| `no posctl config at ...` | Step 3.3 wasn't done, or was done as another Windows user. |
| `not an operator bundle ...` | The bundle was cut short or changed on the way: ask the admin for a new one. |
| `not signed in to NinjaOne` | `posctl login`. |
| `couldn't reach the relay` with `Permission denied (publickey)` | The relay doesn't have their key yet: check step 2 was redeployed. |

## Taking someone off later

```powershell
$name = "jane.doe"
posctl-admin operator remove $name
```

Put the `OPERATOR_KEYS=` line it prints on the relay and redeploy, as in step 2. From then on the
relay refuses their key. Their NinjaOne account is separate: disable it in NinjaOne if they should no
longer run scripts there either.

# Changing the NinjaOne credentials

posctl uses two NinjaOne credentials:

- **The client app:** the tenant's Native API client app, known by its client ID. Every workstation's
  `%APPDATA%\posctl\config.toml` holds that ID, from `posctl-admin init` or from the bundle the
  operator imported. The app has no secret.
- **Each person's sign-in:** `posctl login` signs in through that app as a NinjaOne user and keeps the
  refresh token in Windows Credential Manager. posctl and posctl-admin run as that user.

## Sign in as a different NinjaOne user

On the workstation, run this and sign in as the other user in the browser that opens. It replaces the
stored sign-in.

```powershell
posctl login
```

## Switch to a new client app

Do the steps in this order: the old app keeps working until step 5, so nobody is locked out on the way.

### 1. Create the new app (NinjaOne)

In NinjaOne: Administration → Apps → API → Client App IDs → Add, with:

- Application platform: **Native**
- Redirect URI: `http://127.0.0.1`
- Scopes: **Monitoring**, **Management**, **Offline Access**
- Allowed grant types: **Authorization Code**, **Refresh Token**

Save it and copy its client ID.

### 2. Your workstation (the admin's)

Fill in the three values, then run it:

```powershell
$clientId = "paste the new client ID here"
$organization = "the organization's exact name in NinjaOne"
$policy = "the POS policy's exact name in NinjaOne"
posctl-admin init --base-url https://us2.ninjarmm.com --client-id $clientId --organization $organization --policy $policy --operator-key "$env:USERPROFILE\.ssh\pos-tunnel-operator" --name Jacob
```

It signs in through the new app in the browser, finds the organization, the POS policy and the two
library scripts by name again, and rewrites the config. It keeps the relay this workstation pins and
changes nothing in NinjaOne. Bundles you make from then on (`posctl-admin operator add`) carry the new
client ID.

### 3. Every other operator's workstation

posctl has no command that changes the client ID alone, so each operator edits it in their config,
then signs in again:

```powershell
$clientId = "paste the new client ID here"
$config = "$env:APPDATA\posctl\config.toml"
$lines = (Get-Content -Encoding UTF8 $config) -replace '^client_id = .*$', "client_id = `"$clientId`""
[IO.File]::WriteAllLines($config, $lines)
posctl login
```

The other way is a new bundle: `posctl-admin operator remove` and `operator add` for them, then the
relay update and their import, as in [Setting up another operator](add-an-operator.md).

### 4. Check each workstation

```powershell
posctl status
```

It signs in through the new app and lists the open sessions, or prints `No open sessions.`

### 5. Delete the old app (NinjaOne)

Once every workstation has done step 2 or 3, delete the old app in NinjaOne. A workstation still on the
old client ID then fails to sign in, until it does step 3.

//! Ad hoc sessions, for a Windows machine NinjaOne doesn't manage: `posctl serve` there runs a one-shot
//! `sshd` in its console, dials the relay and prints a line; `posctl connect <line>` on a workstation
//! opens the relay lease (`--adhoc`: the relay ends it once its tunnel drops) and writes the alias.

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssh_key::rand_core::{OsRng, RngCore};
use ssh_key::{Algorithm, PrivateKey};

use crate::config::{self, parse_host_port, write_private};
use crate::keys;
use crate::relay::{self, Lease, Relay};
use crate::session::Timing;
use crate::workstation::{self, Session, Workstation};

/// Ad hoc tunnel ports, 65000–65535: above any NinjaOne device's (20000 + its ID; the fleet's IDs top
/// out near 128). The lease's device ID is the port − 20000, as the relay requires.
pub const FIRST_PORT: u16 = 65000;
const PREFIX: &str = "posctl-adhoc:";
/// The MSI `pos/package/Setup.ps1` pins.
const MSI_URL: &str = "https://github.com/PowerShell/Win32-OpenSSH/releases/download/10.0.0.0p2-Preview/OpenSSH-Win64-v10.0.0.0.msi";
const MSI_SHA256: &str = "DDEC9C53864280759CF9F74791CEFD387100E3946AA849A1C138A4ED1B96B7D9";
const RETRY: Duration = Duration::from_secs(5);
const TICK: Duration = Duration::from_millis(200);

/// Set by Ctrl+C; `serve`'s loop stops its children and deletes its files.
static STOP: AtomicBool = AtomicBool::new(false);

/// What `serve` prints and `connect` takes. It comes from the device, so `decode` checks every field;
/// it holds the session private key, so it is a secret.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Line {
    pub v: u32,
    /// The device's hostname: the session's name.
    pub host: String,
    /// The account `serve` runs as: a `sshd` not running as SYSTEM logs in only its own account.
    pub user: String,
    pub port: u16,
    /// The relay public key the device pinned.
    pub relay: String,
    /// The device's relay public key, which the lease lets forward `port`.
    pub relay_key: String,
    pub server_key: String,
    /// OpenSSH private key text.
    pub session_key: String,
}

impl Line {
    pub fn is_line(text: &str) -> bool {
        text.trim().starts_with(PREFIX)
    }

    pub fn encode(&self) -> Result<String> {
        let json = serde_json::to_vec(self)?;
        Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(json)))
    }

    pub fn decode(text: &str) -> Result<Line> {
        let body = text
            .trim()
            .strip_prefix(PREFIX)
            .context("not a `posctl serve` line")?;
        let line: Line = URL_SAFE_NO_PAD
            .decode(body)
            .ok()
            .and_then(|json| serde_json::from_slice(&json).ok())
            .context("the line is cut short or altered: copy it again")?;
        if line.v != 1 {
            bail!("the line comes from another posctl version: use the same one on both machines");
        }
        // Both go into the generated ssh config: the host as the alias and session name, the user
        // quoted.
        if line.host.is_empty()
            || line.host.len() > 63
            || !line
                .host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
        {
            bail!("the line's hostname '{}' isn't a hostname", line.host);
        }
        // No `"` or `\`: inside the quoted `User` value ssh reads them as escapes, and a trailing `\`
        // would leave the quote open and break the whole generated config. `USERNAME` holds neither.
        if line.user.is_empty()
            || line.user.len() > 104
            || line
                .user
                .chars()
                .any(|c| c.is_control() || c == '"' || c == '\\')
        {
            bail!("the line's user name isn't usable");
        }
        if line.port < FIRST_PORT {
            bail!(
                "the line's port {} is outside {FIRST_PORT}..65535",
                line.port
            );
        }
        for key in [&line.relay, &line.relay_key, &line.server_key] {
            if keys::parse_public(key).ok().as_ref() != Some(key) {
                bail!("the line holds a public key that isn't ssh-ed25519");
            }
        }
        let session = PrivateKey::from_openssh(&line.session_key)
            .context("the line's session key isn't an OpenSSH private key")?;
        if session.algorithm() != Algorithm::Ed25519 || session.is_encrypted() {
            bail!("the line's session key isn't a plain ed25519 key");
        }
        Ok(line)
    }
}

/// The relay `serve` dials unless told another: `cli/relay.pub`.
pub fn built_in_relay() -> Result<config::Relay> {
    parse_relay(include_str!("../relay.pub"))
}

/// `<host>[:<port>] ssh-ed25519 <base64>`.
pub fn parse_relay(text: &str) -> Result<config::Relay> {
    let (address, key) = text
        .trim()
        .split_once(' ')
        .context("expected <host>[:<port>] <public key>")?;
    let (host, port) = parse_host_port(address)?;
    Ok(config::Relay {
        host,
        port,
        public_key: keys::parse_public(key)?,
    })
}

/// Ad hoc sessions' device IDs: their ports' − 20000.
pub fn is_adhoc(device_id: i64) -> bool {
    device_id >= i64::from(FIRST_PORT - 20000)
}

// ---- The device: `posctl serve` ----

pub fn serve(relay: &config::Relay) -> Result<()> {
    let groups = Command::new("whoami")
        .arg("/groups")
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
        .unwrap_or_default();
    // The System and High (elevated) integrity levels' SIDs: only in such a token's groups.
    let system = groups.contains("S-1-16-16384");
    if cfg!(windows) && !system && !groups.contains("S-1-16-12288") {
        bail!("posctl serve needs an elevated console: open one with Run as administrator");
    }
    let user = if system {
        let admin = first_admin()?;
        println!("Running as SYSTEM: the session logs in as {admin}.");
        admin
    } else {
        std::env::var("USERNAME")
            .or_else(|_| std::env::var("USER"))
            .context("no USERNAME")?
    };
    let sshd = find_sshd()?;
    let base = dirs::data_local_dir()
        .context("this account has no local app data folder")?
        .join("posctl");
    fs::create_dir_all(&base).with_context(|| format!("creating {}", base.display()))?;
    // One `serve` per account at a time: a second would delete the first one's keys below. Held
    // until exit; the OS releases it if the process dies.
    let lock = fs::File::create(base.join("serve.lock"))?;
    if lock.try_lock().is_err() {
        bail!("posctl serve is already running for this account, in another console");
    }
    let dir = base.join("serve");
    // Leftovers of a run the watcher didn't clean up after: the sshd service still pointed at its
    // config, and the keys of a session that has ended.
    if system && powershell(RESTORE_SERVICE)?.trim() == "busy" {
        bail!(
            "the sshd service is running on this machine, and posctl serve as SYSTEM needs it: stop it (Stop-Service sshd), or run posctl serve from an elevated console on the desktop"
        );
    }
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    // Held, never written, until this process ends: see `watch`.
    let _watcher = {
        let mut watcher = Command::new(std::env::current_exe()?);
        watcher
            .arg("serve-watch")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP: off this console, so closing it (which ends
        // every process attached to it) doesn't end the watcher.
        #[cfg(windows)]
        std::os::windows::process::CommandExt::creation_flags(&mut watcher, 0x8 | 0x200);
        watcher.spawn().ok()
    };
    ctrlc::set_handler(|| STOP.store(true, Ordering::SeqCst))?;
    let result = run(relay, &sshd, &dir, user, system);
    if system {
        let _ = powershell(RESTORE_SERVICE);
    }
    let _ = fs::remove_dir_all(&dir);
    result
}

/// Puts the `sshd` service back if a SYSTEM `serve` pointed it at its config: stopped, `ImagePath`
/// the bare sshd.exe again. Prints `busy` if the service is running for something else.
const RESTORE_SERVICE: &str = r#"
$k = 'HKLM:\SYSTEM\CurrentControlSet\Services\sshd'
$i = (Get-ItemProperty -LiteralPath $k -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
if ($i -like '*\posctl\serve\*') {
    Stop-Service sshd -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -LiteralPath $k -Name ImagePath -Value ($i -replace '^("[^"]+").*', '$1')
} elseif ((Get-Service sshd -ErrorAction SilentlyContinue).Status -eq 'Running') { 'busy' }
"#;

/// `posctl serve-watch`, which `serve` starts detached with a pipe on its stdin. The pipe reaches EOF
/// once `serve` has ended, however it did: closing a RustDesk terminal ends `serve` with no chance
/// to clean up, and as SYSTEM it leaves the sshd service running. Does what `serve`'s own exit does,
/// unless another `serve` has started since (it holds the lock).
pub fn watch() -> Result<()> {
    let _ = std::io::copy(&mut std::io::stdin(), &mut std::io::sink());
    let base = dirs::data_local_dir()
        .context("this account has no local app data folder")?
        .join("posctl");
    let lock = fs::File::create(base.join("serve.lock"))?;
    if lock.try_lock().is_err() {
        return Ok(());
    }
    let _ = powershell(RESTORE_SERVICE);
    let _ = fs::remove_dir_all(base.join("serve"));
    Ok(())
}

/// A Windows PowerShell script's standard output, or its error. `-EncodedCommand` (UTF-16LE base64),
/// so no quoting has to survive.
fn powershell(script: &str) -> Result<String> {
    let script = format!("[Console]::OutputEncoding = [Text.Encoding]::UTF8\n{script}");
    let encoded: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-EncodedCommand"])
        .arg(STANDARD.encode(encoded))
        .output()
        .context("running PowerShell")?;
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The SSH server `run` started: its own child, or as SYSTEM the `sshd` service. A SYSTEM console
/// (a RustDesk terminal) can't start sshd's per-connection processes: they run as `NT SERVICE\sshd`
/// and can't open that console's desktop (exit 0xC0000142). The service's desktop they can.
enum Server {
    Child(Child),
    Service {
        log: PathBuf,
        shown: usize,
        checked: Instant,
    },
}

impl Server {
    /// Why sshd has stopped, if it has. The service's log is echoed here first: as a service, its
    /// output reaches no console.
    fn stopped(&mut self) -> Result<Option<String>> {
        match self {
            Server::Child(child) => Ok(child
                .try_wait()?
                .map(|status| format!("sshd exited ({status})"))),
            Server::Service {
                log,
                shown,
                checked,
            } => {
                if let Ok(text) = fs::read(&*log)
                    && text.len() > *shown
                {
                    print!("{}", String::from_utf8_lossy(&text[*shown..]));
                    *shown = text.len();
                }
                if checked.elapsed() < Duration::from_secs(5) {
                    return Ok(None);
                }
                *checked = Instant::now();
                let out = Command::new("sc.exe").args(["query", "sshd"]).output()?;
                Ok((!String::from_utf8_lossy(&out.stdout).contains("RUNNING"))
                    .then(|| "the sshd service stopped".to_owned()))
            }
        }
    }
}

fn find_sshd() -> Result<PathBuf> {
    let found = || {
        [
            ("ProgramFiles", r"OpenSSH\sshd.exe"),
            ("SystemRoot", r"System32\OpenSSH\sshd.exe"),
        ]
        .iter()
        .filter_map(|(root, rest)| {
            std::env::var_os(root).map(|root| PathBuf::from(root).join(rest))
        })
        .find(|path| path.exists())
    };
    if let Some(sshd) = found() {
        return Ok(sshd);
    }
    if !cfg!(windows) {
        bail!("no sshd.exe found");
    }
    install_openssh()?;
    found().context("the OpenSSH MSI installed, but sshd.exe isn't in C:\\Program Files\\OpenSSH")
}

fn install_openssh() -> Result<()> {
    eprintln!("OpenSSH isn't installed: installing Win32-OpenSSH (a minute or so)...");
    let ssh_dir =
        PathBuf::from(std::env::var_os("ProgramData").context("no ProgramData")?).join("ssh");
    // The MSI starts its sshd service at once, from this file if there is one, else from its default:
    // every interface, passwords.
    if !ssh_dir.join("sshd_config").exists() {
        fs::create_dir_all(&ssh_dir)?;
        fs::write(
            ssh_dir.join("sshd_config"),
            "ListenAddress 127.0.0.1\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n",
        )?;
        // As Setup.ps1: SYSTEM and Administrators full control, Authenticated Users read.
        let _ = Command::new("icacls")
            .arg(&ssh_dir)
            .args([
                "/inheritance:r",
                "/grant",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
                "*S-1-5-11:(OI)(CI)RX",
                "/T",
                "/Q",
            ])
            .output();
    }
    let mut response = ureq::get(MSI_URL)
        .call()
        .context("downloading the OpenSSH MSI")?;
    let size = response.body().content_length();
    let mut reader = response.body_mut().with_config().limit(64 << 20).reader();
    let mut msi = Vec::new();
    let mut chunk = vec![0; 64 << 10];
    let mut shown = None;
    // One line rewritten in place (`\r`); a terminal that doesn't honour it gets a line per percent.
    let mb = |bytes: usize| bytes as f64 / 1_048_576.0;
    loop {
        let read =
            std::io::Read::read(&mut reader, &mut chunk).context("downloading the OpenSSH MSI")?;
        if read == 0 {
            break;
        }
        msi.extend_from_slice(&chunk[..read]);
        if let Some(size) = size.filter(|&size| size > 0) {
            let percent = msi.len() as u64 * 100 / size;
            if shown != Some(percent) {
                shown = Some(percent);
                eprint!(
                    "\rDownloading OpenSSH: {percent}% ({:.1} of {:.1} MB)",
                    mb(msi.len()),
                    mb(size as usize)
                );
            }
        }
    }
    if shown.is_some() {
        eprintln!();
    }
    let pinned = |bytes: &[u8]| {
        let digest: String = Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect();
        digest == MSI_SHA256
    };
    if !pinned(&msi) {
        bail!("the downloaded OpenSSH MSI doesn't match its pinned SHA256");
    }
    // Run elevated from a folder the account's unelevated processes can write. Reopened read-only
    // with only read sharing (msiexec can't open a file anyone holds for writing, exit 1619), hashed
    // again through that handle, and held until msiexec is done: nothing can swap it after the check.
    let path = std::env::temp_dir().join(format!("posctl-OpenSSH-{}.msi", std::process::id()));
    let _ = fs::remove_file(&path);
    std::io::Write::write_all(
        &mut fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("creating {}", path.display()))?,
        &msi,
    )?;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::share_mode(&mut options, 1); // FILE_SHARE_READ
    let mut held = options
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    let mut written = Vec::new();
    std::io::Read::read_to_end(&mut held, &mut written)?;
    if !pinned(&written) {
        bail!("the OpenSSH MSI changed on disk after its download");
    }
    let mut msiexec = Command::new("msiexec")
        .arg("/i")
        .arg(&path)
        .args(["/qn", "/norestart"])
        .spawn()?;
    // msiexec reports no progress to a console: the time so far, so a slow install doesn't look hung.
    let started = Instant::now();
    let status = loop {
        if let Some(status) = msiexec.try_wait()? {
            break status;
        }
        eprint!("\rInstalling OpenSSH... {}s", started.elapsed().as_secs());
        std::thread::sleep(Duration::from_secs(1));
    };
    eprintln!(
        "\rInstalling OpenSSH... done in {}s",
        started.elapsed().as_secs()
    );
    drop(held);
    let _ = fs::remove_file(&path);
    if !matches!(status.code(), Some(0 | 3010)) {
        bail!("installing OpenSSH failed: msiexec exited {status}");
    }
    // Manual, as on the POSes: started only by a SYSTEM `serve`, for its session (`Server`).
    let _ = Command::new("sc.exe")
        .args(["config", "sshd", "start=", "demand"])
        .output();
    let _ = Command::new("sc.exe").args(["stop", "sshd"]).output();
    Ok(())
}

/// The account a SYSTEM `serve` logs in as. SYSTEM itself can't log in over SSH, but an sshd running
/// as SYSTEM logs in any local account, as its service does: the enabled local administrator with
/// the lowest RID, the built-in one (RID 500) aside.
fn first_admin() -> Result<String> {
    let name = powershell(
        "$g = Get-CimInstance Win32_Group -Filter \"LocalAccount=True AND SID='S-1-5-32-544'\"
        Get-CimAssociatedInstance -InputObject $g -ResultClassName Win32_UserAccount |
            Where-Object { $_.LocalAccount -and -not $_.Disabled -and $_.SID -notlike '*-500' } |
            Sort-Object { [long]($_.SID -split '-')[-1] } | Select-Object -First 1 -ExpandProperty Name",
    )
    .context("finding a local administrator account")?
    .trim()
    .to_owned();
    if name.is_empty() {
        bail!(
            "posctl serve is running as SYSTEM, which can't log in over SSH, and no enabled local administrator account besides the built-in one was found to log in as instead"
        );
    }
    Ok(name)
}

fn run(relay: &config::Relay, sshd: &Path, dir: &Path, user: String, system: bool) -> Result<()> {
    let host = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "device".to_owned());
    let relay_key = keys::generate(&format!("posctl serve {host} relay"))?;
    let server_key = keys::generate(&format!("posctl serve {host} server"))?;
    let session_key = keys::generate(&format!("posctl serve {host} session"))?;
    keys::write_private_key(&dir.join("relay_key"), &relay_key, None)?;
    keys::write_private_key(&dir.join("server_key"), &server_key, None)?;
    let session_public = keys::public_line(session_key.public_key())?;
    write_private(
        &dir.join("authorized_keys"),
        format!("{session_public}\n").as_bytes(),
    )?;
    write_private(
        &dir.join("known_hosts"),
        format!("posctl-relay {}\n", relay.public_key).as_bytes(),
    )?;
    let local = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let port = FIRST_PORT + (OsRng.next_u32() % u32::from(u16::MAX - FIRST_PORT + 1)) as u16;
    // Forward-slashed and quoted: a profile path may hold a space.
    let quoted = |name: &str| {
        format!(
            "\"{}\"",
            dir.join(name).to_string_lossy().replace('\\', "/")
        )
    };
    fs::write(
        dir.join("sshd_config"),
        format!(
            "Port {local}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\n\
             PubkeyAuthentication yes\nAuthenticationMethods publickey\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n\
             AllowTcpForwarding no\nAllowAgentForwarding no\nAllowStreamLocalForwarding no\n\
             GatewayPorts no\nPermitTunnel no\nX11Forwarding no\nSubsystem sftp sftp-server.exe\n",
            quoted("server_key"),
            quoted("authorized_keys"),
        ),
    )?;
    let line = Line {
        v: 1,
        host: host.clone(),
        user,
        port,
        relay: relay.public_key.clone(),
        relay_key: keys::public_line(relay_key.public_key())?,
        server_key: keys::public_line(server_key.public_key())?,
        session_key: keys::private_text(&session_key, None)?,
    }
    .encode()?;

    let mut server = if system {
        // The service runs `ImagePath` as its command line: this run's config and log, until
        // RESTORE_SERVICE puts it back.
        let log = dir.join("sshd.log");
        let image = format!(
            "\"{}\" -f \"{}\" -E \"{}\"",
            sshd.display(),
            dir.join("sshd_config").display(),
            log.display()
        );
        powershell(&format!(
            "$ErrorActionPreference = 'Stop'
            Set-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\sshd' -Name ImagePath -Value '{}'
            Set-Service sshd -StartupType Manual
            Start-Service sshd",
            image.replace('\'', "''")
        ))
        .context("starting the sshd service")?;
        println!(
            "sshd runs as the sshd service for this session: a SYSTEM console can't start its per-connection processes."
        );
        Server::Service {
            log,
            shown: 0,
            checked: Instant::now(),
        }
    } else {
        // -D: never detach (upstream sshd does without it). Not -d, which serves one connection only.
        Server::Child(
            Command::new(sshd)
                .arg("-D")
                .arg("-f")
                .arg(dir.join("sshd_config"))
                .arg("-e")
                .stdin(Stdio::null())
                .spawn()
                .with_context(|| format!("starting {}", sshd.display()))?,
        )
    };
    println!(
        "\nOn your workstation, run (the line is a secret: it logs in to {host}):\n\n  posctl connect {line}\n\n\
         Waiting for it; Ctrl+C or closing this window ends the session.\n"
    );
    // The client of the same OpenSSH.
    let ssh = sshd.with_file_name("ssh.exe");
    let result = tunnel(relay, dir, port, local, &mut server, &ssh);
    // The service `serve` stops once this returns (RESTORE_SERVICE).
    if let Server::Child(child) = &mut server {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

/// Dials the relay until it lets this device in (once `connect` has opened the lease), then holds the
/// tunnel. Ends on Ctrl+C, when sshd exits, or when an established tunnel drops: the relay has then
/// ended the lease, so there is nothing to come back to.
fn tunnel(
    relay: &config::Relay,
    dir: &Path,
    port: u16,
    local: u16,
    server: &mut Server,
    ssh: &Path,
) -> Result<()> {
    let known_hosts = dir.join("known_hosts").to_string_lossy().replace('\\', "/");
    let log_path = dir.join("tunnel.log");
    let mut up = false;
    loop {
        // Each attempt's own log: `-v` writes the line that says the relay granted the forward.
        let log = fs::File::create(&log_path)?;
        let mut child = Command::new(ssh)
            .args(["-v", "-N", "-F", "none", "-R"])
            .arg(format!("{port}:127.0.0.1:{local}"))
            .arg("-p")
            .arg(relay.port.to_string())
            .arg("-i")
            .arg(dir.join("relay_key"))
            .args([
                "-o",
                "ConnectTimeout=15",
                "-o",
                "ExitOnForwardFailure=yes",
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ServerAliveCountMax=3",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "HostKeyAlias=posctl-relay",
                "-o",
            ])
            .arg(format!("UserKnownHostsFile=\"{known_hosts}\""))
            .arg(format!("tunnel@{}", relay.host))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .with_context(|| format!("starting {}", ssh.display()))?;
        loop {
            if let Some(why) = server.stopped()? {
                let _ = child.kill();
                // Ctrl+C reaches sshd too, and may end it before the handler has set STOP.
                std::thread::sleep(Duration::from_millis(500));
                if STOP.load(Ordering::SeqCst) {
                    println!("Stopped: the session has ended.");
                    return Ok(());
                }
                bail!("{why}: see its output above");
            }
            if STOP.load(Ordering::SeqCst) {
                let _ = child.kill();
                println!("Stopped: the session has ended.");
                return Ok(());
            }
            if child.try_wait()?.is_some() {
                break;
            }
            // OpenSSH's own `debug1: remote forward success for: listen <port>, ...`.
            if !up
                && fs::read_to_string(&log_path)
                    .is_ok_and(|log| log.contains("remote forward success"))
            {
                up = true;
                println!("The tunnel to the relay is up.");
            }
            std::thread::sleep(TICK);
        }
        if up {
            println!(
                "The tunnel to the relay dropped, so the session has ended. Run `posctl serve` again for a new one."
            );
            return Ok(());
        }
        let retry = Instant::now() + RETRY;
        while Instant::now() < retry {
            if STOP.load(Ordering::SeqCst) {
                println!("Stopped: the session has ended.");
                return Ok(());
            }
            std::thread::sleep(TICK);
        }
    }
}

// ---- The workstation: `connect <line>`, `keepalive` and `close` ----

/// The ad hoc session this workstation holds under `name`, the device's hostname.
pub fn held(workstation: &Workstation, name: &str) -> Result<Option<Session>> {
    Ok(workstation
        .held()?
        .into_iter()
        .find(|session| session.name == name && is_adhoc(session.device_id)))
}

fn port_of(session: &Session) -> u16 {
    // `is_adhoc` and `decode` keep it in 45000..=45535.
    (20000 + session.device_id) as u16
}

/// Opens the lease for the line's device, waits for its tunnel, saves the session and logs in once;
/// the alias and the lease. A failure closes the lease again.
pub fn connect(
    workstation: &Workstation,
    relay: &dyn Relay,
    line: &Line,
    idle: Duration,
    timing: &Timing,
) -> Result<(String, Lease)> {
    let host = &line.host;
    if line.relay != workstation.relay.public_key {
        bail!(
            "{host}'s posctl dials another relay than this workstation's: upgrade posctl there, or give `posctl serve` this relay with --relay"
        );
    }
    // The device names itself: not after a POS, which `close` and `keepalive` would then pick this
    // session over. Checked against the POS names the last device listing cached.
    let poses = crate::completion::names_path()
        .ok()
        .and_then(|path| fs::read_to_string(path).ok())
        .unwrap_or_default();
    if poses
        .lines()
        .any(|entry| entry.split_once('\t').is_some_and(|(_, name)| name == host))
    {
        bail!("{host} has the name of a POS: connect the POS by name, or rename the machine");
    }
    let (port, device_id) = (line.port, i64::from(line.port) - 20000);
    let leases = relay::leases(relay)?;
    let held = workstation.reconcile(&leases)?;
    if leases.iter().any(|lease| lease.port == port) {
        bail!(
            "another session holds port {port}: stop `posctl serve` on {host} and run it again for a new line"
        );
    }
    workstation.ensure_include()?;
    let taken: Vec<&str> = held.iter().map(|session| session.alias.as_str()).collect();
    let alias = workstation::alias(host, device_id, &taken);
    let session_key = PrivateKey::from_openssh(&line.session_key)?;
    let opened: Lease = relay::ask(
        relay,
        &format!(
            "open {port} {device_id} {} {} --adhoc",
            idle.as_secs(),
            line.relay_key
        ),
    )?;

    let built = (|| -> Result<Lease> {
        eprintln!("Waiting for {host}'s tunnel (it dials every 5 s)...");
        let deadline = Instant::now() + timing.open;
        let lease = loop {
            let leases = relay::leases(relay)?;
            match leases
                .into_iter()
                .find(|lease| lease.port == port && lease.started == opened.started)
            {
                Some(lease) if lease.listening => break lease,
                Some(_) => {}
                None => bail!("the relay dropped the lease before {host}'s tunnel came up"),
            }
            if Instant::now() >= deadline {
                bail!(
                    "{host}'s tunnel didn't reach the relay within {}: is `posctl serve` still running there?",
                    humantime::format_duration(timing.open)
                );
            }
            std::thread::sleep(timing.poll);
        };
        workstation.save(
            &Session {
                device_id,
                name: host.clone(),
                alias: alias.clone(),
                host_key: line.server_key.clone(),
                started: lease.started.clone(),
                user: Some(line.user.clone()),
            },
            &session_key,
        )?;
        workstation.write_ssh_files()?;
        relay.login(&alias)?;
        Ok(lease)
    })();
    match built {
        Ok(lease) => Ok((alias, lease)),
        Err(e) => {
            let _ = relay.tunnelctl(&format!("close {port}"));
            let _ = workstation.remove(device_id);
            let _ = workstation.write_ssh_files();
            Err(e)
        }
    }
}

pub fn keepalive(workstation: &Workstation, relay: &dyn Relay, session: &Session) -> Result<Lease> {
    let port = port_of(session);
    let leases = relay::leases(relay)?;
    workstation.reconcile(&leases)?;
    if !leases
        .iter()
        .any(|lease| lease.port == port && lease.started == session.started)
    {
        bail!(
            "{}'s session has ended: run `posctl serve` there again for a new line",
            session.name
        );
    }
    relay::ask(relay, &format!("renew {port}"))
}

/// Closes the lease if the relay still holds it, then drops this workstation's state; whether it did.
pub fn close(workstation: &Workstation, relay: &dyn Relay, session: &Session) -> Result<bool> {
    let port = port_of(session);
    let had = relay::leases(relay)?
        .iter()
        .any(|lease| lease.port == port && lease.started == session.started);
    if had {
        relay.tunnelctl(&format!("close {port}"))?;
    }
    workstation.remove(session.device_id)?;
    workstation.write_ssh_files()?;
    Ok(had)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{FakeRelay, workstation};

    fn line(relay: &str) -> Line {
        let public = |key: &PrivateKey| keys::public_line(key.public_key()).unwrap();
        let session = keys::generate("s").unwrap();
        Line {
            v: 1,
            host: "DESKTOP-AB12".into(),
            user: "John Smith".into(),
            port: 65123,
            relay: relay.into(),
            relay_key: public(&keys::generate("r").unwrap()),
            server_key: public(&keys::generate("h").unwrap()),
            session_key: keys::private_text(&session, None).unwrap(),
        }
    }

    const RELAY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBxRa3sySInLyRMMVSWz76+abOp7xOibpSn1v7vw1k4x";

    #[test]
    fn a_line_round_trips_and_bad_ones_are_refused() {
        let good = line(RELAY);
        assert_eq!(Line::decode(&good.encode().unwrap()).unwrap(), good);
        let refused = |change: fn(&mut Line)| {
            let mut bad = good.clone();
            change(&mut bad);
            Line::decode(&bad.encode().unwrap()).is_err()
        };
        assert!(refused(|l| l.host = "host\nHost *".into()));
        assert!(refused(|l| l.user = "a\"b".into()));
        // A trailing backslash would leave the quoted `User` value open.
        assert!(refused(|l| l.user = "x\\".into()));
        assert!(refused(|l| l.port = 64999));
        assert!(refused(|l| l.relay_key = "ssh-ed25519 AAAA x".into()));
        assert!(refused(|l| l.session_key = "nope".into()));
        assert!(Line::decode("posctl-adhoc:!!!").is_err());
    }

    /// Reads this machine's accounts: run by hand, `cargo test -- --ignored first_admin`.
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn first_admin_finds_a_local_administrator() {
        let name = first_admin().unwrap();
        assert!(!name.is_empty() && !name.contains('\n'), "{name:?}");
        println!("{name}");
    }

    #[test]
    fn the_built_in_relay_parses() {
        let relay = built_in_relay().unwrap();
        assert_eq!(relay.port, 2222);
        assert!(relay.public_key.starts_with("ssh-ed25519 "));
    }

    #[test]
    fn connect_opens_an_adhoc_lease_and_writes_an_alias_with_the_devices_user() {
        let ws = workstation("adhoc");
        let relay = FakeRelay::new("Jacob");
        let line = line(&ws.relay.public_key.clone());
        let timing = Timing {
            poll: Duration::from_millis(1),
            ..Timing::default()
        };

        let (alias, _) = connect(&ws, &relay, &line, Duration::from_secs(600), &timing).unwrap();

        assert_eq!(alias, "pos-desktop-ab12");
        assert_eq!(
            relay.calls()[1],
            format!("open 65123 45123 600 {} --adhoc", line.relay_key)
        );
        let config = fs::read_to_string(ws.config_file()).unwrap();
        assert!(config.contains("User \"John Smith\""), "{config}");
        assert!(config.contains("Port 65123"), "{config}");
        let session = held(&ws, "DESKTOP-AB12").unwrap().unwrap();
        assert!(close(&ws, &relay, &session).unwrap());
        assert!(held(&ws, "DESKTOP-AB12").unwrap().is_none());
    }

    #[test]
    fn connect_refuses_a_line_for_another_relay() {
        let ws = workstation("adhoc-relay");
        let relay = FakeRelay::new("Jacob");
        let error = connect(
            &ws,
            &relay,
            &line(RELAY),
            Duration::from_secs(600),
            &Timing::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("another relay"), "{error}");
        assert!(relay.calls().is_empty());
    }
}

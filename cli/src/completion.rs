//! Tab completion of `posctl` and `posctl-admin` in Windows PowerShell and bash. A shell's
//! registration runs the binary at each Tab with the words before the cursor in its environment;
//! clap_complete's engine finds the candidates, quoted here for where they land. POS names come from
//! a cache that every device listing rewrites.

use std::ffi::OsString;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result};
use clap_complete::engine::{self, CompletionCandidate};

use crate::config::{Config, config_home, write_private};
use crate::fleet;
use crate::ninja::Api;
use crate::relay::{self, Relay, SshRelay};
use crate::workstation::{Session, Workstation};

/// What `posctl completions powershell` prints. The aliases put `posctl` ahead of `posctl-admin.exe`
/// when Tab completes the command itself.
pub const POWERSHELL: &str = r#"# Tab completion for posctl and posctl-admin: each Tab runs the program, which answers it.
Set-Alias -Name posctl -Value posctl.exe -Scope Global
Set-Alias -Name posctl-admin -Value posctl-admin.exe -Scope Global
Register-ArgumentCompleter -Native -CommandName posctl, posctl.exe, posctl-admin, posctl-admin.exe -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    # The words up to the cursor as PowerShell parsed them, unquoted, the last the word at the cursor.
    $words = @(foreach ($element in $commandAst.CommandElements) {
        if ($element.Extent.StartOffset -ge $cursorPosition) { break }
        $typed = $element.Extent.Text
        if ($element -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
            $element.Value
        } else {
            $element.Extent.Text
        }
    })
    if ($wordToComplete -eq '') { $words += '' }
    # Passed in the environment: Windows PowerShell drops an empty argument to a program and splits
    # one holding a double quote.
    $env:POSCTL_COMPLETE = 'powershell'
    $env:POSCTL_COMPLETE_WORDS = $words -join "`n"
    # The program prints UTF-8, which PowerShell would read in the console's code page.
    $encoding = [Console]::OutputEncoding
    [Console]::OutputEncoding = [Text.Encoding]::UTF8
    try {
        $lines = & (($commandAst.GetCommandName() -replace '\.exe$') + '.exe')
    } finally {
        [Console]::OutputEncoding = $encoding
        Remove-Item Env:\POSCTL_COMPLETE, Env:\POSCTL_COMPLETE_WORDS
    }
    # Nothing to offer: the word as typed, or PowerShell offers the folder's files instead.
    if (-not $lines -and $wordToComplete) { $lines = @($typed) }
    foreach ($line in $lines) {
        $value, $help = $line -split "`t", 2
        $tip = if ($help) { $help } else { $value }
        [System.Management.Automation.CompletionResult]::new($value, $value, 'ParameterValue', $tip)
    }
}
"#;

/// What `posctl completions bash` prints. Git Bash would rewrite a line that starts with a path.
pub const BASH: &str = r#"# Tab completion for posctl and posctl-admin: each Tab runs the program, which answers it.
_posctl_complete() {
    mapfile -t COMPREPLY < <(
        POSCTL_COMPLETE=bash POSCTL_COMPLETE_LINE="${COMP_LINE:0:COMP_POINT}" \
            MSYS2_ENV_CONV_EXCL=POSCTL_COMPLETE_LINE command "$1"
    )
}
complete -F _posctl_complete posctl posctl.exe posctl-admin posctl-admin.exe
"#;

/// The line `install` adds to each startup file. It registers what `posctl completions <shell>`
/// prints at that start, so an upgrade's registration applies from the next shell on, and stays
/// silent where no posctl, or one without `completions`, is on `PATH`.
pub const POWERSHELL_LINE: &str = "if (Get-Command posctl.exe -ErrorAction Ignore) { posctl.exe completions powershell 2>$null | Out-String | Where-Object { $_ } | Invoke-Expression }";
pub const BASH_LINE: &str =
    r#"if command -v posctl >/dev/null; then eval "$(posctl completions bash 2>/dev/null)"; fi"#;

/// A cache older than this is refreshed before a Tab offers its names.
const STALE: Duration = Duration::from_secs(24 * 60 * 60);

/// Answers a Tab and exits when a registration ran this binary for one; returns otherwise. First
/// thing in `main`.
pub fn answer(command: impl FnOnce() -> clap::Command) {
    let Some(shell) = std::env::var_os("POSCTL_COMPLETE") else {
        return;
    };
    let input = |var| std::env::var(var).unwrap_or_default();
    let (words, quote) = if shell == "powershell" {
        let words = input("POSCTL_COMPLETE_WORDS");
        (
            words.split('\n').map(str::to_owned).collect(),
            Quote::PowerShell,
        )
    } else {
        bash_words(&input("POSCTL_COMPLETE_LINE"))
    };
    for line in complete(&mut command(), words, quote) {
        println!("{line}");
    }
    std::process::exit(0);
}

/// The organization's POS names, for a name argument's Tab: the cache, refreshed first through
/// NinjaOne when it is missing or a day old.
pub fn pos_names() -> Vec<CompletionCandidate> {
    let Ok(path) = names_path() else {
        return Vec::new();
    };
    let mut names: Vec<String> = cached_poses(&path, &[], refresh)
        .into_iter()
        .map(|(_, name)| name)
        .collect();
    // Two POSes may share a name, which `find_pos` refuses but the list still shows once.
    names.dedup();
    names.into_iter().map(CompletionCandidate::new).collect()
}

/// The names of the POSes with a session open on the relay, for `close` and `keepalive`'s Tab: the
/// relay is asked at each Tab, through the `ssh` config the session commands write.
pub fn open_session_names() -> Vec<CompletionCandidate> {
    let ask = || -> Result<Vec<String>> {
        let workstation = Workstation::new(&Config::load()?)?;
        let relay = SshRelay {
            ssh: workstation.ssh.clone(),
            config: workstation.config_file(),
        };
        let held = workstation.held().unwrap_or_default();
        Ok(open_names(&relay, &names_path()?, &held, refresh))
    };
    ask()
        .unwrap_or_default()
        .into_iter()
        .map(CompletionCandidate::new)
        .collect()
}

/// Rewrites the cache through NinjaOne: the device listing does (`Shared::set_poses`).
fn refresh() -> Result<()> {
    let config = Config::load()?;
    let ninja = &config.ninjaone;
    fleet::pos_devices(&Api::connect(&ninja.base_url, &ninja.client_id)?, ninja).map(drop)
}

pub(crate) fn names_path() -> Result<PathBuf> {
    Ok(config_home()?.join("posctl").join("pos_names"))
}

/// `posctl completions install`: adds the line to Windows PowerShell's profile and to `~/.bashrc`,
/// which Git Bash reads. Says what it did, a line per file.
pub fn install() -> Result<Vec<String>> {
    let home = dirs::home_dir().context("this platform has no home directory")?;
    let mut files = vec![(home.join(".bashrc"), BASH_LINE)];
    #[cfg(windows)]
    files.insert(
        0,
        (
            dirs::document_dir()
                .context("this account has no Documents folder")?
                .join(r"WindowsPowerShell\Microsoft.PowerShell_profile.ps1"),
            POWERSHELL_LINE,
        ),
    );
    files
        .iter()
        .map(|(path, line)| {
            Ok(if add_line(path, line)? {
                format!("Added Tab completion to {}.", path.display())
            } else {
                format!("{} already has Tab completion.", path.display())
            })
        })
        .collect()
}

/// Where a candidate lands, which decides how it is quoted.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Quote {
    /// PowerShell: the candidate replaces the whole word, quotes included.
    PowerShell,
    /// bash, a word begun unquoted.
    Bare,
    /// bash, inside a `'` the word opened: readline keeps it and closes it on a unique match.
    Single,
    /// bash, inside a `"`.
    Double,
}

/// What a Tab prints: a line per candidate for the last of `words`, quoted for where it lands; in
/// PowerShell, a tab and the first line of its help follow.
fn complete(cmd: &mut clap::Command, words: Vec<String>, quote: Quote) -> Vec<String> {
    let index = words.len() - 1;
    let words = words.into_iter().map(OsString::from).collect();
    let current_dir = std::env::current_dir().ok();
    let candidates =
        engine::complete(cmd, words, index, current_dir.as_deref()).unwrap_or_default();
    candidates
        .iter()
        .map(|candidate| {
            let value = quoted(&candidate.get_value().to_string_lossy(), quote);
            match candidate.get_help() {
                Some(help) if quote == Quote::PowerShell => {
                    format!("{value}\t{}", help.to_string().lines().next().unwrap_or(""))
                }
                _ => value,
            }
        })
        .collect()
}

/// `value` quoted to land where `quote` says; as is when it holds nothing a shell would read.
fn quoted(value: &str, quote: Quote) -> String {
    let plain = |c: char| c.is_ascii_alphanumeric() || "-_./:=+".contains(c);
    if value.chars().all(plain) {
        return value.to_owned();
    }
    let mut out = String::new();
    match quote {
        Quote::PowerShell => {
            out.push('\'');
            for c in value.chars() {
                // PowerShell also ends a single-quoted string at a typographic single quote.
                if matches!(c, '\'' | '\u{2018}'..='\u{201B}') {
                    out.push(c);
                }
                out.push(c);
            }
            out.push('\'');
        }
        Quote::Bare => {
            for c in value.chars() {
                if !plain(c) {
                    out.push('\\');
                }
                out.push(c);
            }
        }
        Quote::Single => out = value.replace('\'', r"'\''"),
        Quote::Double => {
            for c in value.chars() {
                if matches!(c, '"' | '$' | '`' | '\\') {
                    out.push('\\');
                }
                out.push(c);
            }
        }
    }
    out
}

/// The words of a bash command line up to the cursor, unquoted as bash would, the last the word at the
/// cursor (empty after a space), and the quote that word is still open in.
fn bash_words(line: &str) -> (Vec<String>, Quote) {
    let mut words = vec![String::new()];
    let mut quote = Quote::Bare;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        let word = words.last_mut().expect("never empty");
        match (quote, c) {
            (Quote::Single, '\'') | (Quote::Double, '"') => quote = Quote::Bare,
            (Quote::Double, '\\') => match chars.next() {
                Some(next @ ('"' | '$' | '`' | '\\')) => word.push(next),
                next => {
                    word.push('\\');
                    word.extend(next);
                }
            },
            (Quote::Single | Quote::Double, c) => word.push(c),
            (_, '\'') => quote = Quote::Single,
            (_, '"') => quote = Quote::Double,
            (_, '\\') => word.extend(chars.next()),
            (_, c) if c.is_whitespace() => {
                if !word.is_empty() {
                    words.push(String::new());
                }
            }
            (_, c) => word.push(c),
        }
    }
    (words, quote)
}

/// Writes the cache: a POS per line, its device ID, a tab and its name.
pub(crate) fn save_poses(path: &Path, poses: &[(i64, &str)]) -> Result<()> {
    let lines: Vec<String> = poses
        .iter()
        .map(|(id, name)| format!("{id}\t{name}"))
        .collect();
    write_private(path, lines.join("\n").as_bytes())
}

/// The cached POSes, after `refresh` rewrote them if the cache is missing, a day old, unreadable (as
/// written before it held device IDs) or lacks a device of `wanted`. A failed refresh (no sign-in, no
/// network) leaves the POSes as they were.
fn cached_poses(
    path: &Path,
    wanted: &[i64],
    refresh: impl FnOnce() -> Result<()>,
) -> Vec<(i64, String)> {
    let read = || -> Option<Vec<(i64, String)>> {
        let text = fs::read_to_string(path).ok()?;
        text.lines()
            .map(|line| {
                let (id, name) = line.split_once('\t')?;
                Some((id.parse().ok()?, name.to_owned()))
            })
            .collect()
    };
    let fresh = fs::metadata(path)
        .and_then(|meta| meta.modified())
        .is_ok_and(|modified| modified.elapsed().is_ok_and(|age| age < STALE));
    match read() {
        Some(poses)
            if fresh
                && wanted
                    .iter()
                    .all(|id| poses.iter().any(|(known, _)| known == id)) =>
        {
            poses
        }
        before => {
            let _ = refresh();
            read().or(before).unwrap_or_default()
        }
    }
}

/// The names of the POSes the relay holds a lease for, whoever opened it; none when it can't be asked.
fn open_names(
    relay: &dyn Relay,
    path: &Path,
    held: &[Session],
    refresh: impl FnOnce() -> Result<()>,
) -> Vec<String> {
    let Ok(leases) = relay::leases(relay) else {
        return Vec::new();
    };
    // Ad hoc sessions are named by this workstation's state alone: NinjaOne never knows them, so they
    // mustn't make the cache look out of date.
    let (adhoc, open): (Vec<i64>, Vec<i64>) = leases
        .iter()
        .map(|lease| lease.device_id)
        .partition(|id| crate::adhoc::is_adhoc(*id));
    let mut names: Vec<String> = if open.is_empty() {
        Vec::new()
    } else {
        cached_poses(path, &open, refresh)
            .into_iter()
            .filter(|(id, _)| open.contains(id))
            .map(|(_, name)| name)
            .collect()
    };
    names.extend(
        held.iter()
            .filter(|session| adhoc.contains(&session.device_id))
            .map(|session| session.name.clone()),
    );
    names
}

/// Appends `line` to `path` on a line of its own, in the file's line endings, unless one of its lines
/// already is `line`. True when it did.
fn add_line(path: &Path, line: &str) -> Result<bool> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(e).with_context(|| {
                format!(
                    "can't read {}: add this line to it yourself:\n{line}",
                    path.display()
                )
            });
        }
    };
    if text.lines().any(|existing| existing.trim() == line) {
        return Ok(false);
    }
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let separator = if text.is_empty() || text.ends_with('\n') {
        ""
    } else {
        newline
    };
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut file| file.write_all(format!("{separator}{line}{newline}").as_bytes()))
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use anyhow::bail;
    use clap::{Arg, Command};
    use clap_complete::engine::ArgValueCandidates;

    use super::*;
    use crate::fake::FakeRelay;

    const NAMES: [&str; 4] = ["Bob's POS", "POS 000 Test", "POS 001", "POS-002"];

    fn cli() -> Command {
        let name = Arg::new("name").add(ArgValueCandidates::new(|| {
            NAMES.into_iter().map(CompletionCandidate::new).collect()
        }));
        let idle = Arg::new("idle-timeout").long("idle-timeout");
        Command::new("posctl")
            .subcommand(
                Command::new("connect")
                    .about("Open a session.\n\nOr join one.")
                    .arg(name)
                    .arg(idle),
            )
            .subcommand(Command::new("close"))
    }

    fn words(words: &[&str]) -> Vec<String> {
        words.iter().map(|&word| word.to_owned()).collect()
    }

    fn bash(line: &str) -> Vec<String> {
        let (words, quote) = bash_words(line);
        complete(&mut cli(), words, quote)
    }

    /// A dir of its own under the temp dir, emptied.
    fn dir(test: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("posctl-completion {test} {}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn powershell_gets_the_names_that_start_with_the_word_single_quoted_where_they_need_it() {
        let ps = |typed: &[&str]| complete(&mut cli(), words(typed), Quote::PowerShell);
        // The flags follow the names.
        assert_eq!(
            ps(&["posctl", "connect", ""]),
            [
                "'Bob''s POS'",
                "'POS 000 Test'",
                "'POS 001'",
                "POS-002",
                "--idle-timeout",
                "--help\tPrint help"
            ]
        );
        assert_eq!(
            ps(&["posctl", "connect", "POS 0"]),
            ["'POS 000 Test'", "'POS 001'"]
        );
        // Names match exactly, case included, as `find_pos` does.
        assert!(ps(&["posctl", "connect", "pos"]).is_empty());
        assert_eq!(
            ps(&["posctl", "connect", "POS 000 Test", "--i"]),
            ["--idle-timeout"]
        );
    }

    #[test]
    fn powershell_gets_each_subcommand_with_the_first_line_of_its_help() {
        assert_eq!(
            complete(&mut cli(), words(&["posctl", "con"]), Quote::PowerShell),
            ["connect\tOpen a session."]
        );
    }

    #[test]
    fn bash_gets_names_quoted_for_the_quote_the_word_is_open_in() {
        assert_eq!(
            bash("posctl connect P"),
            [r"POS\ 000\ Test", r"POS\ 001", "POS-002"]
        );
        assert_eq!(bash("posctl connect B"), [r"Bob\'s\ POS"]);
        // Readline keeps the quote the word opened and closes it on a unique match.
        assert_eq!(bash("posctl connect 'Bob"), [r"Bob'\''s POS"]);
        assert_eq!(bash("posctl connect \"POS 0"), ["POS 000 Test", "POS 001"]);
        assert_eq!(
            bash(r"posctl connect POS\ 0"),
            [r"POS\ 000\ Test", r"POS\ 001"]
        );
        assert_eq!(bash("posctl con"), ["connect"]);
    }

    #[test]
    fn a_bash_line_splits_into_unquoted_words_the_last_one_at_the_cursor() {
        assert_eq!(
            bash_words("posctl  connect "),
            (words(&["posctl", "connect", ""]), Quote::Bare)
        );
        assert_eq!(
            bash_words("posctl connect 'POS 000 Test' --i"),
            (
                words(&["posctl", "connect", "POS 000 Test", "--i"]),
                Quote::Bare
            )
        );
        assert_eq!(
            bash_words("posctl connect 'POS 0"),
            (words(&["posctl", "connect", "POS 0"]), Quote::Single)
        );
        assert_eq!(
            bash_words(r#"posctl connect "a\"b \$c\d"#),
            (words(&["posctl", "connect", r#"a"b $c\d"#]), Quote::Double)
        );
    }

    #[test]
    fn a_value_that_needs_no_quotes_lands_as_is() {
        for quote in [Quote::PowerShell, Quote::Bare, Quote::Single, Quote::Double] {
            for value in ["--idle-timeout", "POS-002", "relay.example.com:2222"] {
                assert_eq!(quoted(value, quote), value);
            }
        }
    }

    #[test]
    fn powershell_doubles_every_quote_that_would_end_a_single_quoted_string() {
        // PowerShell reads the typographic single quotes as quotes too.
        assert_eq!(
            quoted("Bob's \u{2019}POS\u{2018}", Quote::PowerShell),
            "'Bob''s \u{2019}\u{2019}POS\u{2018}\u{2018}'"
        );
        assert_eq!(quoted("$x `y", Quote::PowerShell), "'$x `y'");
    }

    #[test]
    fn bash_escapes_what_the_quote_the_word_is_open_in_would_read() {
        assert_eq!(quoted("a b'$c", Quote::Bare), r"a\ b\'\$c");
        assert_eq!(quoted("a b'$c", Quote::Single), r"a b'\''$c");
        assert_eq!(
            quoted(r#"a b"$c`d\e'"#, Quote::Double),
            r#"a b\"\$c\`d\\e'"#
        );
    }

    fn poses(poses: &[(i64, &str)]) -> Vec<(i64, String)> {
        poses
            .iter()
            .map(|&(id, name)| (id, name.to_owned()))
            .collect()
    }

    fn make_day_old(path: &Path) {
        let day_old = SystemTime::now() - Duration::from_secs(24 * 60 * 60 + 60);
        fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(day_old)
            .unwrap();
    }

    #[test]
    fn a_fresh_cache_is_read_without_asking_ninjaone() {
        let path = dir("fresh").join("pos_names");
        save_poses(&path, &[(1, "POS 000 Test"), (2, "POS 001")]).unwrap();
        let cached = cached_poses(&path, &[], || panic!("refreshed a fresh cache"));
        assert_eq!(cached, poses(&[(1, "POS 000 Test"), (2, "POS 001")]));
    }

    #[test]
    fn a_missing_or_day_old_cache_is_refreshed_first() {
        let path = dir("refreshed").join("pos_names");
        let refresh = || save_poses(&path, &[(3, "POS 002")]);
        assert_eq!(cached_poses(&path, &[], refresh), poses(&[(3, "POS 002")]));
        save_poses(&path, &[(2, "POS 001")]).unwrap();
        make_day_old(&path);
        assert_eq!(cached_poses(&path, &[], refresh), poses(&[(3, "POS 002")]));
    }

    #[test]
    fn a_cache_without_device_ids_is_refreshed_first() {
        let path = dir("names-only").join("pos_names");
        fs::write(&path, "POS 000 Test\nPOS 001").unwrap();
        let refresh = || save_poses(&path, &[(1, "POS 000 Test")]);
        assert_eq!(
            cached_poses(&path, &[], refresh),
            poses(&[(1, "POS 000 Test")])
        );
    }

    #[test]
    fn a_device_the_cache_lacks_has_it_refreshed_first() {
        let path = dir("lacking").join("pos_names");
        save_poses(&path, &[(1, "POS 000 Test")]).unwrap();
        let refresh = || save_poses(&path, &[(1, "POS 000 Test"), (5, "POS 005")]);
        assert_eq!(
            cached_poses(&path, &[5], refresh),
            poses(&[(1, "POS 000 Test"), (5, "POS 005")])
        );
    }

    #[test]
    fn a_failed_refresh_leaves_the_old_names() {
        let path = dir("failed").join("pos_names");
        assert!(cached_poses(&path, &[], || bail!("not signed in")).is_empty());
        save_poses(&path, &[(2, "POS 001")]).unwrap();
        make_day_old(&path);
        assert_eq!(
            cached_poses(&path, &[], || bail!("offline")),
            poses(&[(2, "POS 001")])
        );
    }

    #[test]
    fn close_offers_the_poses_with_a_lease_on_the_relay_whoever_opened_it() {
        let path = dir("open").join("pos_names");
        save_poses(
            &path,
            &[(3, "Bob's POS"), (1, "POS 000 Test"), (2, "POS 001")],
        )
        .unwrap();
        let relay = FakeRelay::new("admin");
        relay.open_as("bob", 1);
        relay.open_as("admin", 3);
        let names = open_names(&relay, &path, &[], || panic!("refreshed a fresh cache"));
        assert_eq!(names, ["Bob's POS", "POS 000 Test"]);
    }

    #[test]
    fn close_asks_ninjaone_nothing_while_the_relay_holds_no_lease() {
        let path = dir("no-lease").join("pos_names");
        let relay = FakeRelay::new("admin");
        assert!(open_names(&relay, &path, &[], || panic!("refreshed for no lease")).is_empty());
    }

    #[test]
    fn close_offers_nothing_when_the_relay_cant_be_asked() {
        let path = dir("unreachable").join("pos_names");
        save_poses(&path, &[(1, "POS 000 Test")]).unwrap();
        let relay = FakeRelay::new("admin");
        relay.open_as("bob", 1);
        relay.unreachable_at.set(Some(1));
        assert!(open_names(&relay, &path, &[], || Ok(())).is_empty());
    }

    #[test]
    fn the_line_is_added_once() {
        let path = dir("add-once")
            .join("WindowsPowerShell")
            .join("profile.ps1");
        assert!(add_line(&path, "the line").unwrap());
        assert!(!add_line(&path, "the line").unwrap());
        assert_eq!(fs::read_to_string(&path).unwrap(), "the line\n");
    }

    #[test]
    fn the_line_follows_what_is_there_on_a_line_of_its_own_in_its_line_endings() {
        let dir = dir("add-after");
        let unix = dir.join(".bashrc");
        fs::write(&unix, "eval x").unwrap();
        assert!(add_line(&unix, "the line").unwrap());
        assert_eq!(fs::read_to_string(&unix).unwrap(), "eval x\nthe line\n");
        let windows = dir.join("profile.ps1");
        fs::write(&windows, "$c = 1\r\n").unwrap();
        assert!(add_line(&windows, "the line").unwrap());
        assert_eq!(
            fs::read_to_string(&windows).unwrap(),
            "$c = 1\r\nthe line\r\n"
        );
    }
}

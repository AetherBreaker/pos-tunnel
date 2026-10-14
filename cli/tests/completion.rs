//! Tab completion as the shells run it: loaded by the line `posctl completions install` writes, in
//! Windows PowerShell 5.1 and Git Bash, against the built binaries and a fresh names cache.
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;

use posctl::completion;

/// A config home whose names cache is fresh, so no Tab asks NinjaOne, and `PATH` with the built
/// binaries first.
fn setup(test: &str) -> (PathBuf, String) {
    let home = std::env::temp_dir().join(format!("posctl-tab {test} {}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(home.join("posctl")).unwrap();
    std::fs::write(
        home.join("posctl").join("pos_names"),
        "5\tBob's POS\n4\tCaf\u{e9} POS\n1\tPOS 000 Test\n2\tPOS 001\n3\tPOS-002",
    )
    .unwrap();
    let bins = Path::new(env!("CARGO_BIN_EXE_posctl")).parent().unwrap();
    let path = format!("{};{}", bins.display(), std::env::var("PATH").unwrap());
    (home, path)
}

/// Runs `script`, saved as `file`, and returns the lines it wrote to the file `$OUT`, read as UTF-8: a
/// redirected stdout would arrive in the console's code page.
fn run(shell: &Path, args: &[&str], file: &str, script: &str) -> Vec<String> {
    let (home, path) = setup(file);
    let file = home.join(file);
    let out = home.join("out.txt");
    std::fs::write(&file, script).unwrap();
    let status = Command::new(shell)
        .args(args)
        .arg(&file)
        .env("PATH", path)
        .env("POSCTL_CONFIG_HOME", &home)
        .env("OUT", &out)
        .status()
        .unwrap();
    assert!(status.success(), "{} exited with {status}", shell.display());
    let text = std::fs::read_to_string(&out).unwrap();
    text.trim_start_matches('\u{feff}')
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn windows_powershell_completes_subcommands_flags_and_quoted_pos_names() {
    let script = r#"
$ErrorActionPreference = 'Stop'
# A console's default code page, in which a name that isn't ASCII arrives intact only if the
# completer reads UTF-8.
[Console]::OutputEncoding = [Text.Encoding]::GetEncoding(437)
LOAD
$lines = @(
    'posctl conn',
    'posctl connect ',
    'posctl connect POS',
    "posctl connect 'POS 0",
    'posctl connect "POS 000',
    "posctl connect 'Bob''s",
    "posctl connect 'POS 000 Test' --i",
    'posctl update C',
    'posctl.exe status POS',
    'posctl-admin relay point --device POS-',
    'posctl close ',
    'posctl keepalive ',
    'posctl close po'
)
foreach ($sub in 'rebuild', 'update', 'rekey') { $lines += "posctl $sub POS" }
# In the config home, which holds a folder `posctl` for PowerShell's own file completion to offer.
Push-Location (Split-Path $env:OUT)
$result = foreach ($line in $lines) {
    $tab = TabExpansion2 -inputScript $line -cursorColumn $line.Length
    "$line => " + ($tab.CompletionMatches.CompletionText -join '|')
}
Pop-Location
$result += 'posc => ' + (TabExpansion2 -inputScript 'posc' -cursorColumn 4).CompletionMatches[0].CompletionText
$result += 'posctl --version => ' + (posctl --version)
$result | Set-Content -Encoding UTF8 $env:OUT
"#
    .replace("LOAD", completion::POWERSHELL_LINE);
    let names = "'POS 000 Test'|'POS 001'|POS-002";
    let mut expected = vec![
        "posctl conn => connect".to_owned(),
        "posctl connect  => 'Bob''s POS'|'Caf\u{e9} POS'|'POS 000 Test'|'POS 001'|POS-002|--idle-timeout|--help".to_owned(),
        format!("posctl connect POS => {names}"),
        "posctl connect 'POS 0 => 'POS 000 Test'|'POS 001'".to_owned(),
        "posctl connect \"POS 000 => 'POS 000 Test'".to_owned(),
        "posctl connect 'Bob''s => 'Bob''s POS'".to_owned(),
        "posctl connect 'POS 000 Test' --i => --idle-timeout".to_owned(),
        "posctl update C => 'Caf\u{e9} POS'".to_owned(),
        format!("posctl.exe status POS => {names}"),
        "posctl-admin relay point --device POS- => POS-002".to_owned(),
        // They offer the POSes with a session on the relay, and this config has no relay to ask.
        "posctl close  => --help".to_owned(),
        "posctl keepalive  => --help".to_owned(),
        // Nothing to offer: the word stays as typed, where PowerShell would offer the folder's files.
        "posctl close po => po".to_owned(),
    ];
    for sub in ["rebuild", "update", "rekey"] {
        expected.push(format!("posctl {sub} POS => {names}"));
    }
    expected.push("posc => posctl".to_owned());
    expected.push(format!(
        "posctl --version => posctl {}",
        env!("CARGO_PKG_VERSION")
    ));
    let windows_powershell = PathBuf::from(std::env::var("SystemRoot").unwrap())
        .join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let args = [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
    ];
    assert_eq!(
        run(&windows_powershell, &args, "tab.ps1", &script),
        expected
    );
}

#[test]
fn git_bash_completes_pos_names_quoted_for_the_quote_the_word_is_open_in() {
    let script = r#"
LOAD
tab() {
    COMP_LINE=$1 COMP_POINT=${#1} COMPREPLY=()
    _posctl_complete "${1%% *}"
    local IFS='|'
    echo "$1 => ${COMPREPLY[*]}" >> "$OUT"
}
tab 'posctl con'
tab 'posctl connect P'
tab 'posctl connect B'
tab "posctl connect 'Bob"
tab 'posctl connect "POS 0'
tab 'posctl.exe status POS\ 0'
tab 'posctl-admin relay point --device POS-'
"#
    .replace("LOAD", completion::BASH_LINE);
    let expected = [
        "posctl con => connect",
        r"posctl connect P => POS\ 000\ Test|POS\ 001|POS-002",
        r"posctl connect B => Bob\'s\ POS",
        r"posctl connect 'Bob => Bob'\''s POS",
        r#"posctl connect "POS 0 => POS 000 Test|POS 001"#,
        r"posctl.exe status POS\ 0 => POS\ 000\ Test|POS\ 001",
        "posctl-admin relay point --device POS- => POS-002",
    ];
    let git_bash = PathBuf::from(std::env::var("ProgramFiles").unwrap()).join(r"Git\bin\bash.exe");
    assert!(git_bash.exists(), "no Git Bash at {}", git_bash.display());
    assert_eq!(run(&git_bash, &[], "tab.sh", &script), expected);
}

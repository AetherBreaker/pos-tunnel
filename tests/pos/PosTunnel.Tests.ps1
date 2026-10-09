BeforeAll {
    . "$PSScriptRoot\Harness.ps1"
    Initialize-Harness
}

# In file order, each test starting from the state the one before left, as a device's life runs. The
# real PosTunnel-Watch also fires every 2 minutes throughout, so a test of what Watch does checks the
# state it leaves, not which run produced it.
Describe 'Install-PosTunnel' {
    It 'installs from scratch, replacing a folder it does not own without following a junction in it' {
        $null = New-Item -ItemType Directory 'C:\pt-victim' -Force
        Set-Content 'C:\pt-victim\keep.txt' 'keep'
        $null = New-Item -ItemType Directory $Root -Force
        $null = cmd /c mklink /J "$Root\versions" 'C:\pt-victim'
        Publish-TestRelease 1

        $r = Invoke-Install

        $r.ExitCode | Should -Be 0
        $r.Text | Should -Match "CHANGED`tfolder`tnot SYSTEM-only"
        'C:\pt-victim\keep.txt' | Should -Exist
        $acl = Get-Acl $Root
        $acl.AreAccessRulesProtected | Should -BeTrue
        @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value }) |
            Should -Be @('S-1-5-18')
        (Get-Content "$Root\current" -Raw).Trim() | Should -Be '1'
    }

    It 'leaves the device set up and idle' {
        (Get-CimInstance Win32_Service -Filter "Name='sshd'").PathName | Should -BeLike '*Program Files\OpenSSH\sshd.exe*'
        Test-Path "$env:SystemRoot\System32\OpenSSH\sshd.exe" | Should -BeFalse
        $state = Get-IdleState
        $state.SshdStatus | Should -Be 'Stopped'
        $state.SshdStartType | Should -Be 'Manual'
        $state.SupportEnabled | Should -BeFalse
        $state.AuthorizedKeys | Should -Be 0
        $state.LinkState | Should -Be 'Disabled'
        $state.Session | Should -BeFalse
        (Get-LocalGroupMember -SID 'S-1-5-32-544').Name | Should -Contain "$env:COMPUTERNAME\support"
        Get-Content "$env:ProgramData\ssh\sshd_config" | Should -Contain 'ListenAddress 127.0.0.1'
        (Get-ItemProperty 'HKLM:\SOFTWARE\OpenSSH').DefaultShell | Should -BeLike '*\WindowsPowerShell\v1.0\powershell.exe'
        Get-Field posTunnelRelayKey | Should -Match '^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43}$'
        Get-Field posTunnelHostKey | Should -Match '^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43}$'
        Get-Field posTunnelVersion | Should -Be '1'
        (Get-Content "$Root\known_hosts" -Raw).Trim() | Should -Be "[127.0.0.1]:$RelayPort $(Get-Field posTunnelRelayServerKey)"
        $watch = Get-ScheduledTask PosTunnel-Watch
        $watch.Actions[0].Arguments | Should -BeLike "*$Root\versions\1\Watch.ps1*"
        $watch.Triggers[1].Repetition.Interval | Should -Be 'PT2M'
        $watch.Triggers[1].Repetition.Duration | Should -BeNullOrEmpty
        (Get-ScheduledTask PosTunnel-Link).Settings.ExecutionTimeLimit | Should -Be 'PT0S'
    }

    It 'changes nothing on a second run' {
        $r = Invoke-Install

        $r.ExitCode | Should -Be 0
        $r.Text | Should -Not -Match 'CHANGED'
    }
}

Describe 'Install-PosTunnel refusals and upgrades' {
    It 'refuses a release signed by another key, keeping the installed version' {
        Publish-TestRelease 2 -SigningKey "$Work\other_signing_key"

        $r = Invoke-Install

        $r.ExitCode | Should -Be 1
        $r.Text | Should -Match "FAILED`tsignature`tbad signature: .*verif"
        (Get-Content "$Root\current" -Raw).Trim() | Should -Be '1'
        "$Root\versions\2" | Should -Not -Exist
    }

    It 'refuses an archive entry the manifest lacks, writing nothing from the archive' {
        Publish-TestRelease 2 -ExtraEntry

        $r = Invoke-Install

        $r.ExitCode | Should -Be 1
        $r.Text | Should -Match "FAILED`tpackage`tunexpected archive entry 'Extra.ps1'"
        Get-ChildItem $Root -Recurse -Filter 'Extra.ps1' | Should -BeNullOrEmpty
        "$Root\versions\2" | Should -Not -Exist
    }

    It 'refuses an archive file whose hash does not match the manifest' {
        Publish-TestRelease 2 -Tamper 'Open.ps1'

        $r = Invoke-Install

        $r.ExitCode | Should -Be 1
        $r.Text | Should -Match "FAILED`tpackage`tOpen.ps1 does not match the manifest"
        (Get-Content "$Root\current" -Raw).Trim() | Should -Be '1'
    }

    It 'upgrades, keeping the previous version and pointing Watch at the new one' {
        Publish-TestRelease 2

        $r = Invoke-Install

        $r.ExitCode | Should -Be 0
        (Get-Content "$Root\current" -Raw).Trim() | Should -Be '2'
        "$Root\versions\1" | Should -Exist
        (Get-ScheduledTask PosTunnel-Watch).Actions[0].Arguments | Should -BeLike "*$Root\versions\2\Watch.ps1*"
        Get-Field posTunnelVersion | Should -Be '2'

        Publish-TestRelease 3
        (Invoke-Install).ExitCode | Should -Be 0
        "$Root\versions\1" | Should -Not -Exist
        "$Root\versions\2" | Should -Exist
    }

    It 'refuses an older release than the installed one' {
        Publish-TestRelease 2

        $r = Invoke-Install

        $r.ExitCode | Should -Be 1
        $r.Text | Should -Match "FAILED`tpackage`trelease 2 is older than installed 3"
        (Get-Content "$Root\current" -Raw).Trim() | Should -Be '3'
    }

    It 'repairs an installed file that no longer matches the manifest' {
        Add-Content "$Root\versions\3\Touch.ps1" '# drift'
        Publish-TestRelease 3

        $r = Invoke-Install

        $r.ExitCode | Should -Be 0
        $r.Text | Should -Match "CHANGED`tpackage`tversion 3 repaired"
        Get-Content "$Root\versions\3\Touch.ps1" | Should -Not -Contain '# drift'
    }
}

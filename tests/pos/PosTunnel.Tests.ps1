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

#requires -Version 7.2
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'TemporaryFirewall.psm1') -Force -DisableNameChecking
function Assert-Check([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
Assert-Check ((Get-TempSubnet '192.168.42.17' 24) -eq '192.168.42.0/24') 'IPv4 subnet calculation failed.'
Assert-Check ((Get-TempSubnet 'fdfe:dcba:9876::1' 126) -eq 'fdfe:dcba:9876::/126') 'IPv6 subnet calculation failed.'
$program = Join-Path $env:ProgramFiles 'Hiddify\HiddifyCoreEngine.exe'
$planParameters = @{
    Programs = @($program); TunnelAlias = 'tun0'
    TunnelAddresses = @('172.19.0.1','fdfe:dcba:9876::1'); LanNetworks = @('192.168.42.0/24')
    PhysicalAliases = @('Ethernet')
    TransportPeers = @([pscustomobject]@{ Program=$program; RemoteAddress='203.0.113.7'; RemotePort=443 })
}
$plan = @(New-TempRulePlan @planParameters)
$tunnel = @($plan | Where-Object Key -EQ 'tun')
Assert-Check ($tunnel.Count -eq 1 -and $tunnel[0].InterfaceAlias -eq 'tun0') 'Tunnel interface condition missing.'
Assert-Check ($tunnel[0].LocalAddress.Count -eq 2) 'Exact tunnel source addresses missing.'
Assert-Check (@($plan | Where-Object Key -EQ 'transport-0').Count -eq 1) 'VPN transport rule missing.'
$transport = $plan | Where-Object Key -EQ 'transport-0'
Assert-Check ($transport.RemoteAddress -eq '203.0.113.7' -and $transport.RemotePort -eq 443 -and
    $transport.InterfaceAlias[0] -eq 'Ethernet' -and $transport.Protocol -eq 'TCP') 'Unrestricted physical application exception.'
Assert-Check (@($plan | Where-Object { $_.Contains('Service') -and $_.Service -eq 'Dhcp' }).Count -eq 2) 'DHCP service restriction missing.'
Assert-Check (@($plan | ForEach-Object Key | Sort-Object -Unique).Count -eq $plan.Count) 'Duplicate rule keys.'
$rejected = $false
try { $invalid = $planParameters.Clone(); $invalid.TunnelAlias='tun*'; New-TempRulePlan @invalid | Out-Null }
catch { $rejected = $true }
Assert-Check $rejected 'Wildcard tunnel aliases must be rejected.'
$rejected = $false
try { $invalid = $planParameters.Clone(); $invalid.LanNetworks=@('0.0.0.0/0'); New-TempRulePlan @invalid | Out-Null }
catch { $rejected = $true }
Assert-Check $rejected 'Unrestricted LAN must be rejected.'
$rejected = $false
try { $invalid = $planParameters.Clone(); $invalid.TunnelAddresses=@('0.0.0.0'); New-TempRulePlan @invalid | Out-Null }
catch { $rejected = $true }
Assert-Check $rejected 'Unspecified tunnel source must be rejected.'
$rejected = $false
try {
    $invalid = $planParameters.Clone()
    $invalid.TransportPeers = @([pscustomobject]@{ Program=$program; RemoteAddress='203.0.113.7'; RemotePort=53 })
    New-TempRulePlan @invalid | Out-Null
} catch { $rejected = $true }
Assert-Check $rejected 'Direct physical DNS must be rejected.'
$lanRules = @($plan | Where-Object { $_.Key -like 'lan-*' })
Assert-Check ($lanRules.Count -eq 2 -and
    @($lanRules | Where-Object { ($_.RemotePort -join ',') -ne '1-52,54-852,854-65535' }).Count -eq 0) 'LAN DNS exclusions missing.'
$testFolder = Join-Path ([IO.Path]::GetTempPath()) ('HiddifyTempPlan-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testFolder | Out-Null
try {
    $backupPath = Join-Path $testFolder 'not-an-export.wfw'
    $shortcutPath = New-TempRecoveryShortcut -BackupPath $backupPath -DesktopPath $testFolder
    $bytes = [IO.File]::ReadAllBytes($shortcutPath)
    Assert-Check (([BitConverter]::ToUInt32($bytes, 20) -band 0x2000) -ne 0) 'Recovery shortcut elevation flag missing.'
    $shell = New-Object -ComObject WScript.Shell
    try {
        $shortcut = $shell.CreateShortcut($shortcutPath)
        Assert-Check ($shortcut.TargetPath -eq (Join-Path $env:SystemRoot 'System32\netsh.exe')) 'Recovery target mismatch.'
        Assert-Check ($shortcut.Arguments -eq ('advfirewall import "' + $backupPath + '"')) 'Recovery arguments mismatch.'
        [Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut) | Out-Null
    } finally { [Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) | Out-Null }
} finally {
    $testLink = Join-Path $testFolder 'Hiddify Temporary - RESTORE firewall.lnk'
    if (Test-Path -LiteralPath $testLink) { Remove-Item -LiteralPath $testLink }
    [IO.Directory]::Delete($testFolder)
}

# Exercise activation order and failure paths using module-local fakes only.
$module = Get-Module TemporaryFirewall
& $module {
    $script:FakeCalls = [Collections.Generic.List[string]]::new()
    $script:FakeFailure = ''
    $script:FakeRule = [ordered]@{ Key = 'app-0'; Program = 'C:\Test\HiddifyCoreEngine.exe' }
    function script:Read-TempState {
        @{
            Stage = 'Prepared'; HiddifyDirectory = 'C:\Test'; AllowLan = $true
            RecoveryShortcut = 'C:\Fake\restore.lnk'
            Context = @{
                BaselineFingerprint = 'baseline'; Rules = @($script:FakeRule)
            }
        }
    }
    function script:Get-TempContext {
        @{
            Ready = $true; Blockers = @(); BaselineFingerprint = 'baseline'
            Rules = @($script:FakeRule); Baseline = @{ EnabledAllowNames = @('original-allow') }
        }
    }
    function script:Test-Path { $true }
    function script:Save-TempJson { param($Path,$Value); $script:FakeCalls.Add('state-' + $Value.Stage) }
    function script:New-NetFirewallRule {
        $script:FakeCalls.Add('add')
        if ($script:FakeFailure -eq 'add') { throw 'injected add failure' }
    }
    function script:Disable-NetFirewallRule { $script:FakeCalls.Add('disable-old') }
    function script:Get-NetFirewallRule { @() }
    function script:Set-NetFirewallProfile {
        $script:FakeCalls.Add('default-block')
        if ($script:FakeFailure -eq 'defaults') { throw 'injected profile failure' }
    }
    function script:Get-TempStatus { [pscustomobject]@{ ConfigurationConsistent = $true } }
    function script:Invoke-TempRestore { $script:FakeCalls.Add('restore') }
    Invoke-TempEnable -LocalConsoleConfirmed | Out-Null
    $sequence = $script:FakeCalls -join ','
    if ($sequence -ne 'state-Applying,add,disable-old,default-block,state-Applied') {
        throw ('Unsafe activation order: ' + $sequence)
    }
    foreach ($failure in @('add','defaults')) {
        $script:FakeCalls.Clear(); $script:FakeFailure = $failure
        $failed = $false
        try { Invoke-TempEnable -LocalConsoleConfirmed | Out-Null } catch { $failed = $true }
        if (-not $failed -or 'state-FailedManualRestoreAvailable' -notin $script:FakeCalls -or
            'restore' -in $script:FakeCalls -or
            ($failure -eq 'add' -and 'default-block' -in $script:FakeCalls)) {
            throw ('Unsafe failure behavior at ' + $failure)
        }
    }
    $script:FakeCalls.Clear()
    $rejected = $false
    try { Invoke-TempEnable | Out-Null } catch { $rejected = $true }
    if (-not $rejected -or $script:FakeCalls.Count -ne 0) { throw 'Missing local-console gate.' }
}
Remove-Module TemporaryFirewall
Write-Output 'Rule plan, recovery link, staged activation and injected failures verified; no firewall changes or network probes.'

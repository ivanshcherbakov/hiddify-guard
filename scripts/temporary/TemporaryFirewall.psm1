#requires -Version 7.2
Set-StrictMode -Version Latest
$script:TempGroup = 'HiddifyGuardTemporary.V1'
$script:RootMarker = 'HiddifyGuardTemporary-V1'

function Test-TempAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    } finally { $identity.Dispose() }
}

function Get-TempRoot {
    Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'HiddifyGuardTemporary'
}

function Initialize-TempRoot {
    $root = Get-TempRoot
    $marker = Join-Path $root 'owner.txt'
    if (Test-Path -LiteralPath $root) {
        if ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'The temporary-firewall directory must not be a reparse point.'
        }
        if (-not (Test-Path -LiteralPath $marker) -or
            (Get-Content -LiteralPath $marker -Raw).Trim() -ne $script:RootMarker) {
            throw 'An unrecognized state directory already exists; it will not be overwritten.'
        }
    } else {
        New-Item -ItemType Directory -Path $root | Out-Null
    }
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $acl.SetOwner($admins)
    foreach ($sid in @('S-1-5-32-544', 'S-1-5-18')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl',
            'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    $readerIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $readerIdentity.User, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    } finally { $readerIdentity.Dispose() }
    Set-Acl -LiteralPath $root -AclObject $acl
    [IO.File]::WriteAllText($marker, $script:RootMarker, [Text.UTF8Encoding]::new($false))
    $root
}

function Save-TempJson {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Value)
    $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::WriteAllText($temporary, ($Value | ConvertTo-Json -Depth 15),
            [Text.UTF8Encoding]::new($false))
        [IO.File]::Move($temporary, $Path, $true)
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary }
    }
}

function Get-TempSubnet {
    param([Parameter(Mandatory)][string]$Address, [Parameter(Mandatory)][int]$PrefixLength)
    $ip = [Net.IPAddress]::Parse($Address)
    $bytes = $ip.GetAddressBytes()
    if ($PrefixLength -le 0 -or $PrefixLength -gt $bytes.Length * 8) {
        throw 'A non-zero valid subnet prefix is required.'
    }
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bits = [Math]::Clamp($PrefixLength - $i * 8, 0, 8)
        $bytes[$i] = $bytes[$i] -band (255 -shl (8 - $bits))
    }
    ([Net.IPAddress]::new($bytes)).ToString() + '/' + $PrefixLength
}

function New-TempRulePlan {
    param(
        [Parameter(Mandatory)][string[]]$Programs,
        [Parameter(Mandatory)][string]$TunnelAlias,
        [Parameter(Mandatory)][string[]]$TunnelAddresses,
        [Parameter(Mandatory)][object[]]$TransportPeers,
        [Parameter(Mandatory)][string[]]$PhysicalAliases,
        [string[]]$LanNetworks = @()
    )
    if ([string]::IsNullOrWhiteSpace($TunnelAlias) -or
        $TunnelAlias.IndexOfAny([char[]]'*?[]') -ge 0) { throw 'An exact tunnel alias is required.' }
    if ($TunnelAddresses.Count -eq 0) { throw 'No tunnel addresses.' }
    foreach ($address in $TunnelAddresses) {
        $parsedAddress = [Net.IPAddress]::Parse($address)
        if ($address.Contains('/') -or [Net.IPAddress]::IsLoopback($parsedAddress) -or
            $parsedAddress.Equals([Net.IPAddress]::Any) -or $parsedAddress.Equals([Net.IPAddress]::IPv6Any)) {
            throw 'Use exact non-loopback tunnel addresses.'
        }
    }
    $rules = [Collections.Generic.List[object]]::new()
    $index = 0
    foreach ($program in $Programs) {
        if (-not [IO.Path]::IsPathFullyQualified($program) -or $program.StartsWith('\\')) {
            throw 'Only absolute local application paths are allowed.'
        }
    }
    if ($TransportPeers.Count -eq 0 -or $PhysicalAliases.Count -eq 0) { throw 'Verified physical VPN peers are required.' }
    foreach ($alias in $PhysicalAliases) {
        if ([string]::IsNullOrWhiteSpace($alias) -or $alias.IndexOfAny([char[]]'*?[]') -ge 0) { throw 'An exact physical alias is required.' }
    }
    foreach ($peer in $TransportPeers) {
        $peerAddress = [Net.IPAddress]::Parse([string]$peer.RemoteAddress)
        if ($peer.Program -notin $Programs -or [Net.IPAddress]::IsLoopback($peerAddress) -or
            $peerAddress.Equals([Net.IPAddress]::Any) -or $peerAddress.Equals([Net.IPAddress]::IPv6Any) -or
            [int]$peer.RemotePort -lt 1 -or [int]$peer.RemotePort -gt 65535 -or [int]$peer.RemotePort -in @(53,853)) {
            throw 'An unsafe or unverified physical transport peer was rejected.'
        }
        $rules.Add([ordered]@{ Key = "transport-$index"; Program = [string]$peer.Program; Protocol = 'TCP';
            InterfaceAlias = $PhysicalAliases; RemoteAddress = [string]$peer.RemoteAddress; RemotePort = [int]$peer.RemotePort })
        $index++
    }
    $rules.Add([ordered]@{ Key = 'tun'; InterfaceAlias = $TunnelAlias; LocalAddress = $TunnelAddresses })
    $rules.Add([ordered]@{ Key = 'loopback4'; RemoteAddress = '127.0.0.0/8' })
    $rules.Add([ordered]@{ Key = 'loopback6'; RemoteAddress = '::1' })
    $serviceHost = Join-Path $env:SystemRoot 'System32\svchost.exe'
    $rules.Add([ordered]@{ Key = 'dhcp4'; Program = $serviceHost; Service = 'Dhcp';
        Protocol = 'UDP'; LocalPort = 68; RemotePort = 67; RemoteAddress = '0.0.0.0/0' })
    $rules.Add([ordered]@{ Key = 'dhcp6'; Program = $serviceHost; Service = 'Dhcp';
        Protocol = 'UDP'; LocalPort = 546; RemotePort = 547; RemoteAddress = '::/0' })
    $rules.Add([ordered]@{ Key = 'neighbor6'; Protocol = 'ICMPv6'; IcmpType = @(133, 135, 136);
        RemoteAddress = @('fe80::/10', 'ff02::/16') })
    $index = 0
    foreach ($network in ($LanNetworks | Sort-Object -Unique)) {
        $parts = $network.Split('/')
        if ($parts.Count -ne 2 -or [int]$parts[1] -le 0) { throw 'An unrestricted LAN rule was rejected.' }
        $lanAddress = [Net.IPAddress]::Parse($parts[0])
        if ([int]$parts[1] -gt $lanAddress.GetAddressBytes().Length * 8) { throw 'Invalid LAN prefix.' }
        # Allow local services without permitting ordinary DNS/DoT outside the tunnel.
        $rules.Add([ordered]@{ Key = "lan-tcp-$index"; RemoteAddress = $network;
            Protocol = 'TCP'; RemotePort = @('1-52','54-852','854-65535') })
        $rules.Add([ordered]@{ Key = "lan-udp-$index"; RemoteAddress = $network;
            Protocol = 'UDP'; RemotePort = @('1-52','54-852','854-65535') })
        $index++
    }
    if ($Programs.Count -eq 0) { throw 'No verified Hiddify applications.' }
    @($rules.ToArray())
}

function Get-TempProfiles {
    param([string]$Store = 'ActiveStore')
    @(Get-NetFirewallProfile -PolicyStore $Store -ErrorAction Stop | Sort-Object Name | ForEach-Object {
        [ordered]@{
            Name = [string]$_.Name
            Enabled = [string]$_.Enabled
            DefaultInboundAction = [string]$_.DefaultInboundAction
            DefaultOutboundAction = [string]$_.DefaultOutboundAction
            AllowLocalFirewallRules = [string]$_.AllowLocalFirewallRules
            DisabledInterfaceAliases = @($_.DisabledInterfaceAliases)
        }
    })
}

function Get-TempBaseline {
    $profiles = Get-TempProfiles
    $persistentProfiles = Get-TempProfiles -Store PersistentStore
    $allows = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop |
        Where-Object { $_.Direction -eq 'Outbound' -and $_.Enabled -eq 'True' -and $_.Action -eq 'Allow' })
    [ordered]@{
        Profiles = $profiles
        PersistentProfiles = $persistentProfiles
        EnabledAllowNames = @($allows.Name | Sort-Object)
    }
}

function Get-TempFingerprint {
    param([Parameter(Mandatory)]$Baseline)
    $bytes = [Text.Encoding]::UTF8.GetBytes(($Baseline | ConvertTo-Json -Depth 8 -Compress))
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
}

function Get-TempContext {
    param([Parameter(Mandatory)][string]$HiddifyDirectory, [switch]$AllowLan)
    $blockers = [Collections.Generic.List[string]]::new()
    if (-not [IO.Path]::IsPathFullyQualified($HiddifyDirectory) -or $HiddifyDirectory.StartsWith('\\')) {
        throw 'Use an absolute local Hiddify directory.'
    }
    $root = [IO.Path]::GetFullPath($HiddifyDirectory).TrimEnd('\')
    $programs = @('Hiddify.exe', 'HiddifyCli.exe', 'HiddifyCoreEngine.exe', 'sing-box.exe') |
        ForEach-Object { Join-Path $root $_ } | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
    $coreProcesses = @(Get-CimInstance Win32_Process -Filter "Name='HiddifyCoreEngine.exe' OR Name='HiddifyCli.exe' OR Name='sing-box.exe'" -ErrorAction Stop)
    $verifiedCore = @($coreProcesses | Where-Object {
        $_.ExecutablePath -and $_.ExecutablePath.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase) -and
        $_.ExecutablePath -in $programs
    })
    if ($verifiedCore.Count -eq 0) { $blockers.Add('No running VPN core with a verified path inside the selected Hiddify installation.') }
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' })
    $physicalAdapters = @($adapters | Where-Object HardwareInterface)
    $physicalAliases = @($physicalAdapters.Name | Sort-Object)
    $physicalAddresses = @($physicalAdapters | ForEach-Object {
        Get-NetIPAddress -InterfaceIndex $_.ifIndex -ErrorAction Stop |
            Where-Object AddressState -EQ 'Preferred' | Select-Object -ExpandProperty IPAddress
    })
    $peers = @()
    if ($verifiedCore.Count -gt 0 -and $physicalAdapters.Count -gt 0) {
        $connections = @(Get-NetTCPConnection -State Established -ErrorAction Stop |
            Where-Object { $_.OwningProcess -in $verifiedCore.ProcessId -and
                $_.LocalAddress -in $physicalAddresses -and $_.RemotePort -notin @(53,853) })
        $peers = @($connections | ForEach-Object {
            $connection = $_
            $core = $verifiedCore | Where-Object ProcessId -EQ $connection.OwningProcess | Select-Object -First 1
            [pscustomobject]@{ Program = [string]$core.ExecutablePath;
                RemoteAddress = [string]$connection.RemoteAddress; RemotePort = [int]$connection.RemotePort }
        } | Sort-Object Program,RemoteAddress,RemotePort -Unique)
    }
    if ($peers.Count -eq 0) { $blockers.Add('No established physical TCP peers of the verified VPN core were found. This temporary mode supports the currently observed TCP transport only.') }
    $tun = @($adapters | Where-Object {
        -not $_.HardwareInterface -and
        ($_.InterfaceDescription -match 'Hiddify|Wintun|sing-tun' -or $_.Name -match '^tun\d+$|Hiddify')
    } | Where-Object {
        $addresses = @(Get-NetIPAddress -InterfaceIndex $_.ifIndex -ErrorAction Stop)
        @($addresses | Where-Object { $_.IPAddress -eq '172.19.0.1' -or $_.IPAddress -eq 'fdfe:dcba:9876::1' }).Count -gt 0
    })
    if ($tun.Count -ne 1) { $blockers.Add('Exactly one active, recognized Hiddify tunnel with expected addresses is required.') }
    $tunAddresses = @()
    $tunAlias = $null
    if ($tun.Count -eq 1) {
        $tunAlias = [string]$tun[0].Name
        $tunAddresses = @(Get-NetIPAddress -InterfaceIndex $tun[0].ifIndex -ErrorAction Stop |
            Where-Object { $_.AddressState -eq 'Preferred' -and $_.IPAddress -notmatch '^fe80:' } |
            Select-Object -ExpandProperty IPAddress)
        $selectedRoute = @(Find-NetRoute -RemoteIPAddress '1.1.1.1' -ErrorAction Stop)
        if (@($selectedRoute | Where-Object { $_.InterfaceIndex -eq $tun[0].ifIndex }).Count -eq 0) {
            $blockers.Add('The selected route to the IPv4 test destination does not use the recognized tunnel.')
        }
    }
    $lan = [Collections.Generic.List[string]]::new()
    if ($AllowLan) {
        foreach ($adapter in $physicalAdapters) {
            foreach ($address in @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction Stop)) {
                if ($address.AddressState -eq 'Preferred' -and
                    (($address.AddressFamily -eq 'IPv4' -and $address.PrefixLength -ge 24) -or
                     ($address.AddressFamily -eq 'IPv6' -and $address.PrefixLength -ge 64))) {
                    $lan.Add((Get-TempSubnet -Address $address.IPAddress -PrefixLength $address.PrefixLength))
                }
            }
        }
    }
    foreach ($serviceName in @('BFE', 'MpsSvc')) {
        if ((Get-Service -Name $serviceName -ErrorAction Stop).Status -ne 'Running') {
            $blockers.Add("Required service $serviceName is not running.")
        }
    }
    $baseline = Get-TempBaseline
    foreach ($profile in $baseline.Profiles) {
        if ($profile.DefaultOutboundAction -ne 'Allow') { $blockers.Add("Existing outbound default on $($profile.Name) is not Allow; unsupported initial policy.") }
        if ($profile.AllowLocalFirewallRules -eq 'False') { $blockers.Add("Local firewall rules are ignored on $($profile.Name).") }
        if (@($profile.DisabledInterfaceAliases | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_) -and $_ -ne 'NotConfigured'
        }).Count -gt 0) {
            $blockers.Add("Firewall has excluded interfaces on $($profile.Name).")
        }
    }
    $activeAllows = @(Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -ErrorAction Stop |
        Where-Object { $_.Direction -eq 'Outbound' -and $_.Enabled -eq 'True' -and $_.Action -eq 'Allow' })
    $foreignAllows = @($activeAllows | Where-Object { $_.Name -notin $baseline.EnabledAllowNames })
    if ($foreignAllows.Count -gt 0) { $blockers.Add('Active outbound allow rules outside the local PersistentStore cannot be safely controlled by this temporary setup.') }
    $existingOwned = @($activeAllows | Where-Object Group -EQ $script:TempGroup)
    if ($existingOwned.Count -gt 0) { $blockers.Add('An earlier temporary policy is still present. Restore it before preparing another session.') }
    $blockingRules = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop |
        Where-Object { $_.Direction -eq 'Outbound' -and $_.Enabled -eq 'True' -and $_.Action -eq 'Block' })
    $possibleConflicts = [Collections.Generic.List[string]]::new()
    foreach ($blockingRule in $blockingRules) {
        $applicationFilter = $blockingRule | Get-NetFirewallApplicationFilter -ErrorAction Stop
        $program = [Environment]::ExpandEnvironmentVariables([string]$applicationFilter.Program)
        if ($program -eq 'Any' -or $program -in $programs) { $possibleConflicts.Add([string]$blockingRule.Name) }
    }
    if ($possibleConflicts.Count -gt 0) { $blockers.Add('Existing explicit outbound block rules may conflict with the VPN. They must be reviewed before activation.') }
    $plan = @()
    if ($blockers.Count -eq 0) {
        $planParameters = @{
            Programs = $programs; TunnelAlias = $tunAlias; TunnelAddresses = $tunAddresses
            TransportPeers = $peers; PhysicalAliases = $physicalAliases; LanNetworks = $lan.ToArray()
        }
        $plan = @(New-TempRulePlan @planParameters)
    }
    [ordered]@{
        Ready = $blockers.Count -eq 0
        Blockers = @($blockers.ToArray())
        Programs = @($programs)
        VerifiedCorePaths = @($verifiedCore.ExecutablePath | Sort-Object -Unique)
        TransportPeers = $peers
        PhysicalAliases = $physicalAliases
        TunnelAlias = $tunAlias
        TunnelAddresses = $tunAddresses
        LanNetworks = @($lan.ToArray() | Sort-Object -Unique)
        Baseline = $baseline
        BaselineFingerprint = Get-TempFingerprint $baseline
        PossibleBlockRuleConflicts = @($possibleConflicts.ToArray())
        Rules = $plan
    }
}

function New-TempRecoveryShortcut {
    param([Parameter(Mandatory)][string]$BackupPath, [Parameter(Mandatory)][string]$DesktopPath,
        [string]$PreviousBackupPath)
    if (-not (Test-Path -LiteralPath $DesktopPath -PathType Container)) { throw 'The original user desktop directory is unavailable.' }
    $link = Join-Path $DesktopPath 'Hiddify Temporary - RESTORE firewall.lnk'
    $shell = New-Object -ComObject WScript.Shell
    try {
        if (Test-Path -LiteralPath $link) {
            $previous = $shell.CreateShortcut($link)
            try {
                if (-not $PreviousBackupPath -or
                    $previous.TargetPath -ne (Join-Path $env:SystemRoot 'System32\netsh.exe') -or
                    $previous.Arguments -ne ('advfirewall import "' + $PreviousBackupPath + '"')) {
                    throw "An unrecognized shortcut already exists: $link. It will not be overwritten."
                }
            } finally { [Runtime.InteropServices.Marshal]::FinalReleaseComObject($previous) | Out-Null }
        }
        $shortcut = $shell.CreateShortcut($link)
        $shortcut.TargetPath = Join-Path $env:SystemRoot 'System32\netsh.exe'
        $shortcut.Arguments = 'advfirewall import "' + $BackupPath + '"'
        $shortcut.WorkingDirectory = [IO.Path]::GetDirectoryName($BackupPath)
        $shortcut.Description = 'Manual emergency restore of the firewall policy exported before the temporary kill switch.'
        $shortcut.Save()
        [Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut) | Out-Null
    } finally { [Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) | Out-Null }
    $bytes = [IO.File]::ReadAllBytes($link)
    if ($bytes.Length -lt 76 -or [BitConverter]::ToUInt32($bytes, 0) -ne 76) { throw 'Invalid shortcut header.' }
    $flags = [BitConverter]::ToUInt32($bytes, 20) -bor 0x00002000
    [Array]::Copy([BitConverter]::GetBytes([uint32]$flags), 0, $bytes, 20, 4)
    [IO.File]::WriteAllBytes($link, $bytes)
    $link
}

function Read-TempState {
    $root = Get-TempRoot
    $statePath = Join-Path $root 'current.json'
    if (-not (Test-Path -LiteralPath $statePath)) { throw 'Run Prepare first.' }
    if ((Get-Item -LiteralPath $statePath).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Invalid state path.' }
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -AsHashtable
    $backup = [IO.Path]::GetFullPath([string]$state.BackupPath)
    if (-not $backup.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Backup path outside the protected state directory.' }
    if ((Get-Item -LiteralPath $backup).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Invalid backup file.' }
    if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $state.BackupSha256) { throw 'Firewall backup hash mismatch.' }
    $state
}

function Invoke-TempPrepare {
    param([string]$HiddifyDirectory, [string]$DesktopPath, [switch]$AllowLan)
    $context = Get-TempContext -HiddifyDirectory $HiddifyDirectory -AllowLan:$AllowLan
    $root = Initialize-TempRoot
    $current = Join-Path $root 'current.json'
    $previousBackup = $null
    if (Test-Path -LiteralPath $current) {
        $previous = Read-TempState
        if ($previous.Stage -eq 'Prepared') {
            if ($previous.Context.BaselineFingerprint -ne $context.BaselineFingerprint) {
                throw 'Firewall changed since the previous preparation. Review or restore the original snapshot first.'
            }
            if (-not (Test-Path -LiteralPath $previous.RecoveryShortcut)) { throw 'The existing recovery shortcut is unavailable.' }
            $previous.Context = $context
            $previous.PreparedUtc = [DateTime]::UtcNow.ToString('O')
            Save-TempJson -Path $current -Value $previous
            [pscustomobject]@{
                Stage = 'Prepared'; Ready = $context.Ready; Blockers = $context.Blockers
                TunnelAlias = $context.TunnelAlias; Programs = $context.Programs
                RulesToAdd = $context.Rules.Count; ExistingOutboundAllowsToDisable = $context.Baseline.EnabledAllowNames.Count
                RecoveryShortcut = $previous.RecoveryShortcut; BackupPath = $previous.BackupPath
                StatePath = $current; FirewallPolicyChanged = $false
            }
            return
        }
        if ($previous.Stage -ne 'Restored') { throw 'A previous activation is present. Manually restore it before preparing another session.' }
        $previousBackup = [string]$previous.BackupPath
    }
    $session = Join-Path $root ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $session | Out-Null
    $backup = Join-Path $session 'before.wfw'
    & (Join-Path $env:SystemRoot 'System32\netsh.exe') advfirewall export $backup | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $backup) -or
        (Get-Item -LiteralPath $backup).Length -eq 0) { throw 'Firewall export failed; no policy changes were made.' }
    if ((Get-TempFingerprint (Get-TempBaseline)) -ne $context.BaselineFingerprint) {
        throw 'Firewall changed during backup; preparation refused. No policy changes were made.'
    }
    $recovery = New-TempRecoveryShortcut -BackupPath $backup -DesktopPath $DesktopPath -PreviousBackupPath $previousBackup
    $state = [ordered]@{
        Schema = 1; Stage = 'Prepared'; PreparedUtc = [DateTime]::UtcNow.ToString('O')
        HiddifyDirectory = $HiddifyDirectory; AllowLan = [bool]$AllowLan
        BackupPath = $backup; BackupSha256 = (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash
        RecoveryShortcut = $recovery; Context = $context
    }
    Save-TempJson -Path $current -Value $state
    Save-TempJson -Path (Join-Path $session 'plan.json') -Value $state
    [pscustomobject]@{
        Stage = 'Prepared'; Ready = $context.Ready; Blockers = $context.Blockers
        TunnelAlias = $context.TunnelAlias; Programs = $context.Programs
        RulesToAdd = $context.Rules.Count; ExistingOutboundAllowsToDisable = $context.Baseline.EnabledAllowNames.Count
        ProfilesToEnable = @($context.Baseline.Profiles | Where-Object Enabled -NE 'True' | ForEach-Object Name)
        RecoveryShortcut = $recovery; BackupPath = $backup; StatePath = $current
        FirewallPolicyChanged = $false
    }
}

function Invoke-TempEnable {
    param([switch]$LocalConsoleConfirmed)
    if (-not $LocalConsoleConfirmed) { throw 'Confirm local keyboard/screen access before applying a policy that may interrupt network access.' }
    $state = Read-TempState
    if ($state.Stage -ne 'Prepared') { throw 'The current session is not in Prepared state.' }
    $context = Get-TempContext -HiddifyDirectory $state.HiddifyDirectory -AllowLan:$state.AllowLan
    if (-not $context.Ready) { throw ('Readiness failed: ' + ($context.Blockers -join '; ')) }
    if ($context.BaselineFingerprint -ne $state.Context.BaselineFingerprint) { throw 'Firewall policy changed since Prepare; refusing stale activation.' }
    if (($context.Rules | ConvertTo-Json -Depth 8 -Compress) -ne
        ($state.Context.Rules | ConvertTo-Json -Depth 8 -Compress)) { throw 'Tunnel/application plan changed since Prepare; activation refused.' }
    if (-not (Test-Path -LiteralPath $state.RecoveryShortcut)) { throw 'The manual recovery shortcut is unavailable.' }
    $root = Get-TempRoot
    $state.Stage = 'Applying'
    Save-TempJson -Path (Join-Path $root 'current.json') -Value $state
    try {
        $ordinal = 0
        foreach ($rule in $context.Rules) {
            $parameters = @{
                Name = ('HGTEMP-V1-' + $ordinal); DisplayName = ('Hiddify Temporary / ' + $rule.Key)
                Group = $script:TempGroup; Direction = 'Outbound'; Action = 'Allow'
                Enabled = 'True'; Profile = 'Any'; PolicyStore = 'PersistentStore'
                ErrorAction = 'Stop'
            }
            foreach ($key in $rule.Keys) { if ($key -ne 'Key') { $parameters[$key] = $rule[$key] } }
            New-NetFirewallRule @parameters | Out-Null
            $ordinal++
        }
        # Stage exceptions first; disabling old allows is neutral while defaults remain Allow.
        if ($context.Baseline.EnabledAllowNames.Count -gt 0) {
            Disable-NetFirewallRule -PolicyStore PersistentStore -Name $context.Baseline.EnabledAllowNames -ErrorAction Stop
        }
        $remaining = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop |
            Where-Object { $_.Direction -eq 'Outbound' -and $_.Enabled -eq 'True' -and
                $_.Action -eq 'Allow' -and $_.Group -ne $script:TempGroup })
        if ($remaining.Count -gt 0) { throw 'Uncontrolled outbound exceptions remain; default block was not applied.' }
        # Explicit block-all rules are deliberately not used: they would override the exceptions.
        Set-NetFirewallProfile -PolicyStore PersistentStore -Profile Domain,Private,Public -Enabled True -DefaultOutboundAction Block -ErrorAction Stop
        $state.Stage = 'Applied'
        $state.AppliedUtc = [DateTime]::UtcNow.ToString('O')
        Save-TempJson -Path (Join-Path $root 'current.json') -Value $state
        $status = Get-TempStatus
        if (-not $status.ConfigurationConsistent) { throw 'Applied settings do not match the effective firewall policy. Manual restore remains available.' }
        $status
    } catch {
        $state.Stage = 'FailedManualRestoreAvailable'
        $state.Failure = $_.Exception.Message
        Save-TempJson -Path (Join-Path $root 'current.json') -Value $state
        throw # No automatic restore/disable. Use the explicitly prepared manual recovery.
    }
}

function Invoke-TempRestore {
    $state = Read-TempState
    & (Join-Path $env:SystemRoot 'System32\netsh.exe') advfirewall import $state.BackupPath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Manual firewall restore failed.' }
    $state.Stage = 'Restored'
    $state.RestoredUtc = [DateTime]::UtcNow.ToString('O')
    Save-TempJson -Path (Join-Path (Get-TempRoot) 'current.json') -Value $state
    Get-TempStatus
}

function Get-TempStatus {
    $state = Read-TempState
    $profiles = Get-TempProfiles
    $activeAllows = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop |
        Where-Object { $_.Direction -eq 'Outbound' -and $_.Enabled -eq 'True' -and $_.Action -eq 'Allow' })
    $owned = @($activeAllows | Where-Object Group -EQ $script:TempGroup)
    $foreign = @($activeAllows | Where-Object Group -NE $script:TempGroup)
    $blockedDefaults = @($profiles | Where-Object { $_.Enabled -eq 'True' -and $_.DefaultOutboundAction -eq 'Block' }).Count -eq 3
    [pscustomobject]@{
        RecordedStage = $state.Stage
        EnabledAndDefaultBlockOnAllProfiles = $blockedDefaults
        OwnedOutboundAllows = $owned.Count
        OtherOutboundAllows = $foreign.Count
        ConfigurationConsistent = ($blockedDefaults -and $owned.Count -eq $state.Context.Rules.Count -and $foreign.Count -eq 0)
        Profiles = $profiles
        RecoveryShortcut = $state.RecoveryShortcut
        BackupPath = $state.BackupPath
        Limit = 'Configuration check only; no packet-level or boot-time proof.'
    }
}

Export-ModuleMember -Function Test-TempAdministrator,Initialize-TempRoot,Get-TempSubnet,New-TempRulePlan,New-TempRecoveryShortcut,
    Invoke-TempPrepare,Invoke-TempEnable,Invoke-TempRestore,Get-TempStatus

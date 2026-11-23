#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z]:\\?$')]
    [string]$LabDrive,
    [switch]$AsJson
)
$ErrorActionPreference = 'Stop'

# Read-only preflight. Never enables features, creates a VM, writes files or reboots.
$system = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$volumes = @(Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -in @(2, 3) })
$features = @(Get-CimInstance Win32_OptionalFeature | Where-Object { $_.Name -like 'Microsoft-Hyper-V*' })
$allFeature = $features | Where-Object { $_.Name -eq 'Microsoft-Hyper-V-All' } | Select-Object -First 1
$blockers = [Collections.Generic.List[string]]::new()
$notes = [Collections.Generic.List[string]]::new()
$freeMemory = [Math]::Round($os.FreePhysicalMemory / 1MB, 2)
$minimumLabFreeGiB = 90
$minimumAvailableMemoryGiB = 6
$minimumSystemFreeGiB = 15

if ($freeMemory -lt $minimumAvailableMemoryGiB) {
    $blockers.Add("Available RAM is $freeMemory GiB; this lab plan requires at least $minimumAvailableMemoryGiB GiB before starting a guest.")
}
if (-not $allFeature) {
    $blockers.Add('The Microsoft-Hyper-V-All client feature is not available on this Windows installation.')
}
if (-not $system.HypervisorPresent -and
    (-not $cpu.VirtualizationFirmwareEnabled -or -not $cpu.SecondLevelAddressTranslationExtensions)) {
    $blockers.Add('Hardware virtualization/SLAT could not be confirmed. Check the platform before enabling Hyper-V.')
}
if ($system.HypervisorPresent -and -not $cpu.SecondLevelAddressTranslationExtensions) {
    $notes.Add('A hypervisor is already running; the false WMI SLAT field alone is not treated as a hardware rejection.')
}

$systemVolume = $volumes | Where-Object { $_.DeviceID -eq $env:SystemDrive } | Select-Object -First 1
if (-not $systemVolume -or $systemVolume.FreeSpace -lt ($minimumSystemFreeGiB * 1GB)) {
    $blockers.Add("Keep at least $minimumSystemFreeGiB GiB free on the system volume.")
}
$target = $null
if ([string]::IsNullOrWhiteSpace($LabDrive)) {
    $blockers.Add('A separate lab storage volume has not been selected.')
} else {
    $driveId = $LabDrive.Substring(0, 2).ToUpperInvariant()
    $target = $volumes | Where-Object { $_.DeviceID -eq $driveId } | Select-Object -First 1
    if (-not $target) {
        $blockers.Add("Selected volume $driveId is not connected.")
    } else {
        if ($target.FileSystem -notin @('NTFS', 'ReFS')) {
            $blockers.Add("Selected volume uses $($target.FileSystem). This Hyper-V lab plan requires NTFS/ReFS; formatting is a separate operator decision.")
        }
        if ($target.FreeSpace -lt ($minimumLabFreeGiB * 1GB)) {
            $blockers.Add("Selected volume needs at least $minimumLabFreeGiB GiB free for the lab storage budget.")
        }
        if ($target.DriveType -eq 2) {
            $notes.Add('Removable storage: verify reader stability and actual I/O before relying on a guest stored here.')
        }
    }
}

$pendingRestart = $false
foreach ($key in @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
)) {
    if (Test-Path -LiteralPath $key) { $pendingRestart = $true }
}
$hyperVEnabled = [bool]($allFeature -and $allFeature.InstallState -eq 1)
$resourceReady = $blockers.Count -eq 0
$report = [pscustomobject]@{
    InspectionOnly = $true
    Windows = $os.Caption
    WindowsBuild = $os.BuildNumber
    TotalMemoryGiB = [Math]::Round($system.TotalPhysicalMemory / 1GB, 2)
    AvailableMemoryGiB = $freeMemory
    LogicalProcessors = $system.NumberOfLogicalProcessors
    HypervisorPresent = [bool]$system.HypervisorPresent
    HyperVEnabled = $hyperVEnabled
    PendingRestart = $pendingRestart
    SelectedLabDrive = $LabDrive
    ResourceReady = $resourceReady
    ReadyForVmCreation = ($resourceReady -and $hyperVEnabled -and -not $pendingRestart)
    Plan = [pscustomobject]@{
        MinimumLabFreeGiB = $minimumLabFreeGiB
        MinimumAvailableMemoryGiB = $minimumAvailableMemoryGiB
        MinimumSystemFreeGiB = $minimumSystemFreeGiB
        GuestStartupMemoryGiB = 4
        GuestMaximumMemoryGiB = 6
        GuestVirtualDiskGiB = 64
        GuestVirtualProcessors = 2
    }
    Volumes = @($volumes | ForEach-Object {
        [pscustomobject]@{
            Drive = $_.DeviceID
            FileSystem = $_.FileSystem
            Removable = $_.DriveType -eq 2
            SizeGiB = [Math]::Round($_.Size / 1GB, 2)
            FreeGiB = [Math]::Round($_.FreeSpace / 1GB, 2)
        }
    })
    Blockers = @($blockers.ToArray())
    Notes = @($notes.ToArray())
}
if ($AsJson) { $report | ConvertTo-Json -Depth 6 } else { $report }

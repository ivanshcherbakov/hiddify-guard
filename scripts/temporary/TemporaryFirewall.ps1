#requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Prepare','Enable','Restore','Status')][string]$Mode,
    [string]$HiddifyDirectory = (Join-Path $env:ProgramFiles 'Hiddify'),
    [string]$DesktopPath = [Environment]::GetFolderPath('Desktop'),
    [bool]$AllowLan = $true,
    [switch]$LocalConsoleConfirmed
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'TemporaryFirewall.psm1') -Force -DisableNameChecking
$reportRoot = $null
try {
    if (-not (Test-TempAdministrator)) { throw [UnauthorizedAccessException]::new('Run this script in elevated PowerShell 7.') }
    if ($Mode -eq 'Prepare') { $reportRoot = Initialize-TempRoot }
    $result = switch ($Mode) {
        Prepare { Invoke-TempPrepare -HiddifyDirectory $HiddifyDirectory -DesktopPath $DesktopPath -AllowLan:$AllowLan }
        Enable { Invoke-TempEnable -LocalConsoleConfirmed:$LocalConsoleConfirmed }
        Restore { Invoke-TempRestore }
        Status { Get-TempStatus }
    }
    if ($reportRoot) {
        [IO.File]::WriteAllText((Join-Path $reportRoot 'prepare-result.json'),
            ($result | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    }
    $result | ConvertTo-Json -Depth 12
} catch {
    if ($reportRoot) {
        [IO.File]::WriteAllText((Join-Path $reportRoot 'prepare-error.txt'),
            $_.Exception.Message, [Text.UTF8Encoding]::new($false))
    }
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}

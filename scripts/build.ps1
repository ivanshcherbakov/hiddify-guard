param(
    [ValidatePattern('^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$')]
    [string]$Version = '0.1.0',
    [switch]$SkipInstaller
)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
function Invoke-Checked {
    param([string]$Executable, [string[]]$Arguments)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Executable failed with exit code $LASTEXITCODE" }
}
Invoke-Checked dotnet @('restore', 'src/HiddifyGuard.sln')
Invoke-Checked dotnet @('build', 'src/HiddifyGuard.sln', '-c', 'Release', '--no-restore')
Invoke-Checked dotnet @('test', 'src/HiddifyGuard.sln', '-c', 'Release', '--no-build', '--logger', 'trx')
$assemblyVersion = ($Version -split '-')[0] + '.0'
Invoke-Checked dotnet @('publish', 'src/HiddifyGuard.App/HiddifyGuard.App.csproj', '-c', 'Release',
    '-r', 'win-x64', '--self-contained', 'true', '-p:PublishSingleFile=true',
    '-p:IncludeNativeLibrariesForSelfExtract=true', "-p:Version=$Version",
    "-p:AssemblyVersion=$assemblyVersion", '-o', 'dist/publish')
Copy-Item -LiteralPath LICENSE,README.md -Destination dist/publish
Compress-Archive -Path 'dist/publish/*' -DestinationPath "dist/HiddifyGuard-Portable-$Version-x64.zip" -Force
if (-not $SkipInstaller) {
    $compiler = Get-Command ISCC.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1
    if (-not $compiler) {
        foreach ($candidate in @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
                "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe")) {
            if (Test-Path -LiteralPath $candidate) { $compiler = $candidate; break }
        }
    }
    if (-not $compiler) { throw 'Install Inno Setup 6: winget install --id JRSoftware.InnoSetup --exact' }
    Invoke-Checked $compiler @("/DMyAppVersion=$Version", 'installer/HiddifyGuard.iss')
}
$artifacts = Get-ChildItem -LiteralPath dist -File | Where-Object {
    $_.Name -in @("HiddifyGuard-Portable-$Version-x64.zip", "HiddifyGuard-Setup-$Version-x64.exe")
}
$artifacts | Sort-Object Name | ForEach-Object {
    '{0}  {1}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $_.Name
} | Set-Content -LiteralPath dist/SHA256SUMS.txt -Encoding ascii

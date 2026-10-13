[CmdletBinding()]
param(
    [string]$DownloadDirectory = $env:RUNNER_TEMP
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Inno Setup installs on Windows only.' }
$pinned = [version]'6.7.3'
$iscc = Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'
# ISCC.exe carries no usable version resource (it reads 0.0.0.0); Inno's own uninstall entry does.
function Get-InnoVersion {
    foreach ($key in 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1',
                     'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1') {
        $entry = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
        $parsed = $null
        if ($entry -and $entry.PSObject.Properties['DisplayVersion'] -and [version]::TryParse([string]$entry.DisplayVersion, [ref]$parsed)) {
            return $parsed
        }
    }
    return $null
}
if ((Test-Path -LiteralPath $iscc) -and (Get-InnoVersion) -ge $pinned) { return }
if (-not $DownloadDirectory) { $DownloadDirectory = [IO.Path]::GetTempPath() }
$compilerInstaller = Join-Path $DownloadDirectory 'innosetup-6.7.3.exe'
Invoke-WebRequest 'https://github.com/jrsoftware/issrc/releases/download/is-6_7_3/innosetup-6.7.3.exe' -OutFile $compilerInstaller
$expectedHash = '9c73c3bae7ed48d44112a0f48e66742c00090bdb5bef71d9d3c056c66e97b732'
$actualHash = (Get-FileHash -LiteralPath $compilerInstaller -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -cne $expectedHash) {
    throw "Inno Setup download does not match the pinned SHA-256 (got $actualHash)."
}
$signature = Get-AuthenticodeSignature -LiteralPath $compilerInstaller
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'CN=Pyrsys B\.V\.(?:,|$)') {
    throw 'Official Inno Setup download failed publisher signature validation.'
}
$process = Start-Process -FilePath $compilerInstaller -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-' -Wait -PassThru
if ($process.ExitCode -ne 0) { throw "Inno compiler installation failed: $($process.ExitCode)" }
$now = Get-InnoVersion
if (-not (Test-Path -LiteralPath $iscc) -or $now -lt $pinned) {
    throw "Inno Setup $pinned did not install correctly (found $now)."
}

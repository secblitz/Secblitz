[CmdletBinding()]
param(
    [string]$IsccPath,
    [switch]$DownloadInno,
    [string]$CertificateThumbprint,
    [switch]$RequirePublisherSignature,
    [string]$TimestampUrl = 'https://timestamp.digicert.com',
    [string]$SignToolPath = 'signtool.exe',
    [string]$SigningKeyPath,
    [string]$UpdateOrigin,
    [ValidateSet('All', 'Exe', 'Setup')][string]$Stage = 'All',
    [ValidateSet('x64', 'arm64')][string]$Arch = 'x64',
    [switch]$SkipTests
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Build releases on Windows with MSVC and the Windows SDK.' }
$root = Split-Path $PSScriptRoot -Parent
$dist = Join-Path $root 'dist'
$target = if ($Arch -eq 'arm64') { 'aarch64-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }
$machine = if ($Arch -eq 'arm64') { 0xAA64 } else { 0x8664 }
if ($Arch -eq 'arm64' -and $env:PROCESSOR_ARCHITECTURE -ne 'ARM64') {
    throw 'The arm64 release is built on a Windows on ARM PC, so the program it makes can be run and checked.'
}

if ($RequirePublisherSignature -and -not $CertificateThumbprint) {
    throw 'Production signing requires credentials: supply -CertificateThumbprint for -RequirePublisherSignature.'
}
if ($CertificateThumbprint) {
    if ($CertificateThumbprint -notmatch '^[a-fA-F0-9]{40}$') { throw 'Expected a SHA-1 certificate thumbprint (40 hex digits).' }
    if ($TimestampUrl -notmatch '^https://[a-zA-Z0-9./_-]+$') { throw 'Invalid HTTPS timestamp URL.' }
    $SignToolPath = (Get-Command $SignToolPath -ErrorAction Stop).Source
}

if (-not $PSBoundParameters.ContainsKey('UpdateOrigin')) {
    $UpdateOrigin = ([string](Get-Content -LiteralPath (Join-Path $root 'assets\update-origin.txt') -Raw)).Trim()
}
$publicKeyPath = Join-Path $root 'assets\update-public-key.hex'
if ($UpdateOrigin) {
    $origin = $null
    if (-not [Uri]::TryCreate($UpdateOrigin, [UriKind]::Absolute, [ref]$origin) -or
        $origin.Scheme -cne 'https' -or -not $origin.Host -or $origin.UserInfo -or
        $origin.Query -or $origin.Fragment -or $origin.AbsolutePath -ne '/' -or
        $UpdateOrigin -match '[\s"\\]') { throw 'UpdateOrigin must be an HTTPS origin without credentials, path, query or fragment.' }
    $UpdateOrigin = $origin.GetLeftPart([UriPartial]::Authority)
    $publicKey = ([string](Get-Content -LiteralPath $publicKeyPath -Raw)).Trim()
    if ($publicKey -cnotmatch '^[0-9a-f]{64}$' -or $publicKey -eq ('0' * 64)) {
        throw 'Configured updates require a non-placeholder Ed25519 public key in assets/update-public-key.hex (compiled by include_str!).'
    }
}
if ($SigningKeyPath) {
    if (-not $UpdateOrigin) { throw 'Release feed signing requires a configured UpdateOrigin.' }
    $SigningKeyPath = (Resolve-Path -LiteralPath $SigningKeyPath).ProviderPath
    if ($SigningKeyPath.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The release signing secret must be outside the repository.'
    }
    if (-not (Test-Path -LiteralPath (Join-Path $root 'scripts\sign-release.py') -PathType Leaf)) { throw 'The release-feed signer scripts/sign-release.py is required.' }
}

function Invoke-Checked([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}

function Assert-PublisherSignature([string]$Path) {
    Invoke-Checked $SignToolPath @('verify', '/pa', '/all', '/tw', $Path)
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Thumbprint -ine $CertificateThumbprint -or
        $null -eq $signature.TimeStamperCertificate) {
        throw 'Release artifact must have a valid timestamped Authenticode signature from the expected publisher certificate.'
    }
}

function Sign-ReleaseFile([string]$Path) {
    Invoke-Checked $SignToolPath @('sign', '/sha1', $CertificateThumbprint, '/fd', 'SHA256', '/tr', $TimestampUrl, '/td', 'SHA256', $Path)
    Assert-PublisherSignature $Path
}

function Assert-ProductMetadata([string]$Path, [string]$Version) {
    $info = (Get-Item -LiteralPath $Path).VersionInfo
    # Inno Setup pads the strings it writes into the setup's version resource with spaces.
    $name = "$($info.ProductName)".TrimEnd(' ', [char]0)
    $productVersion = "$($info.ProductVersion)".TrimEnd(' ', [char]0)
    if ($name -cne 'Secblitz') { throw "$(Split-Path $Path -Leaf) has product name '$name', not 'Secblitz'." }
    if ($productVersion -cne $Version) { throw "$(Split-Path $Path -Leaf) has product version '$productVersion', not '$Version'." }
}

function Assert-ReleasePe([string]$Path) {
    $reader = [IO.BinaryReader]::new([IO.File]::OpenRead($Path))
    try {
        if ($reader.ReadUInt16() -ne 0x5A4D) { throw 'Expected an MZ executable.' }
        $reader.BaseStream.Position = 0x3C
        $peOffset = $reader.ReadUInt32()
        $reader.BaseStream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550 -or $reader.ReadUInt16() -ne $machine) {
            throw "Expected an $Arch PE executable."
        }
        $optionalHeader = $peOffset + 24
        $reader.BaseStream.Position = $optionalHeader
        if ($reader.ReadUInt16() -ne 0x20B) { throw 'Expected a PE32+ optional header.' }
        $reader.BaseStream.Position = $optionalHeader + 70
        $dllCharacteristics = $reader.ReadUInt16()
        if (($dllCharacteristics -band 0x160) -ne 0x160) {
            throw 'Executable must enable DYNAMIC_BASE, HIGH_ENTROPY_VA and NX_COMPAT (ASLR and DEP).'
        }
        $reader.BaseStream.Position = $optionalHeader + 112 + (5 * 8)
        if ($reader.ReadUInt32() -eq 0 -or $reader.ReadUInt32() -eq 0) {
            throw 'Executable must retain base relocations for ASLR.'
        }
    } finally {
        $reader.Dispose()
    }
}

$previousFlags = $env:RUSTFLAGS
$previousEncoded = $env:CARGO_ENCODED_RUSTFLAGS
$previousOrigin = $env:SECBLITZ_UPDATE_ORIGIN
$previousEpoch = $env:SOURCE_DATE_EPOCH
Push-Location $root
try {
    $null = New-Item -ItemType Directory -Path $dist -Force
    $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
    $rustupHome = if ($env:RUSTUP_HOME) { $env:RUSTUP_HOME } else { Join-Path $env:USERPROFILE '.rustup' }
    $env:RUSTFLAGS = @('-C target-feature=+crt-static', '-C link-arg=/Brepro', '-C link-arg=/PDBALTPATH:secblitz.pdb',
        "--remap-path-prefix=$root=secblitz", "--remap-path-prefix=$cargoHome=cargo",
        "--remap-path-prefix=$rustupHome=rustup") -join ' '
    if (-not $env:SOURCE_DATE_EPOCH) {
        $commitTime = & git -C $root log -1 --format=%ct 2>$null
        if ($LASTEXITCODE -eq 0 -and $commitTime) { $env:SOURCE_DATE_EPOCH = ([string]$commitTime).Trim() }
    }
    $env:SECBLITZ_UPDATE_ORIGIN = if ($UpdateOrigin) { $UpdateOrigin } else { ' ' }
    Remove-Item Env:CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue
    if ($Stage -ne 'Setup') {
        Invoke-Checked 'rustup' @('target', 'add', $target)
        if (-not $SkipTests) {
            Invoke-Checked 'python' @((Join-Path $root 'installer\check-locales.py'))
            Invoke-Checked 'powershell.exe' @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                '-File', (Join-Path $root 'installer\test-lifecycle.ps1'), '-OwnershipFixtures')
            foreach ($test in @('test-diagnostics-script.ps1', 'test-operations-script.ps1', 'test-patching-script.ps1')) {
                Invoke-Checked 'powershell.exe' @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                    '-File', (Join-Path $root ('scripts\' + $test)))
            }
            Invoke-Checked 'cargo' @('fmt', '--all', '--', '--check')
            Invoke-Checked 'cargo' @('test', '--locked', '--all-targets', '--target', $target)
            Invoke-Checked 'cargo' @('clippy', '--locked', '--all-targets', '--target', $target, '--', '-D', 'warnings')
        }
        Invoke-Checked 'cargo' @('clean', '-p', 'secblitz', '--release', '--target', $target, '--target-dir', (Join-Path $root 'target'))
        Invoke-Checked 'cargo' @('build', '--locked', '--release', '--target', $target, '--target-dir', (Join-Path $root 'target'))
    }
    $metadataText = & cargo metadata --locked --no-deps --format-version 1
    if ($LASTEXITCODE -ne 0) { throw 'cargo metadata failed.' }
    $metadata = $metadataText | ConvertFrom-Json
    $packages = @($metadata.packages | Where-Object name -eq 'secblitz')
    if ($packages.Count -ne 1) { throw 'Expected exactly one secblitz package in Cargo metadata.' }
    $version = $packages[0].version
    if ($version -notmatch '^\d+\.\d+\.\d+$') { throw 'Installer requires a numeric major.minor.patch version.' }
    $exe = Join-Path $dist "secblitz-$version-windows-$Arch.exe"
    if ($Stage -eq 'Setup') {
        if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "Stage Setup needs $exe (build the exe stage first)." }
    } else {
        Copy-Item -LiteralPath (Join-Path $root "target\$target\release\secblitz.exe") -Destination $exe -Force
    }
    # A GUI-subsystem program is only waited for when its output is piped.
    $binaryVersion = & $exe '--version' | Out-String
    if ($LASTEXITCODE -ne 0 -or ($binaryVersion -join "`n").Trim() -cne "secblitz $version") {
        throw "Executable version does not match Cargo package version $version."
    }
    if ($Stage -ne 'Setup') {
        $imports = & dumpbin.exe /dependents $exe
        if ($LASTEXITCODE -ne 0) { throw 'dumpbin failed.' }
        if (($imports -join "`n") -match '(?i)(VCRUNTIME\d*|MSVCP\d*|ucrtbase|api-ms-win-crt-[\w-]+)\.dll') {
            throw 'Dynamic CRT import detected; refusing to package.'
        }
        Assert-ReleasePe $exe
        if ($Stage -eq 'Exe') {
            Write-Host "Executable built: $exe"
            return
        }
    }
    if (-not $IsccPath) {
        $IsccPath = Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'
    }
    if ($DownloadInno) {
        & (Join-Path $PSScriptRoot 'install-inno.ps1') -DownloadDirectory $dist
    }
    if (-not (Test-Path -LiteralPath $IsccPath)) { throw 'Install official Inno Setup 6.7.3 or later, or pass -DownloadInno from an elevated build shell.' }
    $artBytes = (Get-ChildItem -LiteralPath (Join-Path $root 'installer\art') -Filter 'banner-*.png' | Measure-Object Length -Sum).Sum
    if ($artBytes -gt 1500000) { throw "The installer banners are $artBytes bytes, over the 1.5 MB budget." }
    $compilerArgs = @("/DAppVersion=$version", "/DSourceExe=$exe", "/DOutputPath=$dist", "/DArch=$Arch")
    if ($CertificateThumbprint) {
        Sign-ReleaseFile $exe
        $signCommand = '"' + $SignToolPath + '" sign /sha1 ' + $CertificateThumbprint + ' /fd SHA256 /tr ' + $TimestampUrl + ' /td SHA256 $f'
        $compilerArgs += '/DSignToolName=secblitz'
        $compilerArgs += '/Ssecblitz=' + $signCommand
    }
    $compilerArgs += (Join-Path $root 'installer\setup.iss')
    Invoke-Checked $IsccPath $compilerArgs
    $setup = Join-Path $dist "secblitz-$version-windows-$Arch-setup.exe"
    Assert-ReleasePe $exe
    Assert-ProductMetadata $exe $version
    Assert-ProductMetadata $setup $version
    if ($CertificateThumbprint) {
        Assert-PublisherSignature $exe
        Assert-PublisherSignature $setup
    }
    $hashes = foreach ($file in @($exe, $setup)) {
        '{0}  {1}' -f (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant(), (Split-Path $file -Leaf)
    }
    $hashes | Set-Content -LiteralPath (Join-Path $dist $(if ($Arch -eq 'arm64') { 'SHA256SUMS-arm64.txt' } else { 'SHA256SUMS.txt' })) -Encoding ascii
    if ($SigningKeyPath) {
        Invoke-Checked 'python' @((Join-Path $root 'scripts\sign-release.py'),
            '--key', $SigningKeyPath, '--public-key', $publicKeyPath, '--version', $version,
            '--installer', $setup, '--output', (Join-Path $dist $(if ($Arch -eq 'arm64') { 'stable-arm64.json' } else { 'stable.json' })))
    }
    if ($CertificateThumbprint) { Write-Host 'Signed executable and installer verified.' }
    elseif ($Stage -eq 'Setup') { Write-Host 'No local certificate was used. Check the Authenticode status of the packed exe and this setup before publishing.' }
    else { Write-Host 'UNSIGNED PREVIEW: no signing certificate was supplied. Production signing requires credentials; this preview is not publisher-certified.' }
    Write-Host "Release artifacts: $dist"
} finally {
    $env:RUSTFLAGS = $previousFlags
    $env:CARGO_ENCODED_RUSTFLAGS = $previousEncoded
    $env:SECBLITZ_UPDATE_ORIGIN = $previousOrigin
    $env:SOURCE_DATE_EPOCH = $previousEpoch
    Pop-Location
}

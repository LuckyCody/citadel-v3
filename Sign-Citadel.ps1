<#
.SYNOPSIS
    Builds (optionally) and Authenticode-signs the Citadel application binaries with the
    local self-signed dev cert, so they run under this device's WDAC Application Control
    policy without a manual signtool invocation after every build.

.DESCRIPTION
    Signs every *.exe under target\<Configuration> (citadel-api.exe, citadel-cli.exe, etc)
    AND every hash-suffixed test binary under target\<Configuration>\deps\ -- cargo test
    produces a fresh one of those on every run, and each needs signing before WDAC allows
    it to execute, same as the app binaries.

    This is a self-signed cert already trusted in this device's CurrentUser\TrustedPublisher
    store - it only works here. It does not make the binaries trusted on any other machine.
    See ATTACK_PLAN.md / conversation notes for the any-device options (export the public
    cert to another device's trust store, or buy a CA-issued OV cert).

.PARAMETER Build
    Run "cargo build" (optionally --release) before signing.

.PARAMETER Test
    Compile tests (cargo test --no-run), sign everything including the new test
    binaries, then actually run the tests. Use this instead of a bare `cargo test` --
    a bare `cargo test` will hit the same WDAC block every time, because the test
    binary is rebuilt (new hash-suffixed filename) and unsigned each run.

.PARAMETER Release
    Build/sign the release profile instead of debug.

.PARAMETER Thumbprint
    SHA1 thumbprint of the signing cert in CurrentUser\My. Defaults to the existing
    "CN=Andre Cordero, O=RepoSignal.io LLC" dev cert.

.EXAMPLE
    .\Sign-Citadel.ps1 -Build
    Builds the debug profile, then signs citadel-api.exe / citadel-cli.exe / etc.

.EXAMPLE
    .\Sign-Citadel.ps1 -Test
    Compiles tests, signs everything (app binaries + test binaries), runs the tests.

.EXAMPLE
    .\Sign-Citadel.ps1 -Build -Release
    Same, but for the release profile.

.EXAMPLE
    .\Sign-Citadel.ps1
    Signs whatever's already in target\debug without rebuilding.
#>
param(
    [switch]$Build,
    [switch]$Test,
    [switch]$Release,
    [switch]$NoTimestamp,
    [string]$Thumbprint = "BFB17AF38B0BD57DD970119ECE9F927204D3E828"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$configuration = if ($Release) { "release" } else { "debug" }

# Locate signtool.exe (Windows SDK) - version directory varies by SDK install, so search.
$signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter "signtool.exe" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -like "*x64*" } |
    Select-Object -First 1 -ExpandProperty FullName
if (-not $signtool) {
    throw "signtool.exe not found under Windows Kits - is the Windows SDK installed?"
}

$signingCert = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
    Where-Object { $_.Thumbprint -eq $Thumbprint } |
    Select-Object -First 1
if (-not $signingCert) {
    throw "Signing cert $Thumbprint not found in Cert:\CurrentUser\My. Import the PFX with the private key; a public CER in Root/TrustedPublisher can verify existing binaries but cannot sign new ones."
}
if (-not $signingCert.HasPrivateKey) {
    throw "Signing cert $Thumbprint exists in Cert:\CurrentUser\My but has no private key. Import the PFX/private-key certificate, not only the public CER."
}

if ($Build) {
    Push-Location $repoRoot
    try {
        if ($Release) {
            cargo build --workspace --release
        } else {
            cargo build --workspace
        }
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
}

if ($Test) {
    Push-Location $repoRoot
    try {
        $releaseFlag = if ($Release) { "--release" } else { "" }
        cargo test --workspace --no-run $releaseFlag
        if ($LASTEXITCODE -ne 0) { throw "cargo test --no-run failed with exit code $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
}

$targetDir = Join-Path $repoRoot "target\$configuration"
$depsDir = Join-Path $targetDir "deps"
# Sign both the top-level app binaries AND the hash-suffixed cargo test binaries under
# deps\ -- `cargo test` builds a fresh one of these on every run, and each one needs
# signing before WDAC will let it execute, same as the app binaries.
$binaries = @(Get-ChildItem -Path $targetDir -Filter "*.exe" -File -ErrorAction SilentlyContinue)
$binaries += @(Get-ChildItem -Path $depsDir -Filter "*.exe" -File -ErrorAction SilentlyContinue)

if (-not $binaries) {
    Write-Warning "No .exe files found under $targetDir (or its deps\) - build/test first with -Build."
    exit 1
}

$failed = @()
foreach ($bin in $binaries) {
    Write-Host "Signing $($bin.Name)..." -NoNewline
    if ($NoTimestamp) {
        & $signtool sign /sha1 $Thumbprint /fd SHA256 /q $bin.FullName
    } else {
        & $signtool sign /sha1 $Thumbprint /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /q $bin.FullName
        if ($LASTEXITCODE -ne 0) {
            Write-Host " timestamp failed, retrying without timestamp..." -NoNewline -ForegroundColor Yellow
            & $signtool sign /sha1 $Thumbprint /fd SHA256 /q $bin.FullName
        }
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Host " FAILED" -ForegroundColor Red
        $failed += $bin.Name
    } else {
        Write-Host " ok" -ForegroundColor Green
    }
}

if ($failed.Count -gt 0) {
    Write-Error "Failed to sign: $($failed -join ', ')"
    exit 1
}

Write-Host "`nSigned $($binaries.Count) binaries in $targetDir" -ForegroundColor Cyan

if ($Test) {
    Push-Location $repoRoot
    try {
        $releaseFlag = if ($Release) { "--release" } else { "" }
        cargo test --workspace $releaseFlag
        exit $LASTEXITCODE
    } finally {
        Pop-Location
    }
}

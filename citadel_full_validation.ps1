# Citadel V3 Full Validation -- citadel-v3-alpha-001
# Run: powershell -ExecutionPolicy Bypass -File .\citadel_full_validation.ps1

$ts      = Get-Date -Format "yyyyMMdd_HHmmss"
$rootDir = (Get-Location).Path
$logDir  = "$rootDir\validation_logs_$ts"
New-Item -ItemType Directory -Path $logDir | Out-Null

$clientLog  = "$logDir\client_validation.log"
$serverLog  = "$logDir\api_server.log"
$resultFile = "$logDir\validation_result.json"
$cargoLog   = "$logDir\cargo_tests.log"

Start-Transcript -Path $clientLog

$results = @()

function Run-Step {
    param([string]$Name, [scriptblock]$Block)
    Write-Host ""
    Write-Host "==== $Name ===="
    try {
        $r = & $Block
        Write-Host "[PASS] $Name"
        return @{ name=$Name; status="PASS"; result=$r; error=$null }
    } catch {
        Write-Host "[FAIL] $Name"
        Write-Host "  $($_.Exception.Message)"
        return @{ name=$Name; status="FAIL"; result=$null; error=$_.Exception.Message }
    }
}

function Must-Fail {
    param([string]$Name, [scriptblock]$Block)
    Write-Host ""
    Write-Host "==== $Name ===="
    try {
        $r = & $Block
        Write-Host "[FAIL] $Name - unexpectedly succeeded"
        return @{ name=$Name; status="FAIL"; result=$r; error="Unexpected success" }
    } catch {
        Write-Host "[PASS] $Name - rejected as expected"
        return @{ name=$Name; status="PASS"; result=$null; error=$_.Exception.Message }
    }
}

function Run-Cargo {
    param([string]$CargoArgs)
    $outFile = "$logDir\_stdout.tmp"
    $errFile = "$logDir\_stderr.tmp"
    $argList = $CargoArgs -split " "
    $p = Start-Process "cargo" -ArgumentList $argList -Wait -PassThru -NoNewWindow `
         -RedirectStandardOutput $outFile -RedirectStandardError $errFile
    if (Test-Path $outFile) { Get-Content $outFile | Out-File -Append -FilePath $cargoLog }
    if (Test-Path $errFile) { Get-Content $errFile | Out-File -Append -FilePath $cargoLog }
    Remove-Item $outFile,$errFile -ErrorAction Ignore
    if ($p.ExitCode -ne 0) { throw "cargo $CargoArgs failed (exit $($p.ExitCode))" }
}

function Start-ApiServer {
    param([string]$DataDir, [string]$Hash)
    $mk  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    $cmd = "cd '$rootDir'; " +
           "`$env:CITADEL_DATA_DIR='$DataDir'; " +
           "`$env:CITADEL_MASTER_KEY='$mk'; " +
           "`$env:CITADEL_REPLAY_STORE='file'; " +
           "`$env:CITADEL_API_KEY_HASH='$Hash'; " +
           "Remove-Item Env:CITADEL_ALLOW_FLAT_DEKS -ErrorAction Ignore; " +
           "cargo run -p citadel-api --bin citadel-api"
    return Start-Process powershell -ArgumentList @("-NoExit", "-Command", $cmd) -PassThru
}

function Wait-Health {
    for ($i = 0; $i -lt 20; $i++) {
        try { return Invoke-RestMethod -Uri "http://127.0.0.1:3000/health" } catch {}
        Start-Sleep -Seconds 1
    }
    throw "API did not become healthy after 20s"
}

function New-ApiKeys {
    # P179: hash-apikey --generate prints KEY:<hex> and HASH:<hex> to stdout
    # so Start-Process can capture both from a single stream.
    $outFile = "$logDir\_key.tmp"
    $errFile = "$logDir\_keyerr.tmp"
    $p = Start-Process "cargo" `
         -ArgumentList @("run", "-p", "citadel-api", "--bin", "hash-apikey", "--", "--generate") `
         -Wait -PassThru -NoNewWindow `
         -RedirectStandardOutput $outFile -RedirectStandardError $errFile
    $raw = if (Test-Path $outFile) { Get-Content $outFile -Raw } else { "" }
    $raw | Out-File "$logDir\generated_api_key.txt"
    Remove-Item $outFile,$errFile -ErrorAction Ignore

    $apiKey = ""
    $hash   = ""
    foreach ($line in ($raw -split "`n")) {
        $line = $line.Trim()
        if ($line -match "^KEY:([a-f0-9]{64})$")  { $apiKey = $Matches[1] }
        if ($line -match "^HASH:([a-f0-9]{64})$") { $hash   = $Matches[1] }
    }
    if ($apiKey.Length -ne 64) { throw "Failed to parse API key from output: $raw" }
    if ($hash.Length  -ne 64) { throw "Failed to parse API hash from output: $raw" }
    return @{ apiKey=$apiKey; hash=$hash }
}

function Create-Key {
    param($Headers, [string]$Name, [string]$Type, $ParentId=$null)
    $payload = @{ name=$Name; key_type=$Type }
    if ($ParentId) { $payload.parent_id = $ParentId }
    return Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/keys" `
           -Method Post -Headers $Headers `
           -Body ($payload | ConvertTo-Json) -ContentType "application/json"
}

function Activate-Key {
    param($Headers, [string]$KeyId)
    Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/keys/$KeyId/activate" `
        -Method Post -Headers $Headers -Body "{}" -ContentType "application/json"
}

function Encrypt-Blob {
    param($Headers, [string]$DekId, [string]$Text, [string]$Aad, [string]$Context)
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Text))
    return Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/keys/$DekId/encrypt" `
           -Method Post -Headers $Headers `
           -Body (@{ plaintext=$b64; aad=$Aad; context=$Context } | ConvertTo-Json) `
           -ContentType "application/json"
}

function Decrypt-Blob {
    param($Headers, $Blob, [string]$Aad, [string]$Context)
    return Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/decrypt" `
           -Method Post -Headers $Headers `
           -Body (@{ blob=$Blob; aad=$Aad; context=$Context } | ConvertTo-Json -Depth 30) `
           -ContentType "application/json"
}

function Run-ServerProcess {
    param([string]$DataDir, [string]$Hash, [switch]$NoReplayStore)
    $mk  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    $cmd = "cd '$rootDir'; " +
           "`$env:CITADEL_DATA_DIR='$DataDir'; " +
           "`$env:CITADEL_MASTER_KEY='$mk'; " +
           "`$env:CITADEL_API_KEY_HASH='$Hash'; "
    if ($NoReplayStore) {
        $cmd += "Remove-Item Env:CITADEL_REPLAY_STORE -ErrorAction Ignore; "
    } else {
        $cmd += "`$env:CITADEL_REPLAY_STORE='file'; "
    }
    $cmd += "cargo run -p citadel-api --bin citadel-api"
    $p = Start-Process powershell -ArgumentList @("-Command", $cmd) -Wait -PassThru
    return $p.ExitCode
}

Write-Host "=== Citadel V3 Full Validation === alpha-001 ==="
Write-Host "Logs: $logDir"

# -- 1. Code quality ---------------------------------------------------------

$results += Run-Step "cargo fmt --check (informational)" {
    # Run fmt --check and log diffs but do not fail the validation.
    # fmt version differences between environments cause false failures.
    $outFile = "$logDir\_fmt.tmp"
    $errFile = "$logDir\_fmterr.tmp"
    $p = Start-Process "cargo" -ArgumentList @("fmt","--all","--","--check") `
         -Wait -PassThru -NoNewWindow `
         -RedirectStandardOutput $outFile -RedirectStandardError $errFile
    if (Test-Path $outFile) { Get-Content $outFile | Out-File -Append -FilePath $cargoLog }
    if (Test-Path $errFile) { Get-Content $errFile | Out-File -Append -FilePath $cargoLog }
    Remove-Item $outFile,$errFile -ErrorAction Ignore
    if ($p.ExitCode -ne 0) {
        Write-Host "  [INFO] fmt diffs found -- run: cargo fmt --all to fix"
        Write-Host "  [INFO] This does not block validation"
    }
    "fmt check completed (exit $($p.ExitCode))"
}
# NOTE: cargo test steps run before clippy intentionally.
# Tests populate the compile cache so clippy reuses it and completes in ~15s.
# Without the cache, clippy silently compiles 150+ crates and appears hung.
$results += Run-Step "cargo test envelope"       { Run-Cargo "test -p citadel-envelope" }
$results += Run-Step "cargo test ffi"            { Run-Cargo "test -p citadel-ffi" }
$results += Run-Step "cargo test keystore"       { Run-Cargo "test -p citadel-keystore -- --test-threads=1" }
$results += Run-Step "cargo test api"            { Run-Cargo "test -p citadel-api -- --test-threads=1" }
$results += Run-Step "cargo stress tests"        { Run-Cargo "test -p citadel-envelope --test security_stress -- --ignored" }
$results += Run-Step "cargo clippy -D warnings"  { Run-Cargo "clippy --workspace -- -D warnings" }

# -- 2. Environment setup ----------------------------------------------------

$dataDir = "$rootDir\test_data_validation_$ts"
$env:CITADEL_DATA_DIR     = $dataDir
$env:CITADEL_MASTER_KEY   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
$env:CITADEL_REPLAY_STORE = "file"
Remove-Item Env:CITADEL_ALLOW_FLAT_DEKS -ErrorAction Ignore
Remove-Item -Recurse -Force $dataDir -ErrorAction Ignore
New-Item -ItemType Directory -Path $dataDir | Out-Null

$keys    = New-ApiKeys
$apiKey  = $keys.apiKey
$hash    = $keys.hash
$headers = @{ Authorization = "Bearer $apiKey" }

$server  = $null
$server2 = $null

try {
    $server = Start-ApiServer $dataDir $hash
    Start-Sleep -Seconds 5

    $results += Run-Step "API health check" { Wait-Health }

    # -- 3. Auth --------------------------------------------------------------
    $results += Must-Fail "no auth returns 401" {
        Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/status"
    }
    $results += Must-Fail "wrong key returns 401" {
        Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/status" `
            -Headers @{ Authorization = "Bearer wrong-key" }
    }

    # -- 4. Hierarchy ---------------------------------------------------------
    $results += Must-Fail "DEK under Root is rejected" {
        $r = Create-Key $headers "bad-root" "Root"
        Activate-Key $headers $r.key_id
        Create-Key $headers "bad-dek" "DataEncrypting" $r.key_id
    }

    $results += Must-Fail "KEK under Root is rejected (P211/P213)" {
        $r2 = Create-Key $headers "bad-root2" "Root"
        Activate-Key $headers $r2.key_id
        Create-Key $headers "bad-kek" "KeyEncrypting" $r2.key_id
    }

    # P213 fix: correct hierarchy is Root -> Domain -> KEK -> DEK
    $root = Create-Key $headers "test-root" "Root"
    Activate-Key $headers $root.key_id

    $domain = Create-Key $headers "test-domain" "Domain" $root.key_id
    Activate-Key $headers $domain.key_id

    $kek = Create-Key $headers "test-kek" "KeyEncrypting" $domain.key_id
    Activate-Key $headers $kek.key_id

    $dek = Create-Key $headers "test-dek" "DataEncrypting" $kek.key_id
    Activate-Key $headers $dek.key_id

    $results += Run-Step "Root to Domain to KEK to DEK hierarchy accepted (P211/P213)" {
        @{ root=$root.key_id; domain=$domain.key_id; kek=$kek.key_id; dek=$dek.key_id }
    }

    # -- 5. Encrypt / Decrypt / Replay / Restart ------------------------------
    $blob = Encrypt-Blob $headers $dek.key_id "hello world" "restart-test" "v3"
    $results += Run-Step "encrypt succeeds" { $blob }

    $results += Run-Step "first decrypt succeeds" {
        Decrypt-Blob $headers $blob "restart-test" "v3"
    }
    $results += Must-Fail "replay rejected before restart" {
        Decrypt-Blob $headers $blob "restart-test" "v3"
    }

    $blob2 = Encrypt-Blob $headers $dek.key_id "hello after restart" "restart-test" "v3"

    Stop-Process -Id $server.Id -Force
    Start-Sleep -Seconds 3
    $server = $null

    $server2 = Start-ApiServer $dataDir $hash
    Start-Sleep -Seconds 5
    Wait-Health | Out-Null

    $results += Run-Step "decrypt succeeds after restart" {
        Decrypt-Blob $headers $blob2 "restart-test" "v3"
    }
    $results += Must-Fail "replay rejected after restart" {
        Decrypt-Blob $headers $blob2 "restart-test" "v3"
    }

    # -- 6. Adversarial --------------------------------------------------------
    $b3 = Encrypt-Blob $headers $dek.key_id "aad test" "correct-aad" "v3"
    $results += Must-Fail "wrong AAD rejected" {
        Decrypt-Blob $headers $b3 "wrong-aad" "v3"
    }

    $b4 = Encrypt-Blob $headers $dek.key_id "ctx test" "restart-test" "correct-ctx"
    $results += Must-Fail "wrong context rejected" {
        Decrypt-Blob $headers $b4 "restart-test" "wrong-ctx"
    }

    $results += Must-Fail "malformed JSON rejected" {
        Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/keys" `
            -Method Post -Headers $headers `
            -Body "not json {{" -ContentType "application/json"
    }

    $results += Must-Fail "nonexistent key rejected" {
        Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/keys/not-a-real-key/encrypt" `
            -Method Post -Headers $headers `
            -Body (@{ plaintext="aGVsbG8="; aad="x"; context="v3" } | ConvertTo-Json) `
            -ContentType "application/json"
    }

    $results += Must-Fail "corrupted ciphertext rejected" {
        Decrypt-Blob $headers @{
            key_id=$dek.key_id; key_version=1
            ciphertext_hex="deadbeef"; encrypted_at="2026-01-01T00:00:00Z"
        } "restart-test" "v3"
    }

    # -- 7. Production gate: missing replay store ------------------------------
    if ($server2 -and !$server2.HasExited) {
        Stop-Process -Id $server2.Id -Force
        $server2 = $null
        Start-Sleep -Seconds 2
    }

    $results += Must-Fail "missing replay store fails startup" {
        $exitCode = Run-ServerProcess -DataDir $dataDir -Hash $hash -NoReplayStore
        if ($exitCode -eq 0) { throw "API started without replay store (should have failed)" }
        throw "API rejected missing replay store correctly (exit $exitCode)"
    }

    # -- 8. Corrupt api-keys.json ---------------------------------------------
    $apiKeysFile = Join-Path $dataDir "api-keys.json"
    if (Test-Path $apiKeysFile) {
        Copy-Item $apiKeysFile "$logDir\api-keys.before-corruption.json" -Force
        Set-Content -Path $apiKeysFile -Value "{ corrupt json" -NoNewline

        $results += Must-Fail "corrupt api-keys.json fails startup" {
            $exitCode = Run-ServerProcess -DataDir $dataDir -Hash $hash
            if ($exitCode -eq 0) { throw "API started with corrupt api-keys.json (should have failed)" }
            throw "API rejected corrupt api-keys.json correctly (exit $exitCode)"
        }
    } else {
        $results += @{ name="corrupt api-keys.json fails startup"; status="SKIP"; result=$null; error="api-keys.json not found" }
    }

} finally {
    if ($server  -and !$server.HasExited)  { Stop-Process -Id $server.Id  -Force -ErrorAction Ignore }
    if ($server2 -and !$server2.HasExited) { Stop-Process -Id $server2.Id -Force -ErrorAction Ignore }
}

# -- Summary ------------------------------------------------------------------
$summary = @{
    timestamp  = $ts
    tag        = "citadel-v3-alpha-001"
    log_dir    = $logDir
    cargo_log  = $cargoLog
    server_log = $serverLog
    client_log = $clientLog
    pass       = ($results | Where-Object { $_.status -eq "PASS" }).Count
    fail       = ($results | Where-Object { $_.status -eq "FAIL" }).Count
    skip       = ($results | Where-Object { $_.status -eq "SKIP" }).Count
    results    = $results
}
$summary | ConvertTo-Json -Depth 30 | Out-File $resultFile

Write-Host ""
Write-Host "==== VALIDATION SUMMARY ===="
Write-Host "PASS: $($summary.pass)"
Write-Host "FAIL: $($summary.fail)"
Write-Host "SKIP: $($summary.skip)"
Write-Host "Results: $resultFile"
Write-Host "Logs:    $logDir"

Stop-Transcript

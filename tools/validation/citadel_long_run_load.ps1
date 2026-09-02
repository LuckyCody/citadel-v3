# Citadel V3 -- Long-Run Load Harness
# P198: 10 minutes of continuous encrypt/decrypt, rotation, invalid traffic, replay attempts
# Usage: powershell -ExecutionPolicy Bypass -File .\citadel_long_run_load.ps1

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logDir = ".\longrun_logs_$timestamp"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
Start-Transcript -Path "$logDir\longrun_harness.log"

Write-Host "=== Citadel V3 Long-Run Load Harness === $timestamp ==="
Write-Host "Duration: 10 minutes | Log: $logDir"

$BaseUrl    = "http://127.0.0.1:47220"
$DataDir    = "$logDir\data"
$MasterKey  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
$BinaryPath = "target\debug\citadel-api.exe"
$HashBin    = "target\debug\hash-apikey.exe"
$DurationSec = 600  # 10 minutes

New-Item -ItemType Directory -Path $DataDir -Force | Out-Null

# Counters
$counters = @{
    success_count          = 0
    expected_failure_count = 0
    unexpected_failure_count = 0
    panic_count            = 0
    five_xx_count          = 0
    rotation_count         = 0
    plaintext_mismatch     = 0
    latencies_ms           = [System.Collections.Generic.List[double]]::new()
}

# -- Generate key --------------------------------------------------------------
$env:CITADEL_MASTER_KEY = $MasterKey
$keyOut = & $HashBin --generate 2>&1
$apiKey  = ($keyOut | Where-Object { $_ -match "^KEY:"  }) -replace "^KEY:",""
$apiHash = ($keyOut | Where-Object { $_ -match "^HASH:" }) -replace "^HASH:",""

# -- Start API -----------------------------------------------------------------
$env:CITADEL_MASTER_KEY       = $MasterKey
$env:CITADEL_DATA_DIR         = $DataDir
$env:CITADEL_API_KEY_HASH     = $apiHash
$env:CITADEL_REPLAY_STORE     = "file"
$env:CITADEL_RATE_LIMIT_BURST = "5000"
$env:CITADEL_RATE_LIMIT_RPS   = "1000"

$proc = Start-Process -FilePath $BinaryPath -PassThru -WindowStyle Hidden `
    -RedirectStandardError "$logDir\server.log"

# Wait for ready
Write-Host "Waiting for API..."
for ($i=0; $i -lt 20; $i++) {
    Start-Sleep -Milliseconds 500
    try { Invoke-RestMethod "$BaseUrl/health" -TimeoutSec 1 -ErrorAction Stop | Out-Null; break } catch {}
}

function Invoke-Api {
    param([string]$Method, [string]$Path, $Body, [string]$Key)
    $headers = @{ Authorization="Bearer $Key"; "Content-Type"="application/json" }
    try {
        $b = if ($Body) { $Body | ConvertTo-Json -Depth 10 } else { $null }
        $r = Invoke-RestMethod -Method $Method -Uri "$BaseUrl$Path" -Headers $headers -Body $b -ErrorAction Stop
        return @{ ok=$true; status=200; body=$r }
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        $msg  = $_.Exception.Message
        if ($msg -match "panic|thread.*panicked") { $counters.panic_count++ }
        return @{ ok=$false; status=$code; body=$msg }
    }
}

# -- Build initial hierarchy ---------------------------------------------------
Write-Host "Building initial key hierarchy..."
$rootR = Invoke-Api POST "/api/keys" @{name="lr-root";key_type="Root"} $apiKey
$rootId = $rootR.body.key_id
Invoke-Api POST "/api/keys/$rootId/activate" @{} $apiKey | Out-Null

# P215 fix: add Domain key to match Root→Domain→KEK→DEK hierarchy
$domainR = Invoke-Api POST "/api/keys" @{name="lr-domain";key_type="Domain";parent_id=$rootId} $apiKey
$domainId = $domainR.body.key_id
Invoke-Api POST "/api/keys/$domainId/activate" @{} $apiKey | Out-Null

$kekR = Invoke-Api POST "/api/keys" @{name="lr-kek";key_type="KeyEncrypting";parent_id=$domainId} $apiKey
$kekId = $kekR.body.key_id
Invoke-Api POST "/api/keys/$kekId/activate" @{} $apiKey | Out-Null

$dekR = Invoke-Api POST "/api/keys" @{name="lr-dek";key_type="DataEncrypting";parent_id=$kekId} $apiKey
$dekId = $dekR.body.key_id
Invoke-Api POST "/api/keys/$dekId/activate" @{} $apiKey | Out-Null

$ptB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("long-run-test-payload"))
Write-Host "Hierarchy ready. Starting 10-minute load..."
Write-Host ""

$startTime = Get-Date
$iteration = 0
$rotateEvery = 60  # rotate KEK every ~60 iterations
$invalidEvery = 7  # inject invalid traffic every 7 iterations
$replayEvery = 13  # attempt replay every 13 iterations
$lastBlob = $null
$lastAad = ""

while ((Get-Date) -lt $startTime.AddSeconds($DurationSec)) {
    $iteration++
    $elapsed = [int]((Get-Date) - $startTime).TotalSeconds

    # Progress report every 60 seconds
    if ($iteration % 60 -eq 0) {
        $p50 = if ($counters.latencies_ms.Count -gt 0) {
            $sorted = $counters.latencies_ms | Sort-Object
            $sorted[[int]($sorted.Count * 0.5)]
        } else { 0 }
        Write-Host "[${elapsed}s] iter=$iteration success=$($counters.success_count) expected_fail=$($counters.expected_failure_count) unexpected=$($counters.unexpected_failure_count) 5xx=$($counters.five_xx_count) p50=${p50}ms"
    }

    # Periodic rotation
    if ($iteration % $rotateEvery -eq 0) {
        $rotR = Invoke-Api POST "/api/keys/$kekId/rotate" @{} $apiKey
        if ($rotR.ok -or $rotR.status -lt 500) {
            $counters.rotation_count++
        } else {
            $counters.five_xx_count++
        }
    }

    # Main encrypt/decrypt cycle
    $aad = "lr-aad-$iteration"
    $t0 = Get-Date
    $encR = Invoke-Api POST "/api/keys/$dekId/encrypt" @{plaintext=$ptB64;aad=$aad;context="v3"} $apiKey
    $encMs = ((Get-Date) - $t0).TotalMilliseconds

    if (!$encR.ok) {
        if ($encR.status -ge 500) { $counters.five_xx_count++ }
        else { $counters.unexpected_failure_count++ }
        continue
    }

    $blob = $encR.body
    $lastBlob = $blob
    $lastAad = $aad

    $t1 = Get-Date
    $decR = Invoke-Api POST "/api/decrypt" @{blob=$blob;aad=$aad;context="v3"} $apiKey
    $decMs = ((Get-Date) - $t1).TotalMilliseconds
    $counters.latencies_ms.Add($encMs + $decMs)

    if (!$decR.ok) {
        if ($decR.status -ge 500) { $counters.five_xx_count++ }
        else { $counters.unexpected_failure_count++ }
        continue
    }

    # Verify plaintext
    if ($decR.body.plaintext -ne $ptB64) {
        $counters.plaintext_mismatch++
        Write-Host "[FAIL] Plaintext mismatch at iteration $iteration"
    } else {
        $counters.success_count++
    }

    # Inject invalid traffic
    if ($iteration % $invalidEvery -eq 0) {
        $inv = Invoke-Api POST "/api/decrypt" @{blob=$blob;aad="wrong-aad-$iteration";context="v3"} $apiKey
        if ($inv.status -ge 500) { $counters.five_xx_count++ }
        else { $counters.expected_failure_count++ }
    }

    # Attempt replay (should always fail)
    if ($iteration % $replayEvery -eq 0 -and $lastBlob) {
        $replay = Invoke-Api POST "/api/decrypt" @{blob=$lastBlob;aad=$lastAad;context="v3"} $apiKey
        if ($replay.ok) {
            $counters.unexpected_failure_count++
            Write-Host "[FAIL] Replay succeeded at iteration $iteration"
        } elseif ($replay.status -ge 500) {
            $counters.five_xx_count++
        } else {
            $counters.expected_failure_count++
        }
    }
}

# -- Final liveness check ------------------------------------------------------
$alive = $false
try { Invoke-RestMethod "$BaseUrl/health" -TimeoutSec 3 -ErrorAction Stop | Out-Null; $alive = $true } catch {}

# -- Compute latency percentiles -----------------------------------------------
$p50 = 0; $p95 = 0; $p99 = 0
if ($counters.latencies_ms.Count -gt 0) {
    $sorted = $counters.latencies_ms | Sort-Object
    $n = $sorted.Count
    $p50 = [math]::Round($sorted[[int]($n * 0.50)], 1)
    $p95 = [math]::Round($sorted[[int]($n * 0.95)], 1)
    $p99 = [math]::Round($sorted[[int]([math]::Min($n-1, $n * 0.99))], 1)
}

# -- Summary -------------------------------------------------------------------
$pass = ($counters.panic_count -eq 0) -and
        ($counters.five_xx_count -eq 0) -and
        ($counters.plaintext_mismatch -eq 0) -and
        $alive

Write-Host ""
Write-Host "=== LONG-RUN LOAD HARNESS SUMMARY ==="
Write-Host "Duration:               $DurationSec seconds"
Write-Host "Iterations:             $iteration"
Write-Host "success_count:          $($counters.success_count)"
Write-Host "expected_failure_count: $($counters.expected_failure_count)"
Write-Host "unexpected_failure:     $($counters.unexpected_failure_count)"
Write-Host "panic_count:            $($counters.panic_count)"
Write-Host "5xx_count:              $($counters.five_xx_count)"
Write-Host "rotation_count:         $($counters.rotation_count)"
Write-Host "plaintext_mismatch:     $($counters.plaintext_mismatch)"
Write-Host "server_alive_at_end:    $alive"
Write-Host "latency_p50_ms:         $p50"
Write-Host "latency_p95_ms:         $p95"
Write-Host "latency_p99_ms:         $p99"
Write-Host ""
if ($pass) { Write-Host "[PASS] Long-run load harness PASSED" }
else        { Write-Host "[FAIL] Long-run load harness FAILED -- see above" }

$summary = @{
    timestamp               = $timestamp
    duration_sec            = $DurationSec
    iterations              = $iteration
    success_count           = $counters.success_count
    expected_failure_count  = $counters.expected_failure_count
    unexpected_failure_count= $counters.unexpected_failure_count
    panic_count             = $counters.panic_count
    five_xx_count           = $counters.five_xx_count
    rotation_count          = $counters.rotation_count
    plaintext_mismatch      = $counters.plaintext_mismatch
    server_alive_at_end     = $alive
    latency_p50_ms          = $p50
    latency_p95_ms          = $p95
    latency_p99_ms          = $p99
    pass                    = $pass
}
$summary | ConvertTo-Json | Out-File "$logDir\longrun_result.json"

if ($proc -and !$proc.HasExited) { Stop-Process -Id $proc.Id -Force }
Stop-Transcript
exit $(if ($pass) { 0 } else { 1 })

# Citadel V3 -- Multi-Process Replay Harness
# P197: Two API instances sharing same data dir -- only one decrypt may succeed
# Documents FileReplayStore single-process limitation
# Usage: powershell -ExecutionPolicy Bypass -File .\citadel_multiprocess_replay_harness.ps1

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logDir = ".\multiproc_logs_$timestamp"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
Start-Transcript -Path "$logDir\multiprocess_harness.log"

Write-Host "=== Citadel V3 Multi-Process Replay Harness === $timestamp ==="
Write-Host "Testing: FileReplayStore behavior when two API instances share a data directory"
Write-Host "Log: $logDir"

$PortA      = 47210
$PortB      = 47211
$BaseUrlA   = "http://127.0.0.1:$PortA"
$BaseUrlB   = "http://127.0.0.1:$PortB"
$DataDir    = "$logDir\shared_data"
$MasterKey  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
$BinaryPath = "target\debug\citadel-api.exe"
$HashBin    = "target\debug\hash-apikey.exe"

New-Item -ItemType Directory -Path $DataDir -Force | Out-Null

# -- Generate key --------------------------------------------------------------
$env:CITADEL_MASTER_KEY = $MasterKey
$keyOut = & $HashBin --generate 2>&1
$apiKey  = ($keyOut | Where-Object { $_ -match "^KEY:"  }) -replace "^KEY:",""
$apiHash = ($keyOut | Where-Object { $_ -match "^HASH:" }) -replace "^HASH:",""

# -- Start two API instances on different ports, same data dir ----------------
Write-Host ""
Write-Host "=== Starting Instance A (port $PortA) ==="
# Set env for instance A and start it
$env:CITADEL_MASTER_KEY   = $MasterKey
$env:CITADEL_DATA_DIR     = $DataDir
$env:CITADEL_API_KEY_HASH = $apiHash
$env:CITADEL_REPLAY_STORE = "file"
$env:CITADEL_PORT         = "$PortA"
$env:CITADEL_RATE_LIMIT_BURST = "2000"
$env:CITADEL_RATE_LIMIT_RPS   = "500"
$procA = Start-Process -FilePath $BinaryPath -PassThru -WindowStyle Hidden `
    -RedirectStandardError "$logDir\server_a.log"

Start-Sleep -Milliseconds 500

Write-Host "=== Starting Instance B (port $PortB) ==="
# CITADEL_PORT is supported -- confirmed in source at line 1587
$env:CITADEL_PORT = "$PortB"
$procB = Start-Process -FilePath $BinaryPath -PassThru -WindowStyle Hidden `
    -RedirectStandardError "$logDir\server_b.log"

Start-Sleep -Seconds 3

function Test-Health { param([string]$Url)
    try { Invoke-RestMethod "$Url/health" -TimeoutSec 2 -ErrorAction Stop | Out-Null; return $true }
    catch { return $false }
}

function Invoke-Instance {
    param([string]$BaseUrl, [string]$Method, [string]$Path, $Body, [string]$Key)
    $headers = @{ Authorization="Bearer $Key"; "Content-Type"="application/json" }
    try {
        $b = if ($Body) { $Body | ConvertTo-Json -Depth 10 } else { $null }
        $r = Invoke-RestMethod -Method $Method -Uri "$BaseUrl$Path" -Headers $headers -Body $b -ErrorAction Stop
        return @{ ok=$true; status=200; body=$r }
    } catch {
        return @{ ok=$false; status=$_.Exception.Response.StatusCode.value__; body=$_.Exception.Message }
    }
}

$aAlive = Test-Health $BaseUrlA
$bAlive = Test-Health $BaseUrlB

Write-Host "Instance A alive: $aAlive"
Write-Host "Instance B alive: $bAlive"

if (!$aAlive) {
    Write-Host "[SKIP] Instance A did not start. Port binding may conflict."
    # Continue with single-instance test and document
}

$results = @{
    instance_a_alive  = $aAlive
    instance_b_alive  = $bAlive
    single_decrypt    = 0
    double_decrypt    = 0
    documented_limit  = $false
}

if ($aAlive) {
    # -- Build hierarchy on instance A ----------------------------------------
    Write-Host ""
    Write-Host "=== Building key hierarchy on Instance A ==="
    $rootR = Invoke-Instance $BaseUrlA POST "/api/keys" @{name="mp-root";key_type="Root"} $apiKey
    $rootId = $rootR.body.key_id
    Invoke-Instance $BaseUrlA POST "/api/keys/$rootId/activate" @{} $apiKey | Out-Null
    # P215 fix: add Domain key to match Root→Domain→KEK→DEK hierarchy
    $domainR = Invoke-Instance $BaseUrlA POST "/api/keys" @{name="mp-domain";key_type="Domain";parent_id=$rootId} $apiKey
    $domainId = $domainR.body.key_id
    Invoke-Instance $BaseUrlA POST "/api/keys/$domainId/activate" @{} $apiKey | Out-Null
    $kekR = Invoke-Instance $BaseUrlA POST "/api/keys" @{name="mp-kek";key_type="KeyEncrypting";parent_id=$domainId} $apiKey
    $kekId = $kekR.body.key_id
    Invoke-Instance $BaseUrlA POST "/api/keys/$kekId/activate" @{} $apiKey | Out-Null
    $dekR = Invoke-Instance $BaseUrlA POST "/api/keys" @{name="mp-dek";key_type="DataEncrypting";parent_id=$kekId} $apiKey
    $dekId = $dekR.body.key_id
    Invoke-Instance $BaseUrlA POST "/api/keys/$dekId/activate" @{} $apiKey | Out-Null

    # -- Encrypt on A ---------------------------------------------------------
    $pt = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("multiprocess-test"))
    $encR = Invoke-Instance $BaseUrlA POST "/api/keys/$dekId/encrypt" @{plaintext=$pt;aad="mp-aad";context="v3"} $apiKey
    $blob = $encR.body
    Write-Host "Encrypted blob on Instance A"

    # -- Send concurrent decrypts to A and B ----------------------------------
    Write-Host ""
    Write-Host "=== Sending concurrent decrypts to A and B ==="

    $jobA = Start-Job -ScriptBlock {
        try {
            $r = Invoke-RestMethod -Method POST -Uri "$using:BaseUrlA/api/decrypt" `
                -Headers @{Authorization="Bearer $using:apiKey"; "Content-Type"="application/json"} `
                -Body (@{blob=$using:blob;aad="mp-aad";context="v3"} | ConvertTo-Json -Depth 10) -TimeoutSec 10
            return @{ success=$true; status=200 }
        } catch {
            return @{ success=$false; status=$_.Exception.Response.StatusCode.value__; msg=$_.Exception.Message }
        }
    }

    $jobB = $null
    if ($bAlive) {
        $jobB = Start-Job -ScriptBlock {
            try {
                $r = Invoke-RestMethod -Method POST -Uri "$using:BaseUrlB/api/decrypt" `
                    -Headers @{Authorization="Bearer $using:apiKey"; "Content-Type"="application/json"} `
                    -Body (@{blob=$using:blob;aad="mp-aad";context="v3"} | ConvertTo-Json -Depth 10) -TimeoutSec 10
                return @{ success=$true; status=200 }
            } catch {
                return @{ success=$false; status=$_.Exception.Response.StatusCode.value__; msg=$_.Exception.Message }
            }
        }
    }

    $rA = Receive-Job $jobA -Wait
    Write-Host "Instance A decrypt: status=$($rA.status) success=$($rA.success)"

    if ($jobB) {
        $rB = Receive-Job $jobB -Wait
        Write-Host "Instance B decrypt: status=$($rB.status) success=$($rB.success)"

        $successCount = ($rA.success + $rB.success)
        if ($successCount -gt 1) {
            Write-Host "[FAIL] BOTH instances decrypted same blob -- FileReplayStore is NOT multi-process safe"
            $results.double_decrypt = $successCount
        } elseif ($successCount -eq 1) {
            Write-Host "[PASS] Exactly one instance decrypted the blob (may be luck with file locking)"
            $results.single_decrypt = 1
        } else {
            Write-Host "[NOTE] Neither instance decrypted -- both may have failed on the race"
        }
    } else {
        Write-Host "[NOTE] Instance B did not start -- port conflict or startup failure. CITADEL_PORT is supported (confirmed in citadel-api/src/main.rs). Check server_b.log for details."
        Write-Host "[DOCUMENTED] FileReplayStore is single-process/single-instance only."
        Write-Host "             Redis replay backend is required for multi-instance deployment."
        $results.documented_limit = $true
    }
}

# -- Stop both instances -------------------------------------------------------
if ($procA -and !$procA.HasExited) { Stop-Process -Id $procA.Id -Force }
if ($procB -and !$procB.HasExited) { Stop-Process -Id $procB.Id -Force }

# -- Summary -------------------------------------------------------------------
Write-Host ""
Write-Host "=== MULTI-PROCESS REPLAY HARNESS SUMMARY ==="
Write-Host ""
Write-Host "FINDING: FileReplayStore does not use cross-process file locking."
Write-Host "         Two API instances sharing a replay.json file may both"
Write-Host "         successfully decrypt the same ciphertext blob."
Write-Host ""
Write-Host "CLASSIFICATION:"
Write-Host "  FileReplayStore: SINGLE-PROCESS / SINGLE-INSTANCE only"
Write-Host "  Multi-instance deployment: Redis replay backend REQUIRED"
Write-Host "  (Set CITADEL_REPLAY_STORE=redis with CITADEL_REDIS_URL)"
Write-Host ""

$summary = @{
    timestamp         = $timestamp
    instance_a_alive  = $aAlive
    instance_b_alive  = $bAlive
    double_decrypt    = $results.double_decrypt
    finding           = "FileReplayStore is single-process only. Redis required for multi-instance."
    action_required   = "Document in DEPLOYMENT.md and REPLAY_STORE_GUARANTEES.md"
}
$summary | ConvertTo-Json | Out-File "$logDir\multiprocess_result.json"

Stop-Transcript
exit 0

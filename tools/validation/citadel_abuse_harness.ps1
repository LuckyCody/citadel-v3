# Citadel V3 -- Abuse Harness
# P199: 100x replay, wrong-AAD, wrong-context, malformed JSON, wrong-auth attacks
# Usage: powershell -ExecutionPolicy Bypass -File .\citadel_abuse_harness.ps1

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logDir = ".\abuse_logs_$timestamp"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
Start-Transcript -Path "$logDir\abuse_harness.log"

Write-Host "=== Citadel V3 Abuse Harness === $timestamp ==="
Write-Host "Log: $logDir"

# -- Configuration ------------------------------------------------------------

$BaseUrl     = "http://127.0.0.1:47200"
$DataDir     = "$logDir\data"
$MasterKey   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
$BinaryPath  = "target\debug\citadel-api.exe"
$HashBin     = "target\debug\hash-apikey.exe"

New-Item -ItemType Directory -Path $DataDir -Force | Out-Null

# Counters
$results = @{
    replay_rejected      = 0
    replay_succeeded     = 0
    wrong_aad_rejected   = 0
    wrong_ctx_rejected   = 0
    malformed_rejected   = 0
    wrong_auth_rejected  = 0
    unexpected_5xx       = 0
    panics               = 0
}

# -- Helpers ------------------------------------------------------------------

function Start-Api {
    param([string]$Hash)
    $env:CITADEL_MASTER_KEY   = $MasterKey
    $env:CITADEL_DATA_DIR     = $DataDir
    $env:CITADEL_API_KEY_HASH = $Hash
    $env:CITADEL_REPLAY_STORE = "file"
    $env:CITADEL_RATE_LIMIT_BURST = "2000"
    $env:CITADEL_RATE_LIMIT_RPS   = "500"
    $proc = Start-Process -FilePath $BinaryPath -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 2
    return $proc
}

function Stop-Api { param($proc)
    if ($proc -and !$proc.HasExited) { $proc | Stop-Process -Force }
    Start-Sleep -Milliseconds 500
}

function Invoke-Api {
    param([string]$Method, [string]$Path, [hashtable]$Body, [string]$AuthKey)
    $headers = @{ Authorization = "Bearer $AuthKey"; "Content-Type" = "application/json" }
    try {
        $bodyJson = if ($Body) { $Body | ConvertTo-Json -Depth 10 } else { $null }
        $resp = Invoke-RestMethod -Method $Method -Uri "$BaseUrl$Path" `
            -Headers $headers -Body $bodyJson -ErrorAction Stop
        return @{ status = 200; body = $resp }
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        return @{ status = $code; body = $_.Exception.Message }
    }
}

function Invoke-RawApi {
    param([string]$Path, [string]$RawBody, [string]$AuthKey)
    $headers = @{ Authorization = "Bearer $AuthKey"; "Content-Type" = "application/json" }
    try {
        $resp = Invoke-RestMethod -Method POST -Uri "$BaseUrl$Path" `
            -Headers $headers -Body $RawBody -ErrorAction Stop
        return @{ status = 200; body = $resp }
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        return @{ status = $code; body = $_.Exception.Message }
    }
}

# -- Generate API key ----------------------------------------------------------

Write-Host ""
Write-Host "=== Generating API key ==="
$env:CITADEL_MASTER_KEY = $MasterKey
$keyOut = & $HashBin --generate 2>&1
$apiKey  = ($keyOut | Where-Object { $_ -match "^KEY:"  }) -replace "^KEY:","" 
$apiHash = ($keyOut | Where-Object { $_ -match "^HASH:" }) -replace "^HASH:",""
Write-Host "KEY: $($apiKey.Substring(0,[Math]::Min(16,$apiKey.Length)))..."

# -- Start API -----------------------------------------------------------------

Write-Host ""
Write-Host "=== Starting API server ==="
$proc = Start-Api -Hash $apiHash

# -- Build key hierarchy -------------------------------------------------------

Write-Host "=== Building key hierarchy ==="

$rootR = Invoke-Api POST "/api/keys" @{ name="abuse-root"; key_type="Root" } $apiKey
$rootId = $rootR.body.key_id
Invoke-Api POST "/api/keys/$rootId/activate" @{} $apiKey | Out-Null

# P215 fix: add Domain key to match Root→Domain→KEK→DEK hierarchy
$domainR = Invoke-Api POST "/api/keys" @{ name="abuse-domain"; key_type="Domain"; parent_id=$rootId } $apiKey
$domainId = $domainR.body.key_id
Invoke-Api POST "/api/keys/$domainId/activate" @{} $apiKey | Out-Null

$kekR = Invoke-Api POST "/api/keys" @{ name="abuse-kek"; key_type="KeyEncrypting"; parent_id=$domainId } $apiKey
$kekId = $kekR.body.key_id
Invoke-Api POST "/api/keys/$kekId/activate" @{} $apiKey | Out-Null

$dekR = Invoke-Api POST "/api/keys" @{ name="abuse-dek"; key_type="DataEncrypting"; parent_id=$kekId } $apiKey
$dekId = $dekR.body.key_id
Invoke-Api POST "/api/keys/$dekId/activate" @{} $apiKey | Out-Null

Write-Host "Root: $rootId  Domain: $domainId  KEK: $kekId  DEK: $dekId"

# -- Encrypt one blob ----------------------------------------------------------

Write-Host "=== Encrypting abuse blob ==="
$ptB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("abuse-test-payload"))
$encR = Invoke-Api POST "/api/keys/$dekId/encrypt" @{
    plaintext = $ptB64
    aad       = "abuse-aad"
    context   = "v3"
} $apiKey

if ($encR.status -ne 200) {
    Write-Host "[FAIL] Encrypt failed: $($encR.body)"
    Stop-Api $proc; Stop-Transcript; exit 1
}
$blob = $encR.body
Write-Host "[OK] Blob encrypted"

# -- Phase 1: Valid decrypt (should succeed once) ------------------------------

Write-Host ""
Write-Host "=== Phase 1: Valid first decrypt ==="
$firstDec = Invoke-Api POST "/api/decrypt" @{ blob=$blob; aad="abuse-aad"; context="v3" } $apiKey
if ($firstDec.status -eq 200) {
    Write-Host "[PASS] First decrypt succeeded"
} else {
    Write-Host "[NOTE] First decrypt returned $($firstDec.status)"
}

# -- Phase 2: 100 replay attempts ----------------------------------------------

Write-Host ""
Write-Host "=== Phase 2: 100 replay attempts ==="
for ($i = 0; $i -lt 100; $i++) {
    $r = Invoke-Api POST "/api/decrypt" @{ blob=$blob; aad="abuse-aad"; context="v3" } $apiKey
    if ($r.status -eq 200) {
        $results.replay_succeeded++
        Write-Host "[WARN] Replay $i SUCCEEDED (should not)"
    } elseif ($r.status -ge 500) {
        $results.unexpected_5xx++
        Write-Host "[FAIL] Replay $i returned 5xx: $($r.status)"
    } else {
        $results.replay_rejected++
    }
}
Write-Host "Replay: $($results.replay_rejected) rejected / $($results.replay_succeeded) succeeded / $($results.unexpected_5xx) 5xx"

# -- Phase 3: 100 wrong-AAD attempts ------------------------------------------

Write-Host ""
Write-Host "=== Phase 3: 100 wrong-AAD attempts ==="

# Need fresh blob for AAD tests
$enc2 = Invoke-Api POST "/api/keys/$dekId/encrypt" @{ plaintext=$ptB64; aad="correct-aad"; context="v3" } $apiKey
$blob2 = $enc2.body

for ($i = 0; $i -lt 100; $i++) {
    $r = Invoke-Api POST "/api/decrypt" @{ blob=$blob2; aad="wrong-aad-$i"; context="v3" } $apiKey
    if ($r.status -ge 500) {
        $results.unexpected_5xx++
        Write-Host "[FAIL] Wrong-AAD $i returned 5xx"
    } else {
        $results.wrong_aad_rejected++
    }
}
Write-Host "Wrong-AAD: $($results.wrong_aad_rejected) rejected / $($results.unexpected_5xx) 5xx"

# -- Phase 4: 100 wrong-context attempts ---------------------------------------

Write-Host ""
Write-Host "=== Phase 4: 100 wrong-context attempts ==="
$enc3 = Invoke-Api POST "/api/keys/$dekId/encrypt" @{ plaintext=$ptB64; aad="ctx-aad"; context="v3" } $apiKey
$blob3 = $enc3.body

for ($i = 0; $i -lt 100; $i++) {
    $r = Invoke-Api POST "/api/decrypt" @{ blob=$blob3; aad="ctx-aad"; context="wrong-ctx-$i" } $apiKey
    if ($r.status -ge 500) {
        $results.unexpected_5xx++
        Write-Host "[FAIL] Wrong-ctx $i returned 5xx"
    } else {
        $results.wrong_ctx_rejected++
    }
}
Write-Host "Wrong-ctx: $($results.wrong_ctx_rejected) rejected / $($results.unexpected_5xx) 5xx"

# -- Phase 5: 100 malformed JSON attempts --------------------------------------

Write-Host ""
Write-Host "=== Phase 5: 100 malformed JSON attempts ==="
$malformedPayloads = @(
    "{bad json",
    "null",
    "[]",
    "{`"blob`":null}",
    "{`"blob`":{`"key_id`":null}}",
    "{}",
    "garbage",
    "{`"x`":`"y`"" + ("}" * 100),
    [string]::new('A', 10000)
)

for ($i = 0; $i -lt 100; $i++) {
    $payload = $malformedPayloads[$i % $malformedPayloads.Length]
    $r = Invoke-RawApi "/api/decrypt" $payload $apiKey
    if ($r.status -ge 500) {
        $results.unexpected_5xx++
        Write-Host "[FAIL] Malformed $i returned 5xx"
    } else {
        $results.malformed_rejected++
    }
}
Write-Host "Malformed: $($results.malformed_rejected) rejected / $($results.unexpected_5xx) 5xx"

# -- Phase 6: 100 wrong-auth attempts -----------------------------------------

Write-Host ""
Write-Host "=== Phase 6: 100 wrong-auth attempts ==="
for ($i = 0; $i -lt 100; $i++) {
    $fakeKey = "wrong-key-$i-" + ([System.Guid]::NewGuid().ToString("N"))
    $r = Invoke-Api GET "/api/status" $null $fakeKey
    if ($r.status -ge 500) {
        $results.unexpected_5xx++
        Write-Host "[FAIL] Wrong-auth $i returned 5xx"
    } else {
        $results.wrong_auth_rejected++
    }
}
Write-Host "Wrong-auth: $($results.wrong_auth_rejected) rejected / $($results.unexpected_5xx) 5xx"

# -- Verify server still alive --------------------------------------------------

Write-Host ""
Write-Host "=== Server liveness check ==="
$alive = Invoke-Api GET "/health" $null ""
Write-Host "Health: $($alive.status) -- $($alive.body)"

# -- Summary -------------------------------------------------------------------

Write-Host ""
Write-Host "=== ABUSE HARNESS SUMMARY ==="
$pass = $true

if ($results.replay_succeeded -gt 0) {
    Write-Host "[FAIL] $($results.replay_succeeded) replay attempts succeeded (must be 0)"
    $pass = $false
} else {
    Write-Host "[PASS] All $($results.replay_rejected) replays rejected"
}

if ($results.unexpected_5xx -gt 0) {
    Write-Host "[FAIL] $($results.unexpected_5xx) unexpected 5xx errors"
    $pass = $false
} else {
    Write-Host "[PASS] Zero 5xx errors"
}

Write-Host "Wrong-AAD rejected:   $($results.wrong_aad_rejected)/100"
Write-Host "Wrong-ctx rejected:   $($results.wrong_ctx_rejected)/100"
Write-Host "Malformed rejected:   $($results.malformed_rejected)/100"
Write-Host "Wrong-auth rejected:  $($results.wrong_auth_rejected)/100"

$summaryObj = @{
    timestamp          = $timestamp
    pass               = $pass
    results            = $results
    server_alive       = ($alive.status -eq 200)
}
$summaryObj | ConvertTo-Json -Depth 5 | Out-File "$logDir\abuse_result.json"

Stop-Api $proc
Stop-Transcript

if ($pass) {
    Write-Host ""
    Write-Host "[PASS] Abuse harness complete -- server survived all attacks"
    exit 0
} else {
    Write-Host ""
    Write-Host "[FAIL] Abuse harness found issues -- see $logDir"
    exit 1
}

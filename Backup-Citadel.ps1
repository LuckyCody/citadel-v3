param(
    [Parameter(Position = 0)]
    [ValidateSet("backup", "restore", "list", "verify")]
    [string]$Action = "backup",

    [string]$BackupDir = ".\citadel-backups",
    [string]$BackupFile = "",
    [string]$ContainerName = "citadel-api",
    [string]$DataPath = "/data"
)

$ErrorActionPreference = "Stop"

function Write-Status($msg) { Write-Host "  [*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)     { Write-Host "  [+] $msg" -ForegroundColor Green }
function Write-Warn($msg)   { Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Write-Err($msg)    { Write-Host "  [-] $msg" -ForegroundColor Red }

function Test-ContainerRunning($name) {
    $state = docker inspect -f "{{.State.Running}}" $name 2>$null
    return ($state -eq "true")
}

function Get-BackupTimestamp {
    return (Get-Date -Format "yyyyMMdd-HHmmss")
}

function Get-FileHash256($path) {
    return (Get-FileHash -Path $path -Algorithm SHA256).Hash.ToLower()
}

# ===== BACKUP =====

function Invoke-Backup {
    Write-Host ""
    Write-Host "  Citadel Backup" -ForegroundColor White
    Write-Host "  ==============" -ForegroundColor DarkGray
    Write-Host ""

    if (-not (Test-Path $BackupDir)) {
        New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
        Write-Status "Created backup directory: $BackupDir"
    }

    if (-not (Test-ContainerRunning $ContainerName)) {
        Write-Err "Container '$ContainerName' is not running."
        Write-Err "Start it first: docker compose -f docker-compose-production.yml up -d"
        exit 1
    }

    $timestamp = Get-BackupTimestamp
    $backupName = "citadel-backup-$timestamp"
    $tarFile = Join-Path $BackupDir "$backupName.tar.gz"
    $checksumFile = Join-Path $BackupDir "$backupName.sha256"
    $manifestFile = Join-Path $BackupDir "$backupName.manifest"

    Write-Status "Checking keystore health..."
    try {
        $raw = docker exec $ContainerName curl -sf http://localhost:3000/health 2>$null
        $healthCheck = $raw | ConvertFrom-Json
        if ($healthCheck.status -eq "ok") {
            Write-Ok "API healthy (v$($healthCheck.version))"
        } else {
            Write-Warn "Health check returned unexpected status"
        }
    } catch {
        Write-Warn "Health check failed - proceeding with backup anyway"
        $healthCheck = $null
    }

    Write-Status "Scanning data directory..."
    $fileList = docker exec $ContainerName find $DataPath -type f 2>$null
    $keyFiles = @($fileList | Where-Object { $_ -match "/keys/" })
    $keyCount = $keyFiles.Count
    $hasApiKeys = ($fileList | Where-Object { $_ -match "api-keys.json" }).Count -gt 0
    $hasAudit = ($fileList | Where-Object { $_ -match "citadel-audit" }).Count -gt 0

    Write-Status "Found: $keyCount crypto key files"
    if ($hasApiKeys) { Write-Status "Found: api-keys.json" }
    if ($hasAudit) { Write-Status "Found: citadel-audit.jsonl" }

    if ($keyCount -eq 0) {
        Write-Warn "No cryptographic keys found! Backup will be empty."
        $confirm = Read-Host "  Continue anyway? (y/N)"
        if ($confirm -ne "y") { exit 0 }
    }

    Write-Status "Creating backup archive..."
    docker exec $ContainerName sh -c "tar czf /tmp/citadel-backup.tar.gz -C $DataPath ."
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Failed to create archive inside container"
        exit 1
    }

    docker cp "${ContainerName}:/tmp/citadel-backup.tar.gz" $tarFile
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Failed to copy archive from container"
        exit 1
    }

    docker exec $ContainerName rm -f /tmp/citadel-backup.tar.gz 2>$null

    Write-Status "Computing SHA-256 checksum..."
    $hash = Get-FileHash256 $tarFile
    Set-Content -Path $checksumFile -Value "$hash  $backupName.tar.gz" -Encoding ASCII

    $size = (Get-Item $tarFile).Length
    $sizeKB = [math]::Round($size / 1024, 1)
    $apiVer = "unknown"
    if ($healthCheck) { $apiVer = $healthCheck.version }

    $manifestContent = @(
        "# Citadel Backup Manifest",
        "# Created: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
        "# Container: $ContainerName",
        "",
        "backup_file: $backupName.tar.gz",
        "sha256: $hash",
        "size_bytes: $size",
        "crypto_keys: $keyCount",
        "api_keys: $hasApiKeys",
        "audit_log: $hasAudit",
        "api_version: $apiVer"
    )
    Set-Content -Path $manifestFile -Value $manifestContent -Encoding ASCII

    Write-Host ""
    Write-Ok "Backup complete!"
    Write-Host ""
    Write-Host "  Archive:  $tarFile ($sizeKB KB)" -ForegroundColor White
    Write-Host "  Checksum: $checksumFile" -ForegroundColor White
    Write-Host "  Manifest: $manifestFile" -ForegroundColor White
    Write-Host "  SHA-256:  $hash" -ForegroundColor DarkGray
    Write-Host ""
    Write-Warn "Store backups securely - they contain raw cryptographic key material."
    Write-Host ""
}

# ===== RESTORE =====

function Invoke-Restore {
    Write-Host ""
    Write-Host "  Citadel Restore" -ForegroundColor White
    Write-Host "  ===============" -ForegroundColor DarkGray
    Write-Host ""

    if (-not $BackupFile) {
        Write-Err "Specify a backup file: -BackupFile <path>"
        Write-Host ""
        Invoke-List
        exit 1
    }

    if (-not (Test-Path $BackupFile)) {
        $tryPath = Join-Path $BackupDir $BackupFile
        if (Test-Path $tryPath) {
            $BackupFile = $tryPath
        } else {
            Write-Err "Backup file not found: $BackupFile"
            exit 1
        }
    }

    $checksumPath = $BackupFile -replace '\.tar\.gz$', '.sha256'
    if (Test-Path $checksumPath) {
        Write-Status "Verifying backup integrity..."
        $expectedHash = ((Get-Content $checksumPath -First 1) -split "\s+")[0].Trim()
        $actualHash = Get-FileHash256 $BackupFile
        if ($actualHash -ne $expectedHash) {
            Write-Err "CHECKSUM MISMATCH! Backup may be corrupted. Aborting."
            Write-Err "  Expected: $expectedHash"
            Write-Err "  Actual:   $actualHash"
            exit 1
        }
        Write-Ok "Checksum verified"
    } else {
        Write-Warn "No checksum file found - skipping integrity check"
    }

    if (Test-ContainerRunning $ContainerName) {
        Write-Err "Container '$ContainerName' is running!"
        Write-Err "Stop it first: docker compose -f docker-compose-production.yml stop citadel-api"
        exit 1
    }

    Write-Host ""
    Write-Warn "THIS WILL OVERWRITE ALL CURRENT KEY MATERIAL."
    Write-Warn "Keys not in this backup will be PERMANENTLY LOST."
    Write-Host ""
    $confirm = Read-Host "  Type RESTORE to confirm"
    if ($confirm -ne "RESTORE") {
        Write-Status "Restore cancelled."
        exit 0
    }

    Write-Status "Creating safety backup of current state..."
    $safetyDir = Join-Path $BackupDir "pre-restore-$(Get-BackupTimestamp)"
    New-Item -ItemType Directory -Path $safetyDir -Force | Out-Null

    docker compose -f docker-compose-production.yml start citadel-api 2>$null
    Start-Sleep -Seconds 5
    docker exec $ContainerName sh -c "tar czf /tmp/pre-restore.tar.gz -C $DataPath ." 2>$null
    docker cp "${ContainerName}:/tmp/pre-restore.tar.gz" (Join-Path $safetyDir "pre-restore.tar.gz") 2>$null
    docker exec $ContainerName rm -f /tmp/pre-restore.tar.gz 2>$null
    docker compose -f docker-compose-production.yml stop citadel-api 2>$null
    Start-Sleep -Seconds 3

    if (Test-Path (Join-Path $safetyDir "pre-restore.tar.gz")) {
        Write-Ok "Safety backup saved to $safetyDir"
    } else {
        Write-Warn "Could not create safety backup - proceeding anyway"
    }

    Write-Status "Restoring backup..."
    docker compose -f docker-compose-production.yml start citadel-api 2>$null
    Start-Sleep -Seconds 5

    docker cp $BackupFile "${ContainerName}:/tmp/citadel-restore.tar.gz"
    docker exec $ContainerName sh -c "rm -rf ${DataPath}/keys/* ${DataPath}/api-keys.json ${DataPath}/citadel-audit.jsonl 2>/dev/null; tar xzf /tmp/citadel-restore.tar.gz -C ${DataPath}; rm -f /tmp/citadel-restore.tar.gz"

    if ($LASTEXITCODE -ne 0) {
        Write-Err "Restore failed! Safety backup is at: $safetyDir"
        exit 1
    }

    Write-Status "Restarting Citadel..."
    docker compose -f docker-compose-production.yml restart citadel-api
    Start-Sleep -Seconds 5

    Write-Status "Verifying restored system..."
    try {
        $raw = docker exec $ContainerName curl -sf http://localhost:3000/health 2>$null
        $check = $raw | ConvertFrom-Json
        if ($check.status -eq "ok") {
            Write-Ok "Health check passed"
        }
    } catch {
        Write-Warn "Health check did not pass - check container logs"
    }

    Write-Host ""
    Write-Ok "Restore complete!"
    Write-Warn "Verify your API keys still work - api-keys.json was restored from backup."
    Write-Host ""
}

# ===== LIST =====

function Invoke-List {
    Write-Host ""
    Write-Host "  Available Backups" -ForegroundColor White
    Write-Host "  =================" -ForegroundColor DarkGray
    Write-Host ""

    if (-not (Test-Path $BackupDir)) {
        Write-Status "No backup directory found at $BackupDir"
        return
    }

    $backups = Get-ChildItem -Path $BackupDir -Filter "citadel-backup-*.tar.gz" -File | Sort-Object Name -Descending

    if ($backups.Count -eq 0) {
        Write-Status "No backups found in $BackupDir"
        Write-Host "  Create one: .\Backup-Citadel.ps1 backup" -ForegroundColor DarkGray
        Write-Host ""
        return
    }

    foreach ($b in $backups) {
        $sizeKB = [math]::Round($b.Length / 1024, 1)
        $date = $b.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
        $cPath = $b.FullName -replace '\.tar\.gz$', '.sha256'
        $verified = "no checksum"
        if (Test-Path $cPath) { $verified = "checksum ok" }

        Write-Host "  $($b.Name)" -ForegroundColor White -NoNewline
        Write-Host "  ${sizeKB} KB | $date | $verified" -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host "  Total: $($backups.Count) backup(s)" -ForegroundColor DarkGray
    Write-Host ""
}

# ===== VERIFY =====

function Invoke-Verify {
    Write-Host ""
    Write-Host "  Citadel Backup Verify" -ForegroundColor White
    Write-Host "  =====================" -ForegroundColor DarkGray
    Write-Host ""

    if (-not $BackupFile) {
        Write-Err "Specify a backup file: -BackupFile <path>"
        exit 1
    }

    if (-not (Test-Path $BackupFile)) {
        $tryPath = Join-Path $BackupDir $BackupFile
        if (Test-Path $tryPath) {
            $BackupFile = $tryPath
        } else {
            Write-Err "Backup file not found: $BackupFile"
            exit 1
        }
    }

    $size = (Get-Item $BackupFile).Length
    $sizeKB = [math]::Round($size / 1024, 1)
    Write-Status "File: $BackupFile ($sizeKB KB)"

    Write-Status "Computing SHA-256..."
    $actualHash = Get-FileHash256 $BackupFile
    Write-Status "SHA-256: $actualHash"

    $checksumPath = $BackupFile -replace '\.tar\.gz$', '.sha256'
    if (Test-Path $checksumPath) {
        $expectedHash = ((Get-Content $checksumPath -First 1) -split "\s+")[0].Trim()
        if ($actualHash -eq $expectedHash) {
            Write-Ok "Checksum MATCHES"
        } else {
            Write-Err "Checksum MISMATCH!"
            Write-Err "  Expected: $expectedHash"
            Write-Err "  Actual:   $actualHash"
            exit 1
        }
    } else {
        Write-Warn "No .sha256 file found - cannot verify"
    }

    $manifestPath = $BackupFile -replace '\.tar\.gz$', '.manifest'
    if (Test-Path $manifestPath) {
        Write-Host ""
        Write-Status "Manifest:"
        Get-Content $manifestPath | ForEach-Object {
            Write-Host "    $_" -ForegroundColor DarkGray
        }
    }

    Write-Host ""
    Write-Ok "Verification complete"
    Write-Host ""
}

# ===== DISPATCH =====

switch ($Action) {
    "backup"  { Invoke-Backup }
    "restore" { Invoke-Restore }
    "list"    { Invoke-List }
    "verify"  { Invoke-Verify }
}

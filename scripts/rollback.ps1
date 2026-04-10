param(
  [ValidateSet("checkpoint", "rollback")]
  [string]$Action = "checkpoint",
  [string]$Snapshot = ""
)

$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $root

$stateDir = Join-Path $root ".rollback"
if (-not (Test-Path $stateDir)) {
  New-Item -ItemType Directory -Path $stateDir | Out-Null
}

function Get-ServiceImageDigest {
  param([string]$Service)
  $containerId = docker compose ps -q $Service
  if (-not $containerId) {
    throw "No running container found for service '$Service'."
  }
  $digest = docker inspect --format '{{.Image}}' $containerId
  if (-not $digest) {
    throw "Unable to inspect image digest for service '$Service'."
  }
  return $digest.Trim()
}

function Create-Checkpoint {
  $ts = Get-Date -Format "yyyyMMdd-HHmmss"
  $snapshotId = "snapshot-$ts"
  $snapshotDir = Join-Path $stateDir $snapshotId
  New-Item -ItemType Directory -Path $snapshotDir | Out-Null

  $envPath = Join-Path $root ".env"
  $envBackup = ""
  if (Test-Path $envPath) {
    $envBackup = Join-Path $snapshotDir ".env.backup"
    Copy-Item $envPath $envBackup -Force
  }

  $services = @("backend", "frontend", "nginx")
  $serviceMap = @{}
  foreach ($service in $services) {
    $digest = Get-ServiceImageDigest -Service $service
    $rollbackTag = "soc-platform-${service}:rollback-$ts"
    docker image tag $digest $rollbackTag
    if ($LASTEXITCODE -ne 0) {
      throw "Failed to create rollback image tag for service '$service'"
    }
    $serviceMap[$service] = @{
      digest = $digest
      rollback_tag = $rollbackTag
      latest_tag = "soc-platform-${service}:latest"
    }
  }

  $metadata = @{
    snapshot = $snapshotId
    created_at = (Get-Date).ToString("o")
    env_backup = $envBackup
    services = $serviceMap
  }

  $metaPath = Join-Path $snapshotDir "snapshot.json"
  $metadata | ConvertTo-Json -Depth 8 | Set-Content $metaPath

  Write-Host "Checkpoint created: $snapshotId"
  Write-Host "Metadata: $metaPath"
}

function Select-LatestSnapshot {
  $dirs = Get-ChildItem -Path $stateDir -Directory | Where-Object { $_.Name -like "snapshot-*" } | Sort-Object LastWriteTime -Descending
  if (-not $dirs -or $dirs.Count -eq 0) {
    throw "No rollback snapshots found in $stateDir"
  }
  return $dirs[0].Name
}

function Restore-Checkpoint {
  param([string]$SnapshotId)

  if (-not $SnapshotId) {
    $SnapshotId = Select-LatestSnapshot
  }

  $snapshotDir = Join-Path $stateDir $SnapshotId
  $metaPath = Join-Path $snapshotDir "snapshot.json"
  if (-not (Test-Path $metaPath)) {
    throw "Snapshot metadata not found: $metaPath"
  }

  $meta = Get-Content $metaPath -Raw | ConvertFrom-Json

  if ($meta.env_backup -and (Test-Path $meta.env_backup)) {
    Copy-Item $meta.env_backup (Join-Path $root ".env") -Force
    Write-Host "Restored .env from snapshot"
  }

  foreach ($property in $meta.services.PSObject.Properties) {
    $serviceName = $property.Name
    $serviceInfo = $property.Value
    $rollbackTag = $serviceInfo.rollback_tag
    $latestTag = $serviceInfo.latest_tag

    $exists = docker image inspect $rollbackTag *> $null
    if ($LASTEXITCODE -ne 0) {
      throw "Rollback image tag not found: $rollbackTag"
    }

    docker image tag $rollbackTag $latestTag
    if ($LASTEXITCODE -ne 0) {
      throw "Failed to retag rollback image $rollbackTag to $latestTag"
    }
    Write-Host "Retagged $rollbackTag -> $latestTag"
  }

  docker compose up -d --no-build
  Write-Host "Rollback applied from snapshot: $SnapshotId"
}

if ($Action -eq "checkpoint") {
  Create-Checkpoint
} else {
  Restore-Checkpoint -SnapshotId $Snapshot
}

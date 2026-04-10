param(
  [string]$Version = "v1.0.0",
  [switch]$PreRelease,
  [string]$BaseUrl = "http://localhost/api"
)

$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $root

function Assert-VersionFormat {
  param([string]$VersionValue)
  if ($VersionValue -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+([-.][A-Za-z0-9]+)?$') {
    throw "Invalid version format: $VersionValue. Expected vMAJOR.MINOR.PATCH"
  }
}

function Test-GitTagExists {
  param([string]$TagName)

  $null = git rev-parse --is-inside-work-tree 2>&1
  if ($LASTEXITCODE -ne 0) {
    Write-Host "git repository not detected here; skipping local tag-exists check"
    return $false
  }

  $null = git rev-parse $TagName 2>&1
  return ($LASTEXITCODE -eq 0)
}

Write-Host "[1/5] Validating release tag format"
Assert-VersionFormat -VersionValue $Version

Write-Host "[2/5] Validating local quick checks"
pwsh -ExecutionPolicy Bypass -File .\scripts\quick-check.ps1
if ($LASTEXITCODE -ne 0) {
  throw "quick-check failed"
}

Write-Host "[3/5] Running full preflight"
pwsh -ExecutionPolicy Bypass -File .\scripts\preflight-release.ps1 -BaseUrl $BaseUrl
if ($LASTEXITCODE -ne 0) {
  throw "preflight-release failed"
}

Write-Host "[4/5] Simulating release-tag workflow inputs"
$tagExists = Test-GitTagExists -TagName $Version
if ($tagExists) {
  throw "Tag already exists locally: $Version"
}

Write-Host "[5/5] Dry-run summary"
[ordered]@{
  dry_run = $true
  version = $Version
  prerelease = [bool]$PreRelease
  quick_check = "passed"
  preflight = "passed"
  release_tag_workflow = ".github/workflows/release-tag.yml"
  next_action = "Run workflow_dispatch for release-tag.yml with version=$Version"
} | ConvertTo-Json -Depth 5

param(
  [string]$BaseUrl = "http://localhost/api",
  [string]$AdminToken = ""
)

$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $root

Write-Host "[1/4] Running fast structural checks"
pwsh -ExecutionPolicy Bypass -File .\scripts\quick-check.ps1
if ($LASTEXITCODE -ne 0) {
  throw "quick-check failed"
}

Write-Host "[2/4] Running release verification gate"
$verifyArgs = @(
  "-ExecutionPolicy", "Bypass",
  "-File", ".\scripts\release-verify-ci.ps1",
  "-BaseUrl", $BaseUrl
)
if ($AdminToken) {
  $verifyArgs += @("-AdminToken", $AdminToken)
}
pwsh @verifyArgs
if ($LASTEXITCODE -ne 0) {
  throw "release-verify-ci failed"
}

Write-Host "[3/4] Capturing runtime health snapshot"
$health = Invoke-RestMethod -Uri "$BaseUrl/health"
$warnings = @($health.security_warnings)

Write-Host "[4/4] Post-release summary"
[ordered]@{
  post_release = $true
  service = $health.service
  status = $health.status
  security_warning_count = $warnings.Count
  timestamp = $health.ts
  next_action = "Monitor nightly-resilience workflow artifacts for drift signals"
} | ConvertTo-Json -Depth 5

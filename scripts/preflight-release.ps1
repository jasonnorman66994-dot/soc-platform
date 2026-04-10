param(
  [string]$BaseUrl = "http://localhost/api",
  [string]$AdminToken = ""
)

$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $root

Write-Host "[1/4] Creating rollback checkpoint"
pwsh -ExecutionPolicy Bypass -File .\scripts\rollback.ps1 -Action checkpoint
if ($LASTEXITCODE -ne 0) {
  throw "rollback checkpoint failed"
}

Write-Host "[2/4] Running release CI verification"
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
  throw "release verification failed"
}

Write-Host "[3/4] Running demo-day scenario"
$demoArgs = @(
  "-ExecutionPolicy", "Bypass",
  "-File", ".\scripts\demo-day.ps1",
  "-BaseUrl", $BaseUrl
)
if ($AdminToken) {
  $demoArgs += @("-AdminToken", $AdminToken)
}
pwsh @demoArgs
if ($LASTEXITCODE -ne 0) {
  throw "demo-day flow failed"
}

Write-Host "[4/4] Preflight complete"
Write-Host "Release preflight passed."

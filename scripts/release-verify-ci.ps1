param(
  [string]$BaseUrl = "http://localhost/api",
  [string]$AdminToken = ""
)

$ErrorActionPreference = "Stop"

$verifyScript = Join-Path $PSScriptRoot "release-verify.ps1"
if (-not (Test-Path $verifyScript)) {
  throw "Missing script: $verifyScript"
}

$jsonOutput = & $verifyScript -BaseUrl $BaseUrl -AdminToken $AdminToken -NoExitOnFail
if (-not $jsonOutput) {
  throw "release-verify produced no output"
}

$result = $jsonOutput | ConvertFrom-Json
$checks = @($result.checks)
$failed = @($checks | Where-Object { -not $_.ok })
$passedCount = @($checks | Where-Object { $_.ok }).Count
$totalCount = $checks.Count

Write-Host "release-verify summary:"
Write-Host "  passed: $($result.passed)"
Write-Host "  checks: $passedCount/$totalCount"
if ($failed.Count -gt 0) {
  Write-Host "  failures:"
  foreach ($f in $failed) {
    Write-Host "    - $($f.name): $($f.detail)"
  }
  exit 1
}

Write-Host "  failures: none"
exit 0

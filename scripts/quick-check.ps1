$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $root

function Assert-PathExists {
  param([string]$PathToCheck)
  if (-not (Test-Path $PathToCheck)) {
    throw "Missing required file: $PathToCheck"
  }
}

function Test-PowerShellSyntax {
  param([string]$ScriptPath)

  $tokens = $null
  $errors = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$errors)
  if ($errors -and $errors.Count -gt 0) {
    $messages = $errors | ForEach-Object { $_.Message }
    throw ("PowerShell parse error in " + $ScriptPath + ": " + ($messages -join '; '))
  }
}

Write-Host "[1/4] Validating required files"
$required = @(
  ".env.example",
  "docker-compose.yml",
  "scripts/demo-day.ps1",
  "scripts/release-verify.ps1",
  "scripts/release-verify-ci.ps1",
  "scripts/preflight-release.ps1",
  "scripts/rollback.ps1"
)
$required | ForEach-Object { Assert-PathExists -PathToCheck $_ }

Write-Host "[2/4] Validating PowerShell script syntax"
$scripts = Get-ChildItem -Path (Join-Path $root "scripts") -Filter "*.ps1" -File
foreach ($script in $scripts) {
  Test-PowerShellSyntax -ScriptPath $script.FullName
}

Write-Host "[3/4] Validating docker compose configuration"
docker compose config *> $null
if ($LASTEXITCODE -ne 0) {
  throw "docker compose config failed"
}

Write-Host "[4/4] Quick checks complete"
Write-Host "All quick checks passed."

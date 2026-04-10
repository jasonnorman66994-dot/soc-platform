param(
  [string]$BaseUrl = "http://localhost/api",
  [string]$AdminToken = "",
  [string]$SourceCountry = "UK",
  [string]$DestinationCountry = "US"
)

$ErrorActionPreference = "Stop"

if (-not $AdminToken) {
  $envFile = Join-Path $PSScriptRoot "..\.env"
  if (Test-Path $envFile) {
    $tokenLine = Get-Content $envFile | Where-Object { $_ -match '^INTERNAL_ADMIN_TOKEN=' } | Select-Object -First 1
    if ($tokenLine) {
      $AdminToken = ($tokenLine -split '=', 2)[1].Trim()
    }
  }
}

if (-not $AdminToken) {
  throw "Admin token not provided. Pass -AdminToken or set INTERNAL_ADMIN_TOKEN in .env"
}

Write-Host "[1/5] Creating admin session..."
$admin = Invoke-RestMethod -Uri "$BaseUrl/admin/session" -Method POST -ContentType "application/json" -Body (@{admin_token=$AdminToken} | ConvertTo-Json)
$adminHeaders = @{ Authorization = "Bearer $($admin.access_token)" }

Write-Host "[2/5] Resetting demo tenant..."
$reset = Invoke-RestMethod -Uri "$BaseUrl/admin/demo/reset" -Method POST -Headers $adminHeaders -ContentType "application/json" -Body (@{regenerate_api_key=$true} | ConvertTo-Json)

Write-Host "[3/5] Running showcase attack chain..."
$showcase = Invoke-RestMethod -Uri "$BaseUrl/admin/demo/run-showcase" -Method POST -Headers $adminHeaders -ContentType "application/json" -Body (@{source_country=$SourceCountry;destination_country=$DestinationCountry;user_id='demo.user'} | ConvertTo-Json)

Write-Host "[4/5] Collecting metrics..."
$funnel = Invoke-RestMethod -Uri "$BaseUrl/admin/funnel" -Headers $adminHeaders
$webhooks = Invoke-RestMethod -Uri "$BaseUrl/admin/webhooks/metrics?limit=20" -Headers $adminHeaders

Write-Host "[5/5] Demo day summary"
[ordered]@{
  demo_tenant = $reset.tenant_id
  api_key_rotated = [bool]$reset.api_key
  timeline_steps = ($showcase.timeline | Measure-Object).Count
  outcomes = ($showcase.outcomes | Measure-Object).Count
  total_leads = $funnel.total_leads
  converted_signups = $funnel.converted_signups
  webhook_summary_rows = ($webhooks.summary_last_7_days | Measure-Object).Count
} | ConvertTo-Json -Depth 8

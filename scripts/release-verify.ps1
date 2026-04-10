param(
  [string]$BaseUrl = "http://localhost/api",
  [string]$AdminToken = "",
  [switch]$NoExitOnFail
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

$checks = @()
function Add-Check {
  param(
    [string]$Name,
    [bool]$Ok,
    [string]$Detail
  )
  $script:checks += [pscustomobject]@{ name = $Name; ok = $Ok; detail = $Detail }
}

try {
  $health = Invoke-RestMethod -Uri "$BaseUrl/health"
  $warnings = @($health.security_warnings)
  Add-Check -Name "health" -Ok ($health.status -eq "ok") -Detail "status=$($health.status)"
  Add-Check -Name "security_warnings" -Ok ($warnings.Count -eq 0) -Detail "count=$($warnings.Count)"
} catch {
  Add-Check -Name "health" -Ok $false -Detail $_.Exception.Message
  Add-Check -Name "security_warnings" -Ok $false -Detail "health call failed"
}

$adminHeaders = $null
try {
  $session = Invoke-RestMethod -Uri "$BaseUrl/admin/session" -Method POST -ContentType "application/json" -Body (@{admin_token=$AdminToken} | ConvertTo-Json)
  $adminHeaders = @{ Authorization = "Bearer $($session.access_token)" }
  $refreshToken = $session.refresh_token
  Add-Check -Name "admin_session_create" -Ok $true -Detail "created"

  $refreshed = Invoke-RestMethod -Uri "$BaseUrl/admin/session/refresh" -Method POST -ContentType "application/json" -Body (@{refresh_token=$refreshToken} | ConvertTo-Json)
  if ($refreshed.access_token) {
    $adminHeaders = @{ Authorization = "Bearer $($refreshed.access_token)" }
    $refreshToken = $refreshed.refresh_token
    Add-Check -Name "admin_session_refresh" -Ok $true -Detail "refreshed"
  } else {
    Add-Check -Name "admin_session_refresh" -Ok $false -Detail "missing access token"
  }

  Invoke-RestMethod -Uri "$BaseUrl/admin/session/revoke" -Method POST -ContentType "application/json" -Body (@{refresh_token=$refreshToken} | ConvertTo-Json) | Out-Null
  Add-Check -Name "admin_session_revoke" -Ok $true -Detail "revoked"
} catch {
  Add-Check -Name "admin_session_flow" -Ok $false -Detail $_.Exception.Message
}

try {
  $session2 = Invoke-RestMethod -Uri "$BaseUrl/admin/session" -Method POST -ContentType "application/json" -Body (@{admin_token=$AdminToken} | ConvertTo-Json)
  $adminHeaders = @{ Authorization = "Bearer $($session2.access_token)" }

  $funnel = Invoke-RestMethod -Uri "$BaseUrl/admin/funnel" -Headers $adminHeaders
  Add-Check -Name "funnel_metrics" -Ok $true -Detail "total_leads=$($funnel.total_leads)"

  $tenantFunnel = Invoke-RestMethod -Uri "$BaseUrl/admin/funnel/tenants" -Headers $adminHeaders
  $tenantCount = @($tenantFunnel.tenants).Count
  Add-Check -Name "funnel_tenant_breakdown" -Ok $true -Detail "tenants=$tenantCount"

  $webhooks = Invoke-RestMethod -Uri "$BaseUrl/admin/webhooks/metrics?limit=20" -Headers $adminHeaders
  $summaryRows = @($webhooks.summary_last_7_days).Count
  Add-Check -Name "webhook_metrics" -Ok $true -Detail "summary_rows=$summaryRows"
} catch {
  Add-Check -Name "admin_metrics_flow" -Ok $false -Detail $_.Exception.Message
}

$failed = @($checks | Where-Object { -not $_.ok })
$result = [ordered]@{
  timestamp = (Get-Date).ToString("o")
  base_url = $BaseUrl
  passed = ($failed.Count -eq 0)
  checks = $checks
}

$result | ConvertTo-Json -Depth 8

if ($failed.Count -gt 0 -and -not $NoExitOnFail) {
  exit 1
}

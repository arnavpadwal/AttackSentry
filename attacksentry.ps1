param(
  [ValidateSet("start", "stop", "restart", "status", "logs", "update", "doctor")]
  [string]$Action = "start",
  [string]$Service = ""
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ComposeDir = Join-Path $RootDir "deploy\docker-compose"
$ComposeFile = Join-Path $ComposeDir "docker-compose.yml"
$EnvFile = Join-Path $ComposeDir ".env"

function New-RandomHex([int]$Bytes = 32) {
  $data = New-Object byte[] $Bytes
  [Security.Cryptography.RandomNumberGenerator]::Fill($data)
  return [Convert]::ToHexString($data).ToLowerInvariant()
}

function Ensure-Config {
  if (-not (Test-Path $EnvFile)) {
    $adminPassword = New-RandomHex 16
    $contents = @"
SENTRY_SECRET_KEY=$(New-RandomHex 32)
SENTRY_BOOTSTRAP_ADMIN_PASSWORD=$adminPassword
POSTGRES_PASSWORD=$(New-RandomHex 24)
POSTGRES_USER=attacksentry
POSTGRES_DB=attacksentry
NATS_USER=attacksentry
NATS_PASSWORD=$(New-RandomHex 24)
NATS_BIND_HOST=127.0.0.1
SENTRY_COOKIE_SECURE=false
SENTRY_LLM_PROVIDER=none
SENTRY_LLM_BASE_URL=http://host.docker.internal:1234
SENTRY_LLM_MODEL=default
SENTRY_BASELINE_HOURS=72
SENTRY_RETENTION_DAYS=30
FRONTEND_PORT=8080
"@
    Set-Content -Path $EnvFile -Value $contents -Encoding UTF8
    Write-Host "Secure configuration created. Admin username: admin"
    Write-Host "Initial admin password: $adminPassword" -ForegroundColor Yellow
    Write-Host "Save this password now; it is shown only during setup."
  } elseif (-not (Select-String -Quiet -Path $EnvFile -Pattern '^NATS_PASSWORD=')) {
    $existing = Get-Content $EnvFile -Raw
    $upgrade = "`n"
    if ($existing -notmatch '(?m)^NATS_USER=') { $upgrade += "NATS_USER=attacksentry`n" }
    $upgrade += "NATS_PASSWORD=$(New-RandomHex 24)`n"
    if ($existing -notmatch '(?m)^NATS_BIND_HOST=') { $upgrade += "NATS_BIND_HOST=127.0.0.1`n" }
    Add-Content -Path $EnvFile -Value $upgrade -Encoding UTF8
    Write-Host "Added NATS authentication to the existing configuration; existing secrets were preserved."
  }
}

function Compose { docker compose --project-directory $ComposeDir --env-file $EnvFile -f $ComposeFile @args }

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw "Install Docker Desktop, then run this script again." }
docker compose version | Out-Null

switch ($Action) {
  "start" { Ensure-Config; Compose up -d --build; Write-Host "AttackSentry: http://localhost:8080" }
  "stop" { Compose down }
  "restart" { Ensure-Config; Compose restart; Write-Host "AttackSentry: http://localhost:8080" }
  "status" { Compose ps }
  "logs" { if ($Service) { Compose logs --follow --tail=200 $Service } else { Compose logs --follow --tail=200 } }
  "update" { Ensure-Config; Compose pull; Compose up -d --build }
  "doctor" { Ensure-Config; docker --version; docker compose version; Compose config --quiet; Compose ps; Write-Host "Configuration is valid." }
}

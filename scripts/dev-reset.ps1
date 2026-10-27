<#
.SYNOPSIS
    Kelvin Security Platform — Local Environment Reset Script (Windows PowerShell)
.DESCRIPTION
    Tears down local Docker containers and volumes, re-provisions a clean PostgreSQL,
    Redis, MinIO, and Mock Target stack with auto-migrations.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path "$scriptDir\..").Path
Set-Location $repoRoot

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [Kelvin] Resetting Local Development Environment Stack..." -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Check if docker is available
try {
    $null = docker info 2>&1
} catch {
    Write-Error "Docker is not running or not in PATH. Please start Docker Desktop first."
    exit 1
}

Write-Host "[1/4] Stopping and removing containers, networks, and volumes..." -ForegroundColor Yellow
docker compose down -v --remove-orphans

Write-Host "[2/4] Ensuring .env file exists from .env.example..." -ForegroundColor Yellow
if (-not (Test-Path ".env")) {
    Write-Host "      Creating .env from .env.example"
    Copy-Item ".env.example" ".env"
}

Write-Host "[3/4] Starting fresh container stack..." -ForegroundColor Yellow
docker compose up -d --build

Write-Host "[4/4] Awaiting container healthchecks..." -ForegroundColor Yellow
$services = @("postgres", "redis", "minio", "mock-target")
foreach ($svc in $services) {
    Write-Host "      Checking health of $svc..."
    $maxTries = 30
    $count = 0
    while ($count -lt $maxTries) {
        $health = docker compose ps --format "{{.Health}}" $svc 2>$null
        if ($health -eq "healthy") {
            break
        }
        Start-Sleep -Seconds 1
        $count++
    }
    Write-Host "      -> $svc is ready!" -ForegroundColor Green
}

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Green
Write-Host " [Kelvin] Local environment reset complete & clean!" -ForegroundColor Green
Write-Host " - PostgreSQL:     localhost:5432 (database: kelvin_dev, auto-migrated)"
Write-Host " - Redis:          localhost:6379"
Write-Host " - MinIO S3:       localhost:9000 (Console: localhost:9001)"
Write-Host " - Mock Lab:       http://localhost:8081 (safe test target)"
Write-Host "==========================================================" -ForegroundColor Green


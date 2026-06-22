# ──────────────────────────────────────────────────────────────
# setup_local.ps1 — CVE Monitoring App Local Dev Setup
# ──────────────────────────────────────────────────────────────
# Run this once to set up the backend for local development.
# Uses SQLite (no Docker / PostgreSQL required).
#
# Usage:
#   cd C:\Users\chaiyaphat\cve_monitoring_app\backend
#   .\setup_local.ps1

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   CVE Monitoring App - Local Backend Setup       ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# 1. Create virtual environment
if (-not (Test-Path "venv")) {
    Write-Host "► Creating Python virtual environment..." -ForegroundColor Yellow
    python -m venv venv
    Write-Host "  ✓ venv created" -ForegroundColor Green
} else {
    Write-Host "  ✓ venv already exists" -ForegroundColor Green
}

# 2. Activate venv
Write-Host "► Activating virtual environment..." -ForegroundColor Yellow
& ".\venv\Scripts\Activate.ps1"

# 3. Install dependencies
Write-Host "► Installing Python dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt --quiet
Write-Host "  ✓ Dependencies installed" -ForegroundColor Green

# 4. Ensure .env exists
if (-not (Test-Path ".env")) {
    Write-Host "► Creating default .env (SQLite mode)..." -ForegroundColor Yellow
    @"
DATABASE_URL=sqlite:///./cvedb.sqlite
SECRET_KEY=changeme-super-secret-jwt-key-32chars-min
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001
"@ | Set-Content ".env"
    Write-Host "  ✓ .env created" -ForegroundColor Green
} else {
    Write-Host "  ✓ .env already exists" -ForegroundColor Green
}

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║   Setup complete! Starting backend server...     ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  API Docs → http://localhost:8000/docs" -ForegroundColor Cyan
Write-Host "  SQLite DB → cvedb.sqlite (auto-created on first run)" -ForegroundColor Cyan
Write-Host ""

# 5. Start uvicorn
uvicorn main:app --reload --host 0.0.0.0 --port 8000

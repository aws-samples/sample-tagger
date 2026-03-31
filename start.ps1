###############################################################################
# Taggr API - Local Development Startup Script (Windows PowerShell)
#
# This script:
# 1. Creates a Python virtual environment (if not exists)
# 2. Activates the virtual environment
# 3. Installs dependencies from requirements.txt
# 4. Sets up environment variables
# 5. Starts the FastAPI server locally
###############################################################################

$ErrorActionPreference = "Stop"

Write-Host "========================================="
Write-Host "Taggr API - Local Development Setup"
Write-Host "========================================="
Write-Host ""

# Get script directory (project root)
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $SCRIPT_DIR

$API_DIR = "api"
$VENV_DIR = Join-Path $API_DIR "venv"

# Step 1: Check Python version
Write-Host "Step 1: Checking Python installation..."
Write-Host "=========================================="

$pythonCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pyVersion = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
    $pyMajor = [int](python -c "import sys; print(sys.version_info.major)")
    $pyMinor = [int](python -c "import sys; print(sys.version_info.minor)")
    if ($pyMajor -ge 3 -and $pyMinor -ge 11) {
        $pythonCmd = "python"
        Write-Host "  [ok] Found Python $pyVersion" -ForegroundColor Green
    } else {
        Write-Host "  [!] Python $pyVersion found, but 3.11+ is required" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "  [x] Python is not installed" -ForegroundColor Red
    Write-Host "  Please install Python 3.11 or higher"
    exit 1
}
Write-Host ""

# Step 2: Create virtual environment
Write-Host "Step 2: Setting up virtual environment..."
Write-Host "=========================================="

if (Test-Path $VENV_DIR) {
    Write-Host "  [i] Virtual environment already exists at: $VENV_DIR" -ForegroundColor Yellow
} else {
    Write-Host "  [i] Creating virtual environment..." -ForegroundColor Yellow
    & $pythonCmd -m venv $VENV_DIR
    Write-Host "  [ok] Virtual environment created at: $VENV_DIR" -ForegroundColor Green
}
Write-Host ""

# Step 3: Activate virtual environment
Write-Host "Step 3: Activating virtual environment..."
Write-Host "=========================================="

$activateScript = Join-Path $VENV_DIR "Scripts\Activate.ps1"
if (Test-Path $activateScript) {
    & $activateScript
    Write-Host "  [ok] Virtual environment activated" -ForegroundColor Green
} else {
    Write-Host "  [x] Activation script not found at: $activateScript" -ForegroundColor Red
    exit 1
}
Write-Host "  Python: $(Get-Command python | Select-Object -ExpandProperty Source)"
Write-Host "  Version: $(python --version)"
Write-Host ""

# Step 4: Install/Update dependencies
Write-Host "Step 4: Installing dependencies..."
Write-Host "=========================================="

$requirementsPath = Join-Path $API_DIR "requirements.txt"
if (Test-Path $requirementsPath) {
    Write-Host "  [i] Installing packages from requirements.txt..." -ForegroundColor Yellow
    pip install --upgrade pip -q
    pip install -r $requirementsPath -q
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [x] Failed to install dependencies. Check errors above." -ForegroundColor Red
        exit 1
    }
    Write-Host "  [ok] Dependencies installed successfully" -ForegroundColor Green
} else {
    Write-Host "  [x] requirements.txt not found!" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Step 5: Set environment variables
Write-Host "Step 5: Configuring environment..."
Write-Host "=========================================="

$env:DB_TYPE = "sqlite"
$env:DB_PATH = "dbstore/tagger.db"
$env:REGION = "us-east-1"
$env:MAX_WORKERS = "10"
$env:API_PORT = "3000"
$env:DISABLE_AUTH = "true"

Write-Host "  [ok] Environment variables configured:" -ForegroundColor Green
Write-Host "  DB_TYPE: $env:DB_TYPE"
Write-Host "  DB_PATH: $env:DB_PATH"
Write-Host "  REGION: $env:REGION"
Write-Host "  MAX_WORKERS: $env:MAX_WORKERS"
Write-Host "  API_PORT: $env:API_PORT"
Write-Host "  DISABLE_AUTH: $env:DISABLE_AUTH (Warning: Authentication disabled for local dev)"
Write-Host ""

# Step 6: Start FastAPI server
Write-Host "Step 6: Starting FastAPI server..."
Write-Host "=========================================="
Write-Host ""
Write-Host "  [ok] FastAPI server starting on port $env:API_PORT" -ForegroundColor Green
Write-Host ""
Write-Host "  API Endpoints:"
Write-Host "    Health Check: http://localhost:$env:API_PORT/"
Write-Host "    API Endpoint: http://localhost:$env:API_PORT/v1/ops/"
Write-Host "    API Docs:     http://localhost:$env:API_PORT/docs"
Write-Host ""
Write-Host "  Press CTRL+C to stop the server"
Write-Host "=========================================="
Write-Host ""

# Start the FastAPI server from the api directory
Set-Location $API_DIR
python -m uvicorn api_core:app --host 0.0.0.0 --port $env:API_PORT --reload

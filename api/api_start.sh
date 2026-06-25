#!/bin/bash

###############################################################################
# Taggr API - Local Development Startup Script
#
# This script:
# 1. Creates a Python virtual environment (if not exists)
# 2. Activates the virtual environment
# 3. Installs dependencies from requirements.txt
# 4. Sets up environment variables (fallbacks for config.json)
# 5. Starts the FastAPI server locally
###############################################################################

set -e  # Exit on error

# Get the directory where this script is located and move into it
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Virtual environment directory
VENV_DIR="venv"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

print_success() { echo -e "${GREEN}✓ $1${NC}"; }
print_info()    { echo -e "${YELLOW}ℹ $1${NC}"; }
print_error()   { echo -e "${RED}✗ $1${NC}"; }

echo "========================================="
echo "Taggr API - Local Development Setup"
echo "========================================="
echo ""

# Step 1: Check Python version
echo "Step 1: Checking Python installation..."
echo "========================================"
if command -v python3.11 &> /dev/null; then
    PYTHON_CMD="python3.11"
    print_success "Found Python 3.11: $(python3.11 --version)"
elif command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
    print_info "Using Python 3: $(python3 --version 2>&1 | awk '{print $2}')"
else
    print_error "Python 3 is not installed. Please install Python 3.11 or higher."
    exit 1
fi
echo ""

# Step 2: Create virtual environment
echo "Step 2: Setting up virtual environment..."
echo "=========================================="
if [ -d "$VENV_DIR" ]; then
    print_info "Virtual environment already exists at: $VENV_DIR"
else
    print_info "Creating virtual environment..."
    $PYTHON_CMD -m venv "$VENV_DIR"
    print_success "Virtual environment created at: $VENV_DIR"
fi
echo ""

# Step 3: Activate virtual environment
echo "Step 3: Activating virtual environment..."
echo "=========================================="
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    source "$VENV_DIR/Scripts/activate"
else
    source "$VENV_DIR/bin/activate"
fi
print_success "Virtual environment activated"
echo "Python: $(which python)"
echo "Version: $(python --version)"
echo ""

# Step 4: Install/Update dependencies
echo "Step 4: Installing dependencies..."
echo "=========================================="
if [ -f "requirements.txt" ]; then
    print_info "Installing packages from requirements.txt..."
    pip install --upgrade pip -q
    pip install -r requirements.txt -q
    print_success "Dependencies installed successfully"
else
    print_error "requirements.txt not found!"
    exit 1
fi
echo ""

# Step 5: Set environment variables
# These are fallbacks used by class_configuration.py when a key is not
# present in ../config.json
echo "Step 5: Configuring environment..."
echo "=========================================="

# AWS Configuration
export REGION="${REGION:-us-east-1}"
export IAM_ROOT_ROLE="${IAM_ROOT_ROLE:-IAMRootRoleTaggerSolution}"
export IAM_CHILD_ROLE="${IAM_CHILD_ROLE:-IAMChildRoleTaggerSolution}"
export MAX_WORKERS="${MAX_WORKERS:-10}"

# Database Configuration (SQLite)
export DB_PATH="${DB_PATH:-../dbstore/tagger.db}"

# API Configuration
export API_PORT="${API_PORT:-3000}"

# Disable authentication for local development
export DISABLE_AUTH="${DISABLE_AUTH:-true}"

print_success "Environment variables configured:"
echo "  REGION: $REGION"
echo "  IAM_ROOT_ROLE: $IAM_ROOT_ROLE"
echo "  IAM_CHILD_ROLE: $IAM_CHILD_ROLE"
echo "  MAX_WORKERS: $MAX_WORKERS"
echo "  DB_PATH: $DB_PATH"
echo "  API_PORT: $API_PORT"
echo "  DISABLE_AUTH: $DISABLE_AUTH (⚠️  Authentication disabled for local dev)"
echo ""

# Step 6: Start FastAPI server
echo "Step 6: Starting FastAPI server..."
echo "=========================================="
echo ""
print_success "FastAPI server starting on port $API_PORT"
echo ""
echo "API Endpoints:"
echo "  Health Check: http://localhost:$API_PORT/v1/health"
echo "  API Endpoint: http://localhost:$API_PORT/v1/ops/"
echo "  API Docs:     http://localhost:$API_PORT/docs"
echo ""
echo "Press CTRL+C to stop the server"
echo "=========================================="
echo ""

# Start the FastAPI server with auto-reload.
# Run from the api directory so flat imports resolve correctly.
python -m uvicorn api_core:app --host 0.0.0.0 --port "$API_PORT" --reload

# Deactivate virtual environment on exit
deactivate 2>/dev/null || true

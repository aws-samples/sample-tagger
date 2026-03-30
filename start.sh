#!/bin/bash

###############################################################################
# Taggr API - Local Development Startup Script
#
# This script:
# 1. Creates a Python virtual environment (if not exists)
# 2. Activates the virtual environment
# 3. Installs dependencies from requirements.txt
# 4. Sets up environment variables
# 5. Starts the FastAPI server locally
###############################################################################

set -e  # Exit on error

echo "========================================="
echo "Taggr API - Local Development Setup"
echo "========================================="
echo ""

# Get the directory where this script is located (project root)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# API and virtual environment directories
API_DIR="api"
VENV_DIR="$API_DIR/venv"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Step 1: Check Python version
echo "Step 1: Checking Python installation..."
echo "========================================"

if command -v python3.11 &> /dev/null; then
    PYTHON_CMD="python3.11"
    print_success "Found Python 3.11: $(python3.11 --version)"
elif command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    PYTHON_CMD="python3"
    print_info "Using Python 3: $PYTHON_VERSION"
else
    print_error "Python 3 is not installed"
    echo "Please install Python 3.11 or higher"
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
    $PYTHON_CMD -m venv $VENV_DIR
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

if [ -f "$API_DIR/requirements.txt" ]; then
    print_info "Installing packages from requirements.txt..."
    pip install --upgrade pip -q
    pip install -r "$API_DIR/requirements.txt" -q
    print_success "Dependencies installed successfully"
else
    print_error "requirements.txt not found!"
    exit 1
fi
echo ""

# Step 5: Set environment variables
echo "Step 5: Configuring environment..."
echo "=========================================="

export DB_TYPE="sqlite"
export DB_PATH="dbstore/tagger.db"
export REGION="us-east-1"
export MAX_WORKERS="10"
export API_PORT="3000"
export DISABLE_AUTH="true"

print_success "Environment variables configured:"
echo "  DB_TYPE: $DB_TYPE"
echo "  DB_PATH: $DB_PATH"
echo "  REGION: $REGION"
echo "  MAX_WORKERS: $MAX_WORKERS"
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
echo "  Health Check: http://localhost:$API_PORT/"
echo "  API Endpoint: http://localhost:$API_PORT/v1/ops/"
echo "  API Docs:     http://localhost:$API_PORT/docs"
echo ""
echo "Press CTRL+C to stop the server"
echo "=========================================="
echo ""

# Start the FastAPI server from the api directory so imports work
cd "$API_DIR"
python -m uvicorn api_core:app --host 0.0.0.0 --port $API_PORT --reload

# Deactivate virtual environment on exit
deactivate 2>/dev/null || true

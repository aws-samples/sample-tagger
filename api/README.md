# Taggr API - FastAPI Application

This directory contains the FastAPI application that replaces the API Gateway + Lambda architecture.

## Quick Start

### Automated Setup (Recommended)

```bash
./api_start.sh
```

This script will:
1. Create a Python virtual environment (if not exists)
2. Activate the virtual environment
3. Install all dependencies from requirements.txt
4. Configure environment variables
5. Start the FastAPI server on port 3000

### Manual Setup

```bash
# Create virtual environment
python3.11 -m venv venv

# Activate virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables (or use aws-exports.json)
export DBHOST="your-dsql-endpoint"
export DBNAME="postgres"
export DBUSER="admin"
export DBPORT="5432"
export REGION="us-east-1"
export S3_BUCKET_MODULES="your-bucket"
export IAM_SCAN_ROLE="YourRole"
export MAX_WORKERS="10"

# Start server
python -m uvicorn api_core:app --host 0.0.0.0 --port 3000 --reload
```

## Directory Structure

```
api/
├── api_core.py           # FastAPI application (routing, auth, middleware)
├── api_functions.py      # 25 API process functions
├── class_tools.py        # DataStore and shared utilities
├── class_discovery.py    # AWSResourceDiscovery class
├── class_tagger.py       # AWSResourceTagger class
├── api_start.sh          # Development startup script
├── requirements.txt      # Python dependencies
└── README.md            # This file
```

## Key Components

### api_core.py
- FastAPI application setup
- CORS middleware configuration
- Cognito JWT authentication
- Request routing to API functions
- Error handling

### api_functions.py
- 25 API process functions (fn_01 through fn_25)
- Business logic for all API operations
- Database operations
- S3 operations
- Module management

### class_tools.py
- DataStore class (unified database operations)
- Type definitions (APIGatewayResponse, ErrorResponse)
- Constants (CORS_HEADERS, ERROR_CODES)

### class_discovery.py
- AWSResourceDiscovery class
- Multi-account, multi-region resource discovery
- Parallel processing with ThreadPoolExecutor
- Module loading from S3

### class_tagger.py
- AWSResourceTagger class
- Bulk resource tagging operations
- Cross-account tagging support
- Error tracking and reporting

## Configuration

Configuration is loaded from `../aws-exports.json` with fallback to environment variables.

Required configuration:
- DBHOST - Aurora DSQL endpoint
- DBNAME - Database name
- DBUSER - Database user
- DBPORT - Database port
- REGION - AWS region
- S3_BUCKET_MODULES - S3 bucket for modules
- IAM_SCAN_ROLE - Cross-account IAM role
- MAX_WORKERS - Number of parallel workers

### Local Development Mode

For local development without Cognito authentication, set:
```bash
export DISABLE_AUTH=true
```

This bypasses JWT token validation and uses a mock user. **Never use this in production!**

The `api_start.sh` script automatically sets `DISABLE_AUTH=true` for convenience.

## API Endpoints

- `GET /` - Health check
- `GET /docs` - Interactive API documentation (Swagger UI)
- `POST /v1/ops/` - Main API endpoint (requires authentication)

## Authentication

All API requests require a valid Cognito JWT token in the Authorization header:

```bash
curl -X POST http://localhost:3000/v1/ops/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"parameters":{"processId":"12-get-profiles"}}'
```

## Development

### Running with Auto-Reload

The `api_start.sh` script starts the server with `--reload` flag, which automatically restarts the server when code changes are detected.

### Testing

```bash
# Health check
curl http://localhost:3000/

# API test (requires valid token)
curl -X POST http://localhost:3000/v1/ops/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"parameters":{"processId":"24-get-profile-catalog"}}'
```

### Interactive API Documentation

Once the server is running, visit:
- Swagger UI: http://localhost:3000/docs
- ReDoc: http://localhost:3000/redoc

## Dependencies

See `requirements.txt` for the complete list. Key dependencies:
- fastapi - Web framework
- uvicorn - ASGI server
- psycopg2-binary - PostgreSQL driver
- boto3 - AWS SDK
- PyJWT - JWT token handling

## Troubleshooting

### Virtual Environment Issues

If you encounter issues with the virtual environment:

```bash
# Remove existing venv
rm -rf venv

# Run the script again
./api_start.sh
```

### Port Already in Use

If port 3000 is already in use, modify the `API_PORT` variable in `api_start.sh` or set it as an environment variable:

```bash
export API_PORT=8000
./api_start.sh
```

### Database Connection Issues

Verify:
- DBHOST is correct
- IAM permissions for DSQL access
- Network connectivity to DSQL endpoint

### Module Loading Issues

Verify:
- S3_BUCKET_MODULES is correct
- IAM permissions for S3 access
- Modules exist in the S3 bucket

## Migration from Lambda

This FastAPI application replaces:
- Lambda API (artifacts/lambda.api/)
- Lambda Discovery (artifacts/lambda.discovery/)
- Lambda Tagger (artifacts/lambda.tagger/)

Key differences:
- No Lambda cold starts
- Direct class instantiation (no Lambda invocation)
- Unified DataStore class
- Background threads instead of async Lambda calls
- Single codebase for all operations

## See Also

- `../docs/readme-fastapi.md` - Quick reference guide
- `../docs/deployment-guide.md` - Deployment instructions
- `../docs/migration-status.md` - Migration details
- `../.kiro/specs/api-gateway-to-fastapi-migration/` - Complete specifications

"""
FastAPI Application - Taggr API

This module contains the main FastAPI application that replaces API Gateway + Lambda.
It handles HTTP requests, authentication, and routes to the appropriate API functions.
"""

import os
import sys
import json
import logging
from typing import Dict, Any, Optional
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from class_configuration import classConfiguration
from class_loggging import classLogging

# Import API class modules
from class_api_metadata import classMetadata
from class_api_tagger import classTagger
from class_api_profiles import classProfiles
from class_api_modules import classModules
from class_tools import ERROR_CODES

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI application
app = FastAPI(
    title="Taggr API",
    version="2.0.0",
    description="AWS Resource Tagging API - FastAPI Migration"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static folder for React build
BUILD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'build')

# Mount static assets (JS, CSS) from React build
if os.path.isdir(os.path.join(BUILD_FOLDER, 'static')):
    app.mount("/static", StaticFiles(directory=os.path.join(BUILD_FOLDER, 'static')), name="static")

# Global configuration
config = None
app_logger = None
db_config = None
region = None

# Global API class instances
metadata_api = None
tagger_api = None
profiles_api = None
modules_api = None


@app.on_event("startup")
async def startup_event():
    """Initialize application on startup - No authentication."""
    global config, app_logger, db_config, region
    global metadata_api, tagger_api, profiles_api, modules_api
    
    try:
        # Load configuration
        config = classConfiguration()
        logger.info("Configuration loaded successfully")
        
        logger.warning("=" * 60)
        logger.warning("⚠️  AUTHENTICATION DISABLED")
        logger.warning("⚠️  This API has no authentication - for development only!")
        logger.warning("=" * 60)
        
        # Initialize logger
        app_logger = classLogging("taggr_api", "main")
        app_logger.write("startup", "info", "Taggr API starting up (no auth)")
        
        # Setup database configuration
        db_config = { 'path': config.get_config('DB_PATH') }
        
        region = config.get_config('REGION')
        
        # Initialize API class instances
        metadata_api = classMetadata(db_config=db_config, region=region, config=config)
        tagger_api = classTagger(db_config=db_config, region=region, config=config)
        profiles_api = classProfiles(db_config=db_config, region=region, config=config)
        modules_api = classModules(db_config=db_config, region=region, config=config)
        
        logger.info(f"Database configured: {db_config['path']}")
        logger.info(f"Region: {region}")
        logger.info("API class instances initialized")
        
        # Log frontend status
        if os.path.isdir(BUILD_FOLDER):
            logger.info(f"Frontend build found: {BUILD_FOLDER}")
        else:
            logger.warning(f"Frontend build not found at: {BUILD_FOLDER}")
        
        logger.info("Taggr API startup complete (no authentication)")
        
    except Exception as e:
        logger.error(f"Error during startup: {str(e)}")
        raise


@app.get("/v1/health")
async def health_check():
    """
    Health check endpoint.
    
    Returns:
        Dictionary with status and service name
    """
    return {
        "status": "healthy",
        "service": "Taggr API",
        "version": "2.0.0",
        "auth": "disabled"
    }


@app.post("/v1/ops/")
async def api_handler(request: Request):
    """
    Main API endpoint handler - No authentication required.
    
    This endpoint routes requests to the appropriate API function based on processId.
    
    Args:
        request: FastAPI request object
        
    Returns:
        JSON response from the API function
    """
    try:
        
        # Parse request body
        try:
            body = await request.json()
            parameters = body.get('parameters', {})
        except Exception as e:
            logger.error(f"Error parsing request body: {str(e)}")
            return JSONResponse(
                status_code=400,
                content=create_error_response(
                    400,
                    "Invalid request body",
                    ERROR_CODES["BAD_REQUEST"]
                )
            )
        
        # Extract processId
        process_id = parameters.get('processId', '')
        
        if not process_id:
            logger.error("Missing processId in request")
            return JSONResponse(
                status_code=400,
                content=create_error_response(
                    400,
                    "Missing processId parameter",
                    ERROR_CODES["BAD_REQUEST"]
                )
            )
        
        logger.info(f"Processing request: {process_id}")
        
        # Route to appropriate function using namespace-based routing
        response = None
        
        # Check if processId uses new namespace format (namespace::api-NNN-method-name)
        if '::' in process_id:
            # Parse namespace and method
            namespace, method = process_id.split('::', 1)
            
            # Convert kebab-case to snake_case
            method = method.replace('-', '_')
            
            # Route based on namespace
            if namespace == 'metadata' and hasattr(metadata_api, method):
                handler = getattr(metadata_api, method)
                response = handler(parameters)
            
            elif namespace == 'tagger' and hasattr(tagger_api, method):
                handler = getattr(tagger_api, method)
                response = handler(parameters)
            
            elif namespace == 'profiles' and hasattr(profiles_api, method):
                handler = getattr(profiles_api, method)
                response = handler(parameters)
            
            elif namespace == 'modules' and hasattr(modules_api, method):
                handler = getattr(modules_api, method)
                response = handler(parameters)
            
            else:
                logger.error(f"Invalid namespace '{namespace}' or method '{method}' not found")
                return JSONResponse(
                    status_code=400,
                    content={
                        "message": f"Invalid namespace '{namespace}' or method '{method}' not found",
                        "code": ERROR_CODES["BAD_REQUEST"]
                    }
                )
        
        else:
            # Legacy processId format - not supported
            logger.error(f"Invalid processId format: {process_id}")
            return JSONResponse(
                status_code=400,
                content={
                    "message": f"Invalid processId format. Use namespace::method format (e.g., 'metadata::api-001-get-metadata-results')",
                    "code": ERROR_CODES["BAD_REQUEST"]
                }
            )
        
        # Return response
        logger.info(f"Request completed: {process_id}")
        return JSONResponse(
            status_code=response['statusCode'],
            content=json.loads(response['body']),
            headers=response['headers']
        )
    
    except HTTPException:
        # Re-raise HTTP exceptions (like 511 from token validation)
        raise
    
    except Exception as e:
        logger.error(f"Error in main handler: {str(e)}")
        return JSONResponse(
            status_code=500,
            content=create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )
        )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """
    Handle HTTP exceptions.
    
    Args:
        request: FastAPI request object
        exc: HTTPException instance
        
    Returns:
        JSON response with error details
    """
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "message": exc.detail,
            "code": "HTTP_ERROR"
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """
    Handle general exceptions.
    
    Args:
        request: FastAPI request object
        exc: Exception instance
        
    Returns:
        JSON response with error details
    """
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={
            "message": "Internal server error",
            "code": ERROR_CODES["INTERNAL_ERROR"]
        }
    )


@app.get("/{path:path}")
async def serve_frontend(path: str):
    """
    Serve React app for all non-API routes.
    
    Handles static files (favicon, manifest, etc.) and
    falls back to index.html for React Router SPA navigation.
    """
    if not os.path.isdir(BUILD_FOLDER):
        return JSONResponse(
            status_code=404,
            content={"message": "Frontend not built. Run: npm run build"}
        )
    
    # Serve actual files (favicon.ico, manifest.json, etc.)
    file_path = os.path.join(BUILD_FOLDER, path)
    if path and os.path.isfile(file_path):
        return FileResponse(file_path)
    
    # For everything else (React Router paths), serve index.html
    index_path = os.path.join(BUILD_FOLDER, 'index.html')
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    
    return JSONResponse(
        status_code=404,
        content={"message": "index.html not found in build folder"}
    )


if __name__ == "__main__":
    import uvicorn
    
    # Get port from configuration or environment
    port = int(os.environ.get('API_PORT', 3000))
    
    logger.info(f"Starting Taggr API on port {port}")
    
    uvicorn.run(
        "api_core:app",
        host="0.0.0.0",
        port=port,
        reload=True,
        log_level="info"
    )

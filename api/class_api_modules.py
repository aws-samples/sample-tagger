"""
classModules - Module Management API

This module contains API methods for AWS service module management operations.
Namespace: modules
Method Range: 301-306
"""

import os
import json
import logging
import boto3
import importlib.util
import sys
import concurrent.futures
import urllib.request
import zipfile
import shutil
from typing import Dict, Any

from class_tools import (
    APIGatewayResponse,
    ErrorResponse,
    DataStore,
    CORS_HEADERS,
    ERROR_CODES
)
from class_configuration import classConfiguration

logger = logging.getLogger(__name__)


def create_response(status_code: int, body: Any) -> APIGatewayResponse:
    """Create API Gateway compatible response."""
    return {
        "statusCode": status_code,
        "headers": CORS_HEADERS,
        "body": json.dumps(body)
    }


def create_error_response(status_code: int, message: str, code: str) -> APIGatewayResponse:
    """Create error response."""
    error_response: ErrorResponse = {
        "message": message,
        "code": code
    }
    return create_response(status_code, error_response)


class classModules:
    """
    Module Management API operations.
    
    Handles all AWS service module management API endpoints.
    """
    
    def __init__(self, db_config: dict, region: str, config: classConfiguration):
        """
        Initialize classModules.
        
        Args:
            db_config: Database configuration
            region: AWS region
            config: Configuration object
        """
        self.db_config = db_config
        self.region = region
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.modules_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'modules')
    
    def api_301_get_list_modules(self, params: dict) -> dict:
        """
        List modules from local directory.
        
        ProcessId: modules::api-301-get-list-modules
        
        Args:
            params: Request parameters
                
        Returns:
            Dictionary with modules array
        """
        try:
            modules = []
            for filename in os.listdir(self.modules_path):
                if filename.endswith('.py'):
                    filepath = os.path.join(self.modules_path, filename)
                    stat = os.stat(filepath)
                    modules.append({
                        'name': filename[:-3],
                        'size': stat.st_size,
                        'lastModified': stat.st_mtime
                    })
            
            return create_response(200, {
                "response": {
                    "modules": modules
                }
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_301_get_list_modules: {str(e)}")
            return create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )
    
    def api_302_get_module_content(self, params: dict) -> dict:
        """
        Get module content from local directory.
        
        ProcessId: modules::api-302-get-module-content
        
        Args:
            params: Request parameters containing:
                - fileName: Module file name (without .py extension)
                
        Returns:
            Dictionary with content
        """
        try:
            filepath = os.path.join(self.modules_path, params['fileName'] + ".py")
            with open(filepath, 'r') as f:
                content = f.read()
            
            return create_response(200, {
                "response": {
                    "content": content
                }
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_302_get_module_content: {str(e)}")
            return create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )
    
    def api_303_save_module_content(self, params: dict) -> dict:
        """
        Save module content to local directory.
        
        ProcessId: modules::api-303-save-module-content
        
        Args:
            params: Request parameters containing:
                - fileName: Module file name (without .py extension)
                - content: Module content
                
        Returns:
            Dictionary with status
        """
        try:
            filepath = os.path.join(self.modules_path, params['fileName'] + ".py")
            with open(filepath, 'w') as f:
                f.write(params['content'])
            
            return create_response(200, {
                "response": {
                    "status": "success"
                }
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_303_save_module_content: {str(e)}")
            return create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )
    
    def api_304_delete_module_content(self, params: dict) -> dict:
        """
        Delete module content from local directory.
        
        ProcessId: modules::api-304-delete-module-content
        
        Args:
            params: Request parameters containing:
                - fileName: Module file name (without .py extension)
                
        Returns:
            Dictionary with status
        """
        try:
            filepath = os.path.join(self.modules_path, params['fileName'] + ".py")
            if os.path.exists(filepath):
                os.remove(filepath)
            
            return create_response(200, {
                "response": {
                    "status": "success"
                }
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_304_delete_module_content: {str(e)}")
            return create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )
    
    def api_305_validate_module_content(self, params: dict) -> dict:
        """
        Validate module content.
        
        ProcessId: modules::api-305-validate-module-content
        Original: fn_21_validate_module_content
        
        Args:
            params: Request parameters containing:
                - accountId: AWS account ID
                - region: AWS region
                - fileName: Module file name (without .py extension)
                
        Returns:
            Dictionary with validation results
        """
        try:
            account_id = params['accountId']
            test_region = params['region']
            file_name = params['fileName'] + ".py"
            service = params['fileName']
            iam_root_role = self.config.get_config('IAM_ROOT_ROLE', '') if self.config else os.environ.get('IAM_ROOT_ROLE', '')
            iam_child_role = self.config.get_config('IAM_CHILD_ROLE', '') if self.config else os.environ.get('IAM_CHILD_ROLE', '')
            max_workers = self.config.get_config('MAX_WORKERS', 10) if self.config else int(os.environ.get('MAX_WORKERS', '10'))
            
            filepath = os.path.join(self.modules_path, file_name)
            with open(filepath, 'r') as f:
                code = f.read()
            
            # Step 1: Assume root role
            sts_client = boto3.client('sts')
            caller = sts_client.get_caller_identity()
            local_account = caller['Account']
            root_role_arn = f'arn:aws:iam::{local_account}:role/{iam_root_role}'
            
            assumed_root = sts_client.assume_role(
                RoleArn=root_role_arn,
                RoleSessionName='TaggrValidationRoot'
            )
            root_session = boto3.Session(
                aws_access_key_id=assumed_root['Credentials']['AccessKeyId'],
                aws_secret_access_key=assumed_root['Credentials']['SecretAccessKey'],
                aws_session_token=assumed_root['Credentials']['SessionToken']
            )
            
            # Step 2: Use root session to assume child role in target account
            root_sts = root_session.client('sts')
            child_role_arn = f'arn:aws:iam::{account_id}:role/{iam_child_role}'
            
            assumed_child = root_sts.assume_role(
                RoleArn=child_role_arn,
                RoleSessionName=f'TaggrValidation-{account_id}'
            )
            
            session = boto3.Session(
                aws_access_key_id=assumed_child['Credentials']['AccessKeyId'],
                aws_secret_access_key=assumed_child['Credentials']['SecretAccessKey'],
                aws_session_token=assumed_child['Credentials']['SessionToken']
            )
            
            # Create a module name
            module_name = "dynamic_module"
            
            # Create a module spec
            spec = importlib.util.spec_from_loader(module_name, loader=None)
            
            # Create a module based on the spec
            module = importlib.util.module_from_spec(spec)
            
            # Add the module to sys.modules
            sys.modules[module_name] = module
            
            # Execute the code string in the module's namespace
            exec(code, module.__dict__)
            
            # Get service types
            service_list = (module.get_service_types(None, None, None, None)).keys()
            
            all_resources = []
            all_services = []
            
            # Parallel processing
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = []
                for srv in service_list:
                    futures.append(
                        executor.submit(
                            module.discovery,
                            None,
                            session,
                            account_id,
                            test_region,
                            service,
                            srv,
                            self.logger
                        )
                    )
                
                # Process results
                for future in concurrent.futures.as_completed(futures):
                    try:
                        service_name, status, message, resources = future.result()
                        resources = [
                            {k: v for k, v in obj.items() if k not in ['metadata']}
                            for obj in resources
                        ]
                        self.logger.info(f"{service_name}, {status}, {message}")
                        all_services.extend([{
                            "service": service_name,
                            "status": status,
                            "message": message
                        }])
                        all_resources.extend(resources)
                    except Exception as e:
                        self.logger.error(f"Error processing future: {e}")
            
            return create_response(200, {
                "response": {
                    "status": "success",
                    "services": all_services,
                    "resources": json.dumps(all_resources, default=str)
                }
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_305_validate_module_content: {str(e)}")
            return create_error_response(
                500,
                f'Internal server error: {e}',
                ERROR_CODES["INTERNAL_ERROR"]
            )
    
    def api_306_sync_modules_from_repo(self, params: dict) -> dict:
        """
        Sync modules from GitHub repository to local directory.
        
        ProcessId: modules::api-306-sync-modules-from-repo
        
        Args:
            params: Request parameters
                
        Returns:
            Dictionary with status and file count
        """
        try:
            # GitHub configuration
            github_repo = "aws-samples/sample-tagger"
            github_branch = "main"
            github_dir = "modules"
            
            # Create temporary directory
            temp_dir = "/tmp/repo_download"
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            os.makedirs(temp_dir)
            
            # Download repository as zip
            zip_url = f"https://github.com/{github_repo}/archive/{github_branch}.zip"
            zip_path = f"/tmp/{github_branch}.zip"
            
            self.logger.info(f"Downloading repository from {zip_url}")
            urllib.request.urlretrieve(zip_url, zip_path)
            
            # Extract the repo
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall("/tmp")
            
            # Path to the extracted directory containing the target folder
            extracted_dir = f"/tmp/sample-tagger-{github_branch}"
            source_dir = os.path.join(extracted_dir, github_dir)
            
            # Ensure local modules directory exists
            os.makedirs(self.modules_path, exist_ok=True)
            
            # Copy .py files to local modules directory
            file_count = 0
            for root, dirs, files in os.walk(source_dir):
                for file in files:
                    if not file.endswith('.py'):
                        continue
                    local_src = os.path.join(root, file)
                    dest_path = os.path.join(self.modules_path, file)
                    
                    self.logger.info(f"Copying {file} to {self.modules_path}")
                    shutil.copy2(local_src, dest_path)
                    file_count += 1
            
            # Clean up
            os.remove(zip_path)
            shutil.rmtree(f"/tmp/sample-tagger-{github_branch}")
            
            return create_response(200, {
                "response": {
                    "status": "success",
                    "files": file_count
                }
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_306_sync_modules_from_repo: {str(e)}")
            return create_error_response(
                500,
                f'Internal server error: {e}',
                ERROR_CODES["INTERNAL_ERROR"]
            )

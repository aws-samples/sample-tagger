"""
classProfiles - Profile Management API

This module contains API methods for profile management operations.
Namespace: profiles
Method Range: 201-205
"""

import os
import json
import logging
import importlib.util
import sys
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


class classProfiles:
    """
    Profile Management API operations.
    
    Handles all profile-related API endpoints.
    """
    
    def __init__(self, db_config: dict, region: str, config: classConfiguration):
        """
        Initialize classProfiles.
        
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
    
    def api_201_create_profile(self, params: dict) -> dict:
        """
        Create a profile.
        
        ProcessId: profiles::api-201-create-profile
        Original: fn_09_create_profile
        
        Args:
            params: Request parameters containing:
                - profileId: Profile identifier
                - jsonProfile: Profile configuration object
                
        Returns:
            Dictionary with profile_id and state
        """
        try:
            create_table_query = """        
            CREATE TABLE IF NOT EXISTS tbprofiles (            
                profile_id TEXT,            
                json_profile TEXT,
                PRIMARY KEY (profile_id)
            )
            """
            
            insert_query = """
            INSERT INTO tbprofiles (
                profile_id,
                json_profile
            )
            VALUES (?, ?)
            """
            
            insert_data = [
                (params['profileId'], json.dumps(params['jsonProfile']))
            ]
            
            ds = DataStore(db_config=self.db_config, region=self.region)
            ds.execute_command(create_table_query)
            ds.execute_insert(insert_query, insert_data)
            
            return create_response(200, {
                "response": {
                    "profile_id": params['profileId'],
                    "state": "success"
                }
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_201_create_profile: {str(e)}")
            return create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )
    
    def api_202_update_profile(self, params: dict) -> dict:
        """
        Update a profile.
        
        ProcessId: profiles::api-202-update-profile
        Original: fn_10_update_profile
        
        Args:
            params: Request parameters containing:
                - profileId: Profile identifier
                - jsonProfile: Updated profile configuration object
                
        Returns:
            Dictionary with profileId, jsonProfile, and state
        """
        try:
            update_query = """
            UPDATE tbprofiles
            SET json_profile = ?
            WHERE profile_id = ?
            """
            
            parameters = (json.dumps(params['jsonProfile']), params['profileId'])
            
            ds = DataStore(db_config=self.db_config, region=self.region)
            ds.execute_dml(update_query, parameters)
            
            return create_response(200, {
                "response": {
                    "profileId": params['profileId'],
                    "jsonProfile": params['jsonProfile'],
                    "state": "success"
                }
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_202_update_profile: {str(e)}")
            return create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )
    
    def api_203_delete_profile(self, params: dict) -> dict:
        """
        Delete a profile.
        
        ProcessId: profiles::api-203-delete-profile
        Original: fn_11_delete_profile
        
        Args:
            params: Request parameters containing:
                - profileId: Profile identifier
                
        Returns:
            Dictionary with scan_id and state
        """
        try:
            update_query = """
            DELETE FROM tbprofiles      
            WHERE profile_id = ?
            """
            
            parameters = (params['profileId'],)
            
            ds = DataStore(db_config=self.db_config, region=self.region)
            ds.execute_dml(update_query, parameters)
            
            return create_response(200, {
                "response": {
                    "scan_id": params['profileId'],
                    "state": "success"
                }
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_203_delete_profile: {str(e)}")
            return create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )
    
    def api_204_get_profiles(self, params: dict) -> dict:
        """
        Get profiles.
        
        ProcessId: profiles::api-204-get-profiles
        Original: fn_12_get_profiles
        
        Args:
            params: Request parameters
                
        Returns:
            Dictionary with profiles array
        """
        try:
            select_query = """
            SELECT
                profile_id,
                json_profile
            FROM
                tbprofiles
            ORDER BY
                profile_id DESC
            """
            
            ds = DataStore(db_config=self.db_config, region=self.region)
            rows = ds.execute_select(select_query, None)
            
            response = []
            for row in rows:
                response.append({
                    "profileId": row[0],
                    "jsonProfile": json.loads(row[1])
                })
            
            return create_response(200, {
                "response": response
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_204_get_profiles: {str(e)}")
            return create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )
    
    def api_205_get_profile_catalog(self, params: dict) -> dict:
        """
        Get profile catalog (services and regions) from local modules.

        ProcessId: profiles::api-205-get-profile-catalog

        Args:
            params: Request parameters

        Returns:
            Dictionary with services and regions arrays
        """
        try:
            # Get regions from local file
            regions_path = os.path.join(self.modules_path, 'regions.json')
            with open(regions_path, 'r') as f:
                regions = json.load(f)

            # Get list of local module files
            module_files = [f for f in os.listdir(self.modules_path) if f.endswith('.py')]

            # Get resources modules
            all_services = []
            for module_file in module_files:
                filepath = os.path.join(self.modules_path, module_file)
                with open(filepath, 'r') as f:
                    code = f.read()

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

                for service in service_list:
                    all_services.append(f'{module_file[:-3]}::{service}')

            all_services.sort()

            return create_response(200, {
                "response": {
                    "services": all_services,
                    "regions": regions
                }
            })

        except Exception as e:
            self.logger.error(f"Error in api_205_get_profile_catalog: {str(e)}")
            return create_error_response(
                500,
                f'Internal server error: {e}',
                ERROR_CODES["INTERNAL_ERROR"]
            )

"""
classTagger - Tagging Operations API

This module contains API methods for resource tagging operations.
Namespace: tagger
Method Range: 101-105
"""

import os
import json
import logging
import threading
from datetime import datetime
from typing import Dict, Any
from collections import Counter

from class_tools import (
    APIGatewayResponse,
    ErrorResponse,
    DataStore,
    CORS_HEADERS,
    ERROR_CODES
)
from class_tagger import AWSResourceTagger
from class_scan_logger import ScanLogger
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


class classTagger:
    """
    Tagging API operations.
    
    Handles all resource tagging related API endpoints.
    """
    
    def __init__(self, db_config: dict, region: str, config: classConfiguration):
        """
        Initialize classTagger.
        
        Args:
            db_config: Database configuration
            region: AWS region
            config: Configuration object
        """
        self.db_config = db_config
        self.region = region
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    def api_101_update_resource_action(self, params: dict) -> dict:
        """
        Update resource action - filter-in / filter-out.
        Supports both single resource and batch updates.
        
        ProcessId: tagger::api-101-update-resource-action
        Original: fn_04_update_resource_action
        
        Args:
            params: Request parameters containing:
                - resources: Array of {scan_id, seq} objects (new batch format)
                - action: Action value (1=filter-in, 2=filter-out)
                
                OR (legacy single resource format):
                - scanId: Scan identifier
                - seq: Resource sequence number
                - action: Action value
                
        Returns:
            Dictionary with success status and count of updated resources
        """
        try:
            ds = DataStore(db_config=self.db_config, region=self.region)
            action_value = int(params['action'])
            updated_count = 0
            
            # Check if batch update (new format)
            if 'resources' in params and isinstance(params['resources'], list):
                # Batch update
                update_query = """
                UPDATE tbresources
                SET action = ?
                WHERE scan_id = ? AND seq = ?
                """
                
                for resource in params['resources']:
                    parameters = (action_value, resource['scan_id'], int(resource['seq']))
                    ds.execute_dml(update_query, parameters)
                    updated_count += 1
                
                self.logger.info(f"Batch updated {updated_count} resources to action={action_value}")
                
            else:
                # Single resource update (legacy format)
                update_query = """
                UPDATE tbresources
                SET action = ?
                WHERE scan_id = ? AND seq = ?
                """
                
                parameters = (action_value, params['scanId'], int(params['seq']))
                ds.execute_dml(update_query, parameters)
                updated_count = 1
                
                self.logger.info(f"Updated single resource to action={action_value}")
            
            return create_response(200, {
                "response": {
                    "status": "success",
                    "updated_count": updated_count
                }
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_101_update_resource_action: {str(e)}")
            return create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )
    
    def api_102_create_tagging_process(self, params: dict) -> dict:
        """
        Launch tagging process (replaces Lambda invocation with direct class instantiation).
        
        ProcessId: tagger::api-102-create-tagging-process
        Original: fn_05_create_tagging_process
        
        Args:
            params: Request parameters containing:
                - scanId: Scan identifier
                - tags: Array of tag objects with key/value
                - action: Tagging action (1=add, 2=remove)
                
        Returns:
            Dictionary with scan_id and state
        """
        try:
            update_query = """
            UPDATE tbprocess 
            SET start_time_tagging = ?, status_tagging = ?, message_tagging = NULL
            WHERE scan_id = ?
            """
            
            parameters = (
                (datetime.now()).strftime("%Y-%m-%d %H:%M:%S"),
                "in-progress",
                params['scanId']
            )
            
            ds = DataStore(db_config=self.db_config, region=self.region)
            ds.execute_dml(update_query, parameters)
            
            # Run tagging asynchronously in a separate thread
            def run_tagging():
                try:
                    scan_id = params['scanId']
                    tags_object = params['tags']
                    tags_action = int(params['action'])
                    max_workers = self.config.get_config('MAX_WORKERS', 10) if self.config else int(os.environ.get('MAX_WORKERS', '10'))
                    
                    # Select resources to tag
                    ds_tagging = DataStore(db_config=self.db_config, region=self.region)
                    
                    select_query = """
                    SELECT
                        account_id,
                        region,
                        service,
                        resource_id,
                        arn
                    FROM
                        tbresources
                    WHERE 
                        scan_id = ?
                        AND
                        action = 1
                    ORDER BY
                        account_id,
                        region,
                        service,
                        resource_id,
                        arn
                    """
                    
                    parameters = (scan_id,)
                    rows = ds_tagging.execute_select(select_query, parameters)
                    resources = [tuple(row) for row in rows]
                    
                    tags_string = ",".join([f"{obj['key']}:{obj['value']}" for obj in tags_object])
                    
                    # Initialize tagger
                    tagger = AWSResourceTagger(
                        scan_id=scan_id,
                        max_workers=max_workers,
                        root_role=self.config.get_config('IAM_ROOT_ROLE', '') if self.config else os.environ.get('IAM_ROOT_ROLE', ''),
                        child_role=self.config.get_config('IAM_CHILD_ROLE', '') if self.config else os.environ.get('IAM_CHILD_ROLE', '')
                    )
                    
                    # Load service modules from local directory
                    tagger.load_local_modules()
                    
                    # Tag resources and get results with metrics
                    results, metrics = tagger.tag_resources(resources, tags_string, tags_action)
                    
                    self.logger.info(f"Tagging metrics: {metrics}")
                    
                    # Create structured message with metrics
                    if metrics['failed'] > 0:
                        message_data = {
                            'text': f"Tagging completed with {metrics['failed']} errors",
                            'metrics': metrics
                        }
                    else:
                        message_data = {
                            'text': 'Tagging completed successfully',
                            'metrics': metrics
                        }
                    
                    update_query = """
                    UPDATE tbprocess
                    SET end_time_tagging = ?, status_tagging = ?, message_tagging = ?, 
                        resources_tagged_success = ?, resources_tagged_error = ?, action = ?
                    WHERE scan_id = ?
                    """
                    ds_tagging.execute_dml(
                        update_query,
                        (
                            (datetime.now()).strftime("%Y-%m-%d %H:%M:%S"),
                            'completed',
                            json.dumps(message_data),
                            metrics['success'],
                            metrics['failed'],
                            tags_action,
                            scan_id
                        )
                    )
                    
                    error_items = [item for item in results if item.get('status') == 'error']
                    ds_tagging.save_tags_errors(scan_id, error_items)
                    
                    self.logger.info(f"Tagging completed for scan_id: {scan_id}")
                
                except Exception as e:
                    self.logger.error(f"Error in tagging thread: {str(e)}")
                    # Update process status with error
                    try:
                        ds_error = DataStore(db_config=self.db_config, region=self.region)
                        update_query = """
                        UPDATE tbprocess
                        SET end_time_tagging = ?, status_tagging = ?, message_tagging = ?
                        WHERE scan_id = ?
                        """
                        ds_error.execute_dml(
                            update_query,
                            (
                                (datetime.now()).strftime("%Y-%m-%d %H:%M:%S"),
                                'error',
                                str(e),
                                params['scanId']
                            )
                        )
                    except Exception as update_error:
                        self.logger.error(f"Error updating process status: {str(update_error)}")
            
            # Start tagging in background thread
            tagging_thread = threading.Thread(target=run_tagging, daemon=True)
            tagging_thread.start()
            
            return create_response(200, {
                "response": {
                    "scan_id": params['scanId'],
                    "state": "success"
                }
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_102_create_tagging_process: {str(e)}")
            return create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )
    
    def api_103_get_tagging_process_status(self, params: dict) -> dict:
        """
        Get status for tagging process.
        
        ProcessId: tagger::api-103-get-tagging-process-status
        Original: fn_06_get_tagging_process_status
        
        Args:
            params: Request parameters containing:
                - scanId: Scan identifier
                
        Returns:
            Dictionary with status and message
        """
        try:
            select_query = """
            SELECT
                status_tagging,
                message_tagging
            FROM
                tbprocess
            WHERE scan_id = ?
            """
            
            parameters = (params["scanId"],)
            
            ds = DataStore(db_config=self.db_config, region=self.region)
            rows = ds.execute_select(select_query, parameters)
            
            status = ""
            message = ""
            
            for row in rows:
                status = row[0]
                message = row[1]
            
            # Parse message field if it's JSON (new format)
            message_text = ""
            metrics = None
            has_errors = False
            
            if message and message != "-":
                try:
                    message_obj = json.loads(message)
                    message_text = message_obj.get('text', message)
                    metrics = message_obj.get('metrics')
                    if metrics:
                        has_errors = metrics.get('failed', 0) > 0
                except (json.JSONDecodeError, TypeError):
                    # Old format: {"success": 354, "error": 0}
                    # Try to parse as Counter format for backward compatibility
                    try:
                        counter_obj = json.loads(message)
                        if 'success' in counter_obj or 'error' in counter_obj:
                            # Old Counter format
                            metrics = {
                                'total': counter_obj.get('success', 0) + counter_obj.get('error', 0),
                                'success': counter_obj.get('success', 0),
                                'failed': counter_obj.get('error', 0)
                            }
                            has_errors = metrics['failed'] > 0
                            message_text = f"Tagging completed with {metrics['failed']} errors" if has_errors else "Tagging completed successfully"
                        else:
                            message_text = message
                            has_errors = True
                    except:
                        message_text = message
                        has_errors = True
            
            response = {
                "status": status,
                "message": message_text,
                "has_errors": has_errors,
                "metrics": metrics
            }
            
            return create_response(200, {
                "response": response
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_103_get_tagging_process_status: {str(e)}")
            return create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )
    
    def api_104_get_dataset_tagging(self, params: dict) -> dict:
        """
        Get resources for specific tagging process with analytics.
        
        ProcessId: tagger::api-104-get-dataset-tagging
        Original: fn_08_get_dataset_tagging
        
        Args:
            params: Request parameters
                
        Returns:
            Dictionary with processes, summary, and services
        """
        try:
            ds = DataStore(db_config=self.db_config, region=self.region)
            
            select_query = """
            SELECT
                scan_id,     
                name,       
                parameters,
                start_time,
                end_time,
                status,
                message,
                resources,
                start_time_tagging,
                end_time_tagging,
                status_tagging,
                message_tagging,
                resources_tagged_success,
                resources_tagged_error,
                action
            FROM
                tbprocess
            WHERE
                start_time_tagging is NOT NULL
                and
                end_time_tagging is NOT NULL
                and
                (type = 1 or type = 3)
                and
                status_tagging = 'completed'
            ORDER BY
                scan_id DESC
            LIMIT
                ?
            """
            
            parameters = (100,)
            rows = ds.execute_select(select_query, parameters)
            
            processes = []
            summary = {"added": [], "removed": []}
            limit_records = 0
            for row in rows:
                processes.append({
                    "scan_id": row[0],
                    "name": row[1],
                    "parameters": row[2],
                    "start_time": row[3],
                    "end_time": row[4],
                    "status": row[5],
                    "message": row[6],
                    "resources": row[7],
                    "start_time_tagging": row[8],
                    "end_time_tagging": row[9],
                    "status_tagging": row[10],
                    "message_tagging": row[11],
                    "resources_tagged_success": row[12],
                    "resources_tagged_error": row[13],
                    "action": row[14]
                })
                if limit_records < 10:
                    if row[14] == 1:
                        summary['added'].append({"x": row[0], "y": row[12]})
                        summary['removed'].append({"x": row[0], "y": 0})
                    elif row[14] == 2:
                        summary['added'].append({"x": row[0], "y": 0})
                        summary['removed'].append({"x": row[0], "y": row[12]})
                
                limit_records += 1
            
            # Chart Summary
            select_query = """
            SELECT
                scan_id,
                service,                        
                COUNT(*) AS total
            FROM
                tbresources
            WHERE scan_id IN (
                SELECT
                    scan_id
                FROM
                    tbprocess
                WHERE
                    start_time_tagging is NOT NULL
                    and
                    end_time_tagging is NOT NULL                    
                    and
                    (type = 1 or type = 3)
                    and
                    status_tagging = 'completed'
                ORDER BY
                    scan_id DESC
                LIMIT
                    ?
            )
                AND
                action = 1
            GROUP BY
                scan_id,
                service
            ORDER BY
                scan_id ASC
            """
            parameters = (10,)
            rows = ds.execute_select(select_query, parameters)
            
            services = {}
            result_services = []
            for row in rows:
                if row[1] not in services:
                    services[row[1]] = []
                services[row[1]].append({'x': row[0], 'y': float(row[2])})
            
            for service in services.keys():
                result_services.append({'title': service, 'type': 'bar', 'data': services[service]})
            
            return create_response(200, {
                "response": {
                    "processes": processes,
                    "summary": summary,
                    "services": result_services
                }
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_104_get_dataset_tagging: {str(e)}")
            return create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )
    
    def api_105_get_tagging_errors(self, params: dict) -> dict:
        """
        Get tagging errors.
        
        ProcessId: tagger::api-105-get-tagging-errors
        Original: fn_23_get_tagging_errors
        
        Args:
            params: Request parameters containing:
                - scanId: Scan identifier
                
        Returns:
            Dictionary with error resources
        """
        try:
            ds = DataStore(db_config=self.db_config, region=self.region)
            
            select_query = """
            SELECT
                account_id,
                region,
                service,
                resource_id,
                arn,
                status,
                error
            FROM
                tbtag_errors
            WHERE            
                scan_id = ?
            """
            
            parameters = (params['scanId'],)
            rows = ds.execute_select(select_query, parameters)
            
            resources = []
            for row in rows:
                resources.append({
                    "account_id": row[0],
                    "region": row[1],
                    "service": row[2],
                    "resource_id": row[3],
                    "arn": row[4],
                    "status": row[5],
                    "error": row[6]
                })
            
            return create_response(200, {
                "response": {
                    "resources": resources
                }
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_105_get_tagging_errors: {str(e)}")
            return create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )
    
    def api_106_get_scan_logs(self, params: dict) -> dict:
        """
        Get scan logs for discovery or tagging process.
        
        ProcessId: tagger::api-106-get-scan-logs
        
        Args:
            params: Request parameters containing:
                - scanId: Scan identifier
                - lines: Optional number of lines to return (tail mode)
                
        Returns:
            Dictionary with log content and statistics
        """
        try:
            scan_id = params['scanId']
            lines = params.get('lines', None)
            
            # Check if log exists
            if not ScanLogger.log_exists(scan_id):
                return create_response(200, {
                    "response": {
                        "exists": False,
                        "content": "",
                        "stats": {
                            "total_lines": 0,
                            "info_count": 0,
                            "warning_count": 0,
                            "error_count": 0,
                            "success_count": 0
                        }
                    }
                })
            
            # Read log content
            log_content = ScanLogger.read_log(scan_id, lines=lines)
            
            # Get log statistics
            stats = ScanLogger.get_log_stats(scan_id)
            
            return create_response(200, {
                "response": {
                    "exists": True,
                    "content": log_content,
                    "stats": stats
                }
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_106_get_scan_logs: {str(e)}")
            return create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )

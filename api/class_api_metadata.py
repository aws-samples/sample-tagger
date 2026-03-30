"""
classMetadata - Metadata Operations API

This module contains API methods for metadata and resource discovery operations.
Namespace: metadata
Method Range: 001-009
"""

import os
import json
import logging
import threading
from datetime import datetime
from typing import Dict, Any
import boto3
import math

from class_tools import (
    APIGatewayResponse,
    ErrorResponse,
    DataStore,
    CORS_HEADERS,
    ERROR_CODES
)
from class_discovery import AWSResourceDiscovery
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


class classMetadata:
    """
    Metadata API operations.
    
    Handles all metadata and resource discovery related API endpoints.
    """
    
    def __init__(self, db_config: dict, region: str, config: classConfiguration):
        """
        Initialize classMetadata.
        
        Args:
            db_config: Database configuration
            region: AWS region
            config: Configuration object
        """
        self.db_config = db_config
        self.region = region
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    def api_001_get_metadata_results(self, params: dict) -> dict:
        """
        Get metadata results with pagination.
        
        ProcessId: metadata::api-001-get-metadata-results
        Original: fn_01_get_metadata_results
        
        Args:
            params: Request parameters containing:
                - scanId: Scan identifier
                - action: Action filter
                - page: Page number
                - limit: Results per page
                
        Returns:
            Dictionary with resources, pages, and records count
        """
        try:
            total_records = 0
            resources = []
            
            # Get total pages
            select_query = """
            SELECT
                count(*)
            FROM
                tbresources
            WHERE
                scan_id = ?
                AND
                ( action = ? OR ? = 3)       
            """
            
            parameters = (params['scanId'], int(params['action']), int(params['action']))
            
            ds = DataStore(db_config=self.db_config, region=self.region)
            rows = ds.execute_select(select_query, parameters)
            for row in rows:
                total_records = row[0]
            
            pages = math.ceil(total_records / int(params['limit']))
            
            # Get all resources
            select_query = """
            SELECT
                scan_id,            
                seq,
                account_id, 
                region, 
                service,
                resource_type, 
                resource_id, 
                name,
                creation_date,
                tags,  
                tags_number,          
                action
            FROM
                tbresources
            WHERE
                scan_id = ?
                AND
                ( action = ? OR ? = 3)
            ORDER BY
                seq ASC
            LIMIT 
                ?
            OFFSET 
                ?
            """
            
            parameters = (
                params['scanId'],
                int(params['action']),
                int(params['action']),
                int(params['limit']),
                int(params['page']) * int(params['limit'])
            )
            
            rows = ds.execute_select(select_query, parameters)
            for row in rows:
                resources.append({
                    'scan_id': row[0],
                    'seq': row[1],
                    'account': row[2],
                    'region': row[3],
                    'service': row[4],
                    'type': row[5],
                    'identifier': row[6],
                    'name': row[7],
                    'creation': row[8],
                    'tags_list': row[9],
                    'tags_number': row[10],
                    'action': row[11]
                })
            
            return create_response(200, {
                "response": {
                    "resources": resources,
                    "pages": pages,
                    "records": total_records
                }
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_001_get_metadata_results: {str(e)}")
            return create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )
    
    def api_002_create_metadata_search(self, params: dict) -> dict:
        """
        Create metadata search process.
        
        ProcessId: metadata::api-002-create-metadata-search
        Original: fn_02_create_metadata_search
        
        Args:
            params: Request parameters containing:
                - scanId: Scan identifier
                - name: Search name
                - ruleset: Discovery rules (accounts, regions, services, filter)
                - type: Search type
                
        Returns:
            Dictionary with scan status
        """
        try:
            # Write data store record
            create_table_query = """        
            CREATE TABLE IF NOT EXISTS tbprocess (            
                scan_id TEXT,            
                name TEXT,
                parameters TEXT,
                start_time TEXT,
                end_time TEXT,
                status TEXT,
                message TEXT,
                resources INT DEFAULT 0,
                start_time_tagging TEXT,
                end_time_tagging TEXT,
                status_tagging TEXT,
                message_tagging TEXT,
                resources_tagged_success INT DEFAULT 0,
                resources_tagged_error INT DEFAULT 0,
                action INT DEFAULT 0,
                type INT DEFAULT 0,
                PRIMARY KEY (scan_id)
            )
            """
            
            insert_query = """
            INSERT INTO tbprocess (
                scan_id,            
                name,
                parameters,
                start_time,
                end_time,
                status,
                message,
                type
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """
            
            insert_data = [
                (
                    params['scanId'],
                    params['name'],
                    json.dumps(params['ruleset']),
                    (datetime.now()).strftime("%Y-%m-%d %H:%M:%S"),
                    "-",
                    "in-progress",
                    "-",
                    params['type']
                )
            ]
            
            ds = DataStore(db_config=self.db_config, region=self.region)
            ds.execute_command(create_table_query)
            ds.execute_insert(insert_query, insert_data)
            
            # Run discovery asynchronously in a separate thread
            def run_discovery():
                """
                Run discovery process and save results.
                Always saves resources found, even if errors occur.
                """
                scan_id = params['scanId']
                resources = []
                error_message = None
                
                try:
                    self.logger.info(f"Starting discovery for scan_id: {scan_id}")
                    
                    # Get parameters
                    accounts = params['ruleset']['accounts']
                    regions_list = params['ruleset']['regions']
                    services = params['ruleset']['services']
                    filter_clause = params['ruleset'].get('filter', 'true')
                    max_workers = self.config.get_config('MAX_WORKERS', 10) if self.config else int(os.environ.get('MAX_WORKERS', '10'))
                    
                    # Create tag collector
                    tag_collector = AWSResourceDiscovery(
                        scan_id=scan_id,
                        accounts=accounts,
                        regions=regions_list,
                        services=services,
                        max_workers=max_workers,
                        root_role=self.config.get_config('IAM_ROOT_ROLE', '') if self.config else os.environ.get('IAM_ROOT_ROLE', ''),
                        child_role=self.config.get_config('IAM_CHILD_ROLE', '') if self.config else os.environ.get('IAM_CHILD_ROLE', '')
                    )
                    
                    # Load service modules from local directory
                    tag_collector.load_local_modules()
                    
                    # Loading service catalog
                    tag_collector.load_service_catalog()
                    
                    # Validate service catalog
                    tag_collector.validate_service_catalog()
                    
                    # Validate region catalog
                    tag_collector.validate_region_catalog()
                    
                    # Collect tags - this continues even if some services fail
                    self.logger.info(f"Starting resource collection for scan_id: {scan_id}")
                    resources, metrics = tag_collector.collect_multi_account_tags()
                    self.logger.info(f"Resource collection completed: {len(resources)} resources found")
                    self.logger.info(f"Discovery metrics: {metrics}")
                    
                    # Determine if there were errors based on metrics
                    if metrics['tasks_failed'] > 0:
                        error_message = json.dumps({
                            'text': f"Discovery completed with {metrics['tasks_failed']} errors",
                            'metrics': metrics
                        })
                        self.logger.warning(f"Discovery had {metrics['tasks_failed']} failed tasks")
                    else:
                        # No errors - store success message with metrics
                        error_message = json.dumps({
                            'text': 'Discovery completed successfully',
                            'metrics': metrics
                        })
                    
                except Exception as e:
                    # Capture error but continue to save any resources found
                    error_message = json.dumps({
                        'text': str(e)[:500],
                        'metrics': {
                            'tasks_total': 0,
                            'tasks_success': 0,
                            'tasks_failed': 0,
                            'resources_found': len(resources) if 'resources' in locals() else 0
                        }
                    })
                    self.logger.error(f"Error during discovery: {error_message}")
                    self.logger.info(f"Will attempt to save {len(resources)} resources found before error")
                
                # ALWAYS try to save resources if any were found
                resources_saved = 0
                try:
                    if len(resources) > 0:
                        self.logger.info(f"Saving {len(resources)} resources to database")
                        
                        # Create DataStore with scan_id
                        db_store = DataStore(scan_id=scan_id, db_config=self.db_config, region=self.region)
                        
                        # Ensure table exists
                        db_store.create_table()
                        
                        # Save resources
                        db_store.save_tags_to_store(resources)
                        self.logger.info(f"Resources saved successfully")
                        
                        # Verify resources were saved by counting (do this BEFORE filter update)
                        count_query = "SELECT COUNT(*) FROM tbresources WHERE scan_id = ?"
                        rows = db_store.execute_select(count_query, (scan_id,))
                        resources_saved = rows[0][0] if rows else 0
                        self.logger.info(f"Verification: {resources_saved} resources in database")
                        
                        # Apply filter to set action field
                        if not isinstance(filter_clause, str) or not filter_clause.strip():
                            filter_clause = 'true'
                        
                        # Sanitize filter clause - if it contains invalid SQL, default to 'true'
                        try:
                            update_query = f"""
                            UPDATE tbresources
                            SET action = CASE WHEN ( {filter_clause} ) THEN 1 ELSE 2 END
                            WHERE scan_id = ?
                            """
                            db_store.execute_dml(update_query, (scan_id,))
                            self.logger.info(f"Filters applied successfully")
                        except Exception as filter_error:
                            self.logger.warning(f"Filter clause failed, defaulting all to action=1: {str(filter_error)}")
                            # If filter fails, set all resources to action=1 (filter-in)
                            try:
                                update_query = """
                                UPDATE tbresources
                                SET action = 1
                                WHERE scan_id = ?
                                """
                                db_store.execute_dml(update_query, (scan_id,))
                                self.logger.info(f"Default filter applied (all resources set to action=1)")
                            except Exception as fallback_error:
                                self.logger.error(f"Even fallback filter failed: {str(fallback_error)}")
                                # Continue anyway - resources are saved, just filter might not be applied
                        
                    else:
                        self.logger.warning(f"No resources to save for scan_id: {scan_id}")
                        
                except Exception as save_error:
                    self.logger.error(f"CRITICAL: Failed to save resources: {str(save_error)}")
                    import traceback
                    self.logger.error(f"Traceback: {traceback.format_exc()}")
                
                # Update process status
                try:
                    ds_update = DataStore(db_config=self.db_config, region=self.region)
                    
                    # Determine final status
                    if error_message and resources_saved == 0:
                        # Complete failure
                        final_status = 'error'
                        final_message = error_message
                    elif error_message and resources_saved > 0:
                        # Partial success
                        final_status = 'completed'
                        final_message = error_message
                    else:
                        # Complete success
                        final_status = 'completed'
                        final_message = '-'
                    
                    update_query = """
                    UPDATE tbprocess
                    SET end_time = ?, status = ?, message = ?, resources = ?
                    WHERE scan_id = ?
                    """
                    
                    ds_update.execute_dml(
                        update_query,
                        (
                            (datetime.now()).strftime("%Y-%m-%d %H:%M:%S"),
                            final_status,
                            final_message,
                            resources_saved,
                            scan_id
                        )
                    )
                    
                    self.logger.info(f"Discovery completed - scan_id: {scan_id}, status: {final_status}, resources: {resources_saved}")
                    
                except Exception as update_error:
                    self.logger.error(f"CRITICAL: Failed to update process status: {str(update_error)}")
                    import traceback
                    self.logger.error(f"Traceback: {traceback.format_exc()}")
            
            # Start discovery in background thread
            discovery_thread = threading.Thread(target=run_discovery, daemon=True)
            discovery_thread.start()
            
            return create_response(200, {
                "response": {
                    "scan_id": params['scanId'],
                    "state": "success"
                }
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_002_create_metadata_search: {str(e)}")
            return create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )
    
    def api_003_get_metadata_search_status(self, params: dict) -> dict:
        """
        Get metadata search status.
        
        ProcessId: metadata::api-003-get-metadata-search-status
        Original: fn_03_get_metadata_search_status
        
        Args:
            params: Request parameters containing:
                - scanId: Scan identifier
                
        Returns:
            Dictionary with scan status and progress
        """
        try:
            select_query = """
            SELECT
                status,
                resources,
                message
            FROM
                tbprocess
            WHERE scan_id = ?
            """
            
            parameters = (params["scanId"],)
            
            ds = DataStore(db_config=self.db_config, region=self.region)
            rows = ds.execute_select(select_query, parameters)
            status = ""
            resources = 0
            message = "-"
            for row in rows:
                status = row[0]
                resources = row[1]
                message = row[2] if len(row) > 2 else "-"
            
            # Parse message field if it's JSON
            message_text = "-"
            metrics = None
            has_errors = False
            
            if message and message != "-":
                try:
                    message_obj = json.loads(message)
                    message_text = message_obj.get('text', message)
                    metrics = message_obj.get('metrics')
                    if metrics:
                        has_errors = metrics.get('tasks_failed', 0) > 0
                except (json.JSONDecodeError, TypeError):
                    # Not JSON, treat as plain text
                    message_text = message
                    has_errors = True  # Assume error if message exists and isn't JSON
            
            return create_response(200, {
                "response": {
                    "status": status,
                    "resources": resources,
                    "message": message_text,
                    "has_errors": has_errors,
                    "metrics": metrics
                }
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_003_get_metadata_search_status: {str(e)}")
            return create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )
    
    def api_004_get_resource_metadata(self, params: dict) -> dict:
        """
        Get resource metadata details.
        
        ProcessId: metadata::api-004-get-resource-metadata
        Original: fn_07_get_resource_metadata
        
        Args:
            params: Request parameters containing:
                - scanId: Scan identifier
                - seq: Resource sequence number
                
        Returns:
            Dictionary with resource metadata
        """
        try:
            select_query = """
            SELECT
                metadata
            FROM
                tbresources
            WHERE 
                scan_id = ?
                and
                seq = ?
            """
            
            parameters = (params["scanId"], params["seq"])
            
            ds = DataStore(db_config=self.db_config, region=self.region)
            rows = ds.execute_select(select_query, parameters)
            
            response = {
                "status": "",
                "metadata": ""
            }
            
            for row in rows:
                response['status'] = "success"
                response['metadata'] = row[0]
            
            return create_response(200, {
                "response": response
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_004_get_resource_metadata: {str(e)}")
            return create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )
    
    def api_005_get_dataset_metadata_bases(self, params: dict) -> dict:
        """
        Get dataset metadata bases.
        
        ProcessId: metadata::api-005-get-dataset-metadata-bases
        Original: fn_13_get_dataset_metadata_bases
        
        Args:
            params: Request parameters containing:
                - type: Process type filter
                
        Returns:
            Dictionary with metadata bases list
        """
        try:
            ds = DataStore(db_config=self.db_config, region=self.region)
            process_type = params['type']
            
            select_query = """
            SELECT
                p.scan_id,            
                p.name,
                p.parameters,
                p.start_time,
                p.end_time,
                p.status,
                p.message,
                p.resources,
                COALESCE(c.in_compliance, 0) as in_compliance,
                COALESCE(c.out_compliance, 0) as out_compliance
            FROM
                tbprocess p
            LEFT JOIN (
                SELECT
                    scan_id,
                    SUM(CASE WHEN action = 2 THEN 1 ELSE 0 END) as in_compliance,
                    SUM(CASE WHEN action = 1 THEN 1 ELSE 0 END) as out_compliance
                FROM
                    tbresources
                GROUP BY
                    scan_id
            ) c ON p.scan_id = c.scan_id
            WHERE            
                p.type = ?
            ORDER BY
                p.scan_id DESC
            LIMIT
                ?
            """
            
            parameters = (process_type, 100,)
            rows = ds.execute_select(select_query, parameters)
            
            processes = []
            for row in rows:
                process = {
                    "scan_id": row[0],
                    "name": row[1],
                    "parameters": row[2],
                    "start_time": row[3],
                    "end_time": row[4],
                    "status": row[5],
                    "message": row[6],
                    "resources": row[7],
                    "in_compliance": row[8],
                    "out_compliance": row[9]
                }
                processes.append(process)
            
            return create_response(200, {
                "response": {
                    "processes": processes
                }
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_005_get_dataset_metadata_bases: {str(e)}")
            return create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )
    
    def api_006_get_metadata_search(self, params: dict) -> dict:
        """
        Get metadata search details.
        
        ProcessId: metadata::api-006-get-metadata-search
        Original: fn_14_get_metadata_search
        
        Args:
            params: Request parameters containing:
                - scanId: Scan identifier
                - filter: SQL filter clause
                
        Returns:
            Dictionary with filtered resources
        """
        try:
            filter_clause = params['filter']
            if not isinstance(filter_clause, str) or not filter_clause.strip():
                filter_clause = 'true'
            
            resources = []
            select_query = f"""
            SELECT * FROM (
                            SELECT
                                scan_id,            
                                seq,
                                account_id, 
                                region, 
                                service,
                                resource_type, 
                                resource_id, 
                                name,
                                creation_date,
                                tags,  
                                tags_number,          
                                arn,
                                case  when ( {filter_clause} ) then 1 else 0 end as filtered
                            FROM
                                tbresources
                            WHERE
                                scan_id = ?     
            ) results       
            WHERE
                filtered = 1    
            ORDER BY
                resource_id ASC
            """
            
            parameters = (params['scanId'],)
            
            ds = DataStore(db_config=self.db_config, region=self.region)
            rows = ds.execute_select(select_query, parameters)
            for row in rows:
                resources.append({
                    'scan_id': row[0],
                    'seq': row[1],
                    'account': row[2],
                    'region': row[3],
                    'service': row[4],
                    'type': row[5],
                    'identifier': row[6],
                    'name': row[7],
                    'creation': row[8],
                    'tags_list': row[9],
                    'tags_number': row[10],
                    'arn': row[11]
                })
            
            return create_response(200, {
                "response": {
                    "resources": resources
                }
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_006_get_metadata_search: {str(e)}")
            return create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )
    
    def api_007_get_dataset_metadata_information(self, params: dict) -> dict:
        """
        Get dataset metadata information.
        
        ProcessId: metadata::api-007-get-dataset-metadata-information
        Original: fn_15_get_dataset_metadata_information
        
        Args:
            params: Request parameters containing:
                - scanId: Scan identifier
                
        Returns:
            Dictionary with process information
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
                resources
            FROM
                tbprocess
            WHERE            
                scan_id = ?
            """
            
            parameters = (params['scanId'],)
            rows = ds.execute_select(select_query, parameters)
            
            processes = {}
            for row in rows:
                processes = {
                    "scan_id": row[0],
                    "name": row[1],
                    "parameters": row[2],
                    "start_time": row[3],
                    "end_time": row[4],
                    "status": row[5],
                    "message": row[6],
                    "resources": row[7]
                }
            
            return create_response(200, {
                "response": {
                    "processes": processes
                }
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_007_get_dataset_metadata_information: {str(e)}")
            return create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )
    
    def api_008_delete_metadata_base(self, params: dict) -> dict:
        """
        Delete metadata base.
        
        ProcessId: metadata::api-008-delete-metadata-base
        Original: fn_16_delete_metadata_base
        
        Args:
            params: Request parameters containing:
                - scanId: Scan identifier
                
        Returns:
            Dictionary with deletion status
        """
        try:
            ds = DataStore(db_config=self.db_config, region=self.region)
            parameters = (params['scanId'],)
            
            delete_query = """
            DELETE FROM tbprocess
            WHERE scan_id = ?
            """
            ds.execute_dml(delete_query, parameters)
            
            delete_query = """
            DELETE FROM tbresources
            WHERE scan_id = ?
            """
            ds.execute_dml(delete_query, parameters)
            
            return create_response(200, {
                "response": {
                    "status": "success"
                }
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_008_delete_metadata_base: {str(e)}")
            return create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )
    
    def api_009_get_compliance_score(self, params: dict) -> dict:
        """
        Get compliance score.
        
        ProcessId: metadata::api-009-get-compliance-score
        Original: fn_22_get_compliance_score
        
        Args:
            params: Request parameters containing:
                - scanId: Scan identifier
                
        Returns:
            Dictionary with compliance summary and breakdowns
        """
        try:
            ds = DataStore(db_config=self.db_config, region=self.region)
            
            # Summary
            select_query = """
            SELECT
                SUM(case when action = 2 then 1 else 0 end) in_compliance,
                SUM(case when action = 1 then 1 else 0 end) out_compliance,
                COUNT(*) total
            FROM
                tbresources
            WHERE
                scan_id = ?
            """
            
            parameters = (params['scanId'],)
            rows = ds.execute_select(select_query, parameters)
            
            summary = {}
            for row in rows:
                summary = {
                    "in_compliance": row[0],
                    "out_compliance": row[1],
                    "total": row[2]
                }
            
            # In-Compliance
            select_query = """
            SELECT
                service,
                COUNT(*) total
            FROM
                tbresources
            WHERE
                scan_id = ?
                AND 
                action = 2
            GROUP BY service
            """
            
            parameters = (params['scanId'],)
            rows = ds.execute_select(select_query, parameters)
            
            resources_in_compliance = []
            for row in rows:
                resources_in_compliance.append({
                    "title": row[0],
                    "value": row[1]
                })
            
            # Out-Compliance
            select_query = """
            SELECT
                service,
                COUNT(*) total
            FROM
                tbresources
            WHERE
                scan_id = ?
                AND 
                action = 1
            GROUP BY service
            """
            
            parameters = (params['scanId'],)
            rows = ds.execute_select(select_query, parameters)
            
            resources_out_compliance = []
            for row in rows:
                resources_out_compliance.append({
                    "title": row[0],
                    "value": row[1]
                })
            
            return create_response(200, {
                "response": {
                    "summary": summary,
                    "in_compliance": resources_in_compliance,
                    "out_compliance": resources_out_compliance
                }
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_009_get_compliance_score: {str(e)}")
            return create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )
    
    def api_010_get_tag_explorer_items(self, params: dict) -> dict:
        """
        Get tag explorer items with key-value counts and account/region breakdown.
        
        ProcessId: metadata::api-010-get-tag-explorer-items
        
        Args:
            params: Request parameters containing:
                - scanId: Scan identifier
                
        Returns:
            Dictionary with tag keys, values, counts with account/region breakdown
        """
        try:
            ds = DataStore(db_config=self.db_config, region=self.region)
            
            # Get total resources
            total_query = "SELECT COUNT(*) FROM tbresources WHERE scan_id = ?"
            parameters = (params['scanId'],)
            rows = ds.execute_select(total_query, parameters)
            total_resources = rows[0][0] if rows else 0
            
            # Get key-value-account-region counts
            select_query = """
            SELECT 
                json_each.key AS tag_key,
                json_each.value AS tag_value,
                account_id,
                region,
                COUNT(*) AS cnt
            FROM 
                tbresources,
                json_each(tbresources.tags)
            WHERE
                scan_id = ?
                AND json_each.key NOT LIKE 'aws:cloudformation%'
                AND json_each.key != 'Name'
            GROUP BY 
                json_each.key,
                json_each.value,
                account_id,
                region
            ORDER BY 
                json_each.key,
                cnt DESC
            """
            
            parameters = (params['scanId'],)
            rows = ds.execute_select(select_query, parameters)
            
            # Build nested structure: key -> value -> {total, accounts: {acct: {total, regions: {rgn: count}}}}
            tags_dict = {}
            key_totals = {}
            
            for row in rows:
                key = row[0]
                value = row[1] if row[1] else "Empty"
                account = row[2]
                region = row[3]
                count = row[4]
                
                if key not in tags_dict:
                    tags_dict[key] = {}
                    key_totals[key] = 0
                
                if value not in tags_dict[key]:
                    tags_dict[key][value] = {"total": 0, "accounts": {}}
                
                tags_dict[key][value]["total"] += count
                
                if account not in tags_dict[key][value]["accounts"]:
                    tags_dict[key][value]["accounts"][account] = {"total": 0, "regions": {}}
                
                tags_dict[key][value]["accounts"][account]["total"] += count
                tags_dict[key][value]["accounts"][account]["regions"][region] = count
                key_totals[key] += count
            
            # Calculate "Missing" with account->region breakdown
            if key_totals:
                missing_query = """
                SELECT account_id, region, COUNT(*) AS cnt
                FROM tbresources
                WHERE scan_id = ?
                AND json_extract(tags, ?) IS NULL
                GROUP BY account_id, region
                """
                
                for key in list(tags_dict.keys()):
                    missing_count = total_resources - key_totals[key]
                    if missing_count > 0:
                        json_path = f'$.{key}'
                        m_rows = ds.execute_select(missing_query, (params['scanId'], json_path))
                        
                        missing_entry = {"total": missing_count, "accounts": {}}
                        for m_row in m_rows:
                            acct = m_row[0]
                            rgn = m_row[1]
                            cnt = m_row[2]
                            if acct not in missing_entry["accounts"]:
                                missing_entry["accounts"][acct] = {"total": 0, "regions": {}}
                            missing_entry["accounts"][acct]["total"] += cnt
                            missing_entry["accounts"][acct]["regions"][rgn] = cnt
                        
                        tags_dict[key]["Missing"] = missing_entry
            
            return create_response(200, {
                "response": {
                    "tags": tags_dict,
                    "total": total_resources
                }
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_010_get_tag_explorer_items: {str(e)}")
            return create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )
    
    def api_011_get_tag_explorer_items_filtered(self, params: dict) -> dict:
        """
        Get filtered resources by tag key and value with pagination.
        
        ProcessId: metadata::api-011-get-tag-explorer-items-filtered
        
        Args:
            params: Request parameters containing:
                - scanId: Scan identifier
                - tagKey: Tag key to filter by
                - tagValue: Tag value to filter by (use "Missing" for resources without the key)
                - page: Page number (default: 0)
                - limit: Results per page (default: 50)
                
        Returns:
            Dictionary with resources, pages, and records count
        """
        try:
            ds = DataStore(db_config=self.db_config, region=self.region)
            
            # Log received parameters
            self.logger.info(f"Received params: {params}")
            
            # Safely get parameters with defaults
            page_param = params.get('page')
            limit_param = params.get('limit')
            tag_key = params.get('tagKey')
            tag_value = params.get('tagValue')
            filter_account = params.get('filterAccount', '')
            filter_region = params.get('filterRegion', '')
            
            self.logger.info(f"page_param: {page_param}, limit_param: {limit_param}, tag_key: {tag_key}, tag_value: {tag_value}, account: {filter_account}, region: {filter_region}")
            
            # Convert to int with defaults
            page = int(page_param) if page_param is not None else 0
            limit = int(limit_param) if limit_param is not None else 50
            
            if not tag_key:
                return create_error_response(
                    400,
                    "tagKey parameter is required",
                    ERROR_CODES["INVALID_REQUEST"]
                )
            
            if tag_value is None:
                return create_error_response(
                    400,
                    "tagValue parameter is required",
                    ERROR_CODES["INVALID_REQUEST"]
                )
            
            # Build extra filter clauses
            extra_where = ""
            extra_params = []
            if filter_account:
                extra_where += " AND account_id = ?"
                extra_params.append(filter_account)
            if filter_region:
                extra_where += " AND region = ?"
                extra_params.append(filter_region)
            
            # Build query based on whether we're looking for Missing or a specific value
            if tag_value == "Missing":
                # Resources that don't have this key
                count_query = f"""
                SELECT COUNT(*)
                FROM tbresources
                WHERE scan_id = ?
                AND (json_extract(tags, ?) IS NULL)
                {extra_where}
                """
                
                select_query = f"""
                SELECT
                    scan_id,
                    seq,
                    account_id,
                    region,
                    service,
                    resource_type,
                    resource_id,
                    name,
                    creation_date,
                    tags,
                    tags_number,
                    arn
                FROM tbresources
                WHERE scan_id = ?
                AND (json_extract(tags, ?) IS NULL)
                {extra_where}
                ORDER BY seq ASC
                LIMIT ? OFFSET ?
                """
                
                json_path = f'$.{tag_key}'
                count_params = tuple([params['scanId'], json_path] + extra_params)
                select_params = tuple([params['scanId'], json_path] + extra_params + [limit, page * limit])
            else:
                # Resources that have this specific key-value pair
                count_query = f"""
                SELECT COUNT(*)
                FROM tbresources
                WHERE scan_id = ?
                AND json_extract(tags, ?) = ?
                {extra_where}
                """
                
                select_query = f"""
                SELECT
                    scan_id,
                    seq,
                    account_id,
                    region,
                    service,
                    resource_type,
                    resource_id,
                    name,
                    creation_date,
                    tags,
                    tags_number,
                    arn
                FROM tbresources
                WHERE scan_id = ?
                AND json_extract(tags, ?) = ?
                {extra_where}
                ORDER BY seq ASC
                LIMIT ? OFFSET ?
                """
                
                json_path = f'$.{tag_key}'
                count_params = tuple([params['scanId'], json_path, tag_value] + extra_params)
                select_params = tuple([params['scanId'], json_path, tag_value] + extra_params + [limit, page * limit])
            
            # Get total count
            rows = ds.execute_select(count_query, count_params)
            total_records = rows[0][0] if rows else 0
            pages = math.ceil(total_records / limit)
            
            # Get resources
            rows = ds.execute_select(select_query, select_params)
            resources = []
            for row in rows:
                resources.append({
                    'scan_id': row[0],
                    'seq': row[1],
                    'account': row[2],
                    'region': row[3],
                    'service': row[4],
                    'type': row[5],
                    'identifier': row[6],
                    'name': row[7],
                    'creation': row[8],
                    'tags_list': row[9],
                    'tags_number': row[10],
                    'arn': row[11]
                })
            
            return create_response(200, {
                "response": {
                    "resources": resources,
                    "pages": pages,
                    "records": total_records,
                    "tagKey": tag_key,
                    "tagValue": tag_value
                }
            })
        
        except Exception as e:
            self.logger.error(f"Error in api_011_get_tag_explorer_items_filtered: {str(e)}")
            return create_error_response(
                500,
                "Internal server error",
                ERROR_CODES["INTERNAL_ERROR"]
            )

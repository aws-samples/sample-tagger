"""
API Functions Module

This module contains all 25 API process functions extracted from Lambda API.
These functions handle the business logic for the Taggr API endpoints.

Extracted from artifacts/lambda.api/lambda_function.py
"""

import os
import json
from datetime import datetime
import logging
import boto3
from typing import Dict, Any
import math
import importlib.util
import sys
import concurrent.futures
import urllib.request
import zipfile
import shutil
from collections import Counter
import threading

# Add parent directory to path for ref imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from class_tools import (
    APIGatewayResponse,
    ErrorResponse,
    DataStore,
    CORS_HEADERS,
    ERROR_CODES
)
from class_discovery import AWSResourceDiscovery
from class_tagger import AWSResourceTagger
from class_configuration import classConfiguration

logger = logging.getLogger()
logger.setLevel(logging.INFO)


######################################################
# Helper Functions
######################################################

def create_response(status_code: int, body: Any) -> APIGatewayResponse:
    """
    Create API Gateway compatible response.
    
    Args:
        status_code: HTTP status code
        body: Response body (will be JSON serialized)
        
    Returns:
        APIGatewayResponse dictionary
    """
    return {
        "statusCode": status_code,
        "headers": CORS_HEADERS,
        "body": json.dumps(body)
    }


def create_error_response(status_code: int, message: str, code: str) -> APIGatewayResponse:
    """
    Create error response.
    
    Args:
        status_code: HTTP status code
        message: Error message
        code: Error code
        
    Returns:
        APIGatewayResponse dictionary with error
    """
    error_response: ErrorResponse = {
        "message": message,
        "code": code
    }
    return create_response(status_code, error_response)


######################################################
# API Process Functions
######################################################

def fn_01_get_metadata_results(event: dict, db_config: dict, region: str) -> APIGatewayResponse:
    """
    Get metadata results with pagination.
    
    Args:
        event: Request parameters containing scanId, action, page, limit
        db_config: Database configuration
        region: AWS region
        
    Returns:
        APIGatewayResponse with resources, pages, and records count
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
            scan_id = %s
            AND
            ( action = %s OR %s = 3)       
        """
        
        parameters = (event['scanId'], int(event['action']), int(event['action']))
        
        ds = DataStore(db_config=db_config, region=region)
        rows = ds.execute_select(select_query, parameters)
        for row in rows:
            total_records = row[0]
        
        pages = math.ceil(total_records / int(event['limit']))
        
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
            scan_id = %s
            AND
            ( action = %s OR %s = 3)
        ORDER BY
            seq ASC
        OFFSET 
            %s
        LIMIT 
            %s
        """
        
        parameters = (
            event['scanId'],
            int(event['action']),
            int(event['action']),
            int(event['page']) * int(event['limit']),
            int(event['limit'])
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
        logger.error(f"Error in fn_01_get_metadata_results: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )


def fn_02_create_metadata_search(event: dict, db_config: dict, region: str, config: classConfiguration = None) -> APIGatewayResponse:
    """
    Launch discovery process (replaces Lambda invocation with direct class instantiation).
    
    Args:
        event: Request parameters containing scanId, name, ruleset, type
        db_config: Database configuration
        region: AWS region
        
    Returns:
        APIGatewayResponse with scan_id and state
    """
    try:
        # Write data store record
        create_table_query = """        
        CREATE TABLE IF NOT EXISTS tbprocess (            
            scan_id VARCHAR,            
            name VARCHAR,
            parameters VARCHAR,
            start_time VARCHAR,
            end_time VARCHAR,
            status VARCHAR,
            message VARCHAR,
            resources INT DEFAULT 0,
            start_time_tagging VARCHAR,
            end_time_tagging VARCHAR,
            status_tagging VARCHAR,
            message_tagging VARCHAR,
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
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        insert_data = [
            (
                event['scanId'],
                event['name'],
                json.dumps(event['ruleset']),
                (datetime.now()).strftime("%Y-%m-%d %H:%M:%S"),
                "-",
                "in-progress",
                "-",
                event['type']
            )
        ]
        
        ds = DataStore(db_config=db_config, region=region)
        ds.execute_command(create_table_query)
        ds.execute_insert(insert_query, insert_data)
        
        # Run discovery asynchronously in a separate thread
        def run_discovery():
            try:
                scan_id = event['scanId']
                accounts = event['ruleset']['accounts']
                regions_list = event['ruleset']['regions']
                services = event['ruleset']['services']
                filter_clause = event['ruleset']['filter']
                max_workers = config.get_max_workers() if config else int(os.environ.get('MAX_WORKERS', '10'))
                
                # Create tag collector
                tag_collector = AWSResourceDiscovery(
                    scan_id=scan_id,
                    accounts=accounts,
                    regions=regions_list,
                    services=services,
                    max_workers=max_workers,
                    role_name=config.get_iam_scan_role() if config else os.environ.get('IAM_SCAN_ROLE', 'CrossAccountTagReadRole')
                )
                
                # Load service modules from local directory
                tag_collector.load_local_modules()
                
                # Loading service catalog
                tag_collector.load_service_catalog()
                
                # Validate service catalog
                tag_collector.validate_service_catalog()
                
                # Validate region catalog
                tag_collector.validate_region_catalog()
                
                # Collect tags
                resources = tag_collector.collect_multi_account_tags()
                
                # Save results in Data Store
                db_store = DataStore(scan_id=scan_id, db_config=db_config, region=region)
                db_store.create_table()
                db_store.save_tags_to_store(resources)
                
                # Update process status
                update_query = """
                UPDATE tbprocess
                SET end_time = %s, status = %s, resources = %s
                WHERE scan_id = %s
                """
                db_store.execute(
                    update_query,
                    (
                        (datetime.now()).strftime("%Y-%m-%d %H:%M:%S"),
                        'completed',
                        len(resources),
                        scan_id
                    )
                )
                
                # Update filtered-in and filter-out
                if not isinstance(filter_clause, str) or not filter_clause.strip():
                    filter_clause = 'true'
                
                update_query = f"""
                UPDATE tbresources
                SET action = case when ( {filter_clause} ) then 1 else 2 end
                WHERE scan_id = %s
                """
                db_store.execute(update_query, (scan_id,))
                
                logger.info(f"Discovery completed for scan_id: {scan_id}")
            
            except Exception as e:
                logger.error(f"Error in discovery thread: {str(e)}")
                # Update process status with error
                try:
                    db_store = DataStore(scan_id=event['scanId'], db_config=db_config, region=region)
                    update_query = """
                    UPDATE tbprocess
                    SET end_time = %s, status = %s, message = %s
                    WHERE scan_id = %s
                    """
                    db_store.execute(
                        update_query,
                        (
                            (datetime.now()).strftime("%Y-%m-%d %H:%M:%S"),
                            'error',
                            str(e),
                            event['scanId']
                        )
                    )
                except Exception as update_error:
                    logger.error(f"Error updating process status: {str(update_error)}")
        
        # Start discovery in background thread
        discovery_thread = threading.Thread(target=run_discovery, daemon=True)
        discovery_thread.start()
        
        return create_response(200, {
            "response": {
                "scan_id": event['scanId'],
                "state": "success"
            }
        })
    
    except Exception as e:
        logger.error(f"Error in fn_02_create_metadata_search: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )


def fn_03_get_metadata_search_status(event: dict, db_config: dict, region: str) -> APIGatewayResponse:
    """
    Get status for discovery process.
    
    Args:
        event: Request parameters containing scanId
        db_config: Database configuration
        region: AWS region
        
    Returns:
        APIGatewayResponse with status and resources count
    """
    try:
        select_query = """
        SELECT
            status,
            resources
        FROM
            tbprocess
        WHERE scan_id = %s
        """
        
        parameters = (event["scanId"],)
        
        ds = DataStore(db_config=db_config, region=region)
        rows = ds.execute_select(select_query, parameters)
        status = ""
        resources = 0
        for row in rows:
            status = row[0]
            resources = row[1]
        
        return create_response(200, {
            "response": {
                "status": status,
                "resources": resources
            }
        })
    
    except Exception as e:
        logger.error(f"Error in fn_03_get_metadata_search_status: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )


def fn_04_update_resource_action(event: dict, db_config: dict, region: str) -> APIGatewayResponse:
    """
    Update resource action - filter-in / filter-out.
    
    Args:
        event: Request parameters containing scanId, seq, action
        db_config: Database configuration
        region: AWS region
        
    Returns:
        APIGatewayResponse with success status
    """
    try:
        update_query = """
        UPDATE tbresources
        SET action = %s
        WHERE scan_id = %s AND seq = %s
        """
        
        parameters = (int(event['action']), event['scanId'], int(event['seq']))
        
        ds = DataStore(db_config=db_config, region=region)
        ds.execute_dml(update_query, parameters)
        
        return create_response(200, {
            "response": {
                "status": "success"
            }
        })
    
    except Exception as e:
        logger.error(f"Error in fn_04_update_resource_action: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )


def fn_05_create_tagging_process(event: dict, db_config: dict, region: str, config: classConfiguration = None) -> APIGatewayResponse:
    """
    Launch tagging process (replaces Lambda invocation with direct class instantiation).
    
    Args:
        event: Request parameters containing scanId, tags, action
        db_config: Database configuration
        region: AWS region
        
    Returns:
        APIGatewayResponse with scan_id and state
    """
    try:
        update_query = """
        UPDATE tbprocess 
        SET start_time_tagging = %s, status_tagging = %s, message_tagging = NULL
        WHERE scan_id = %s
        """
        
        parameters = (
            (datetime.now()).strftime("%Y-%m-%d %H:%M:%S"),
            "in-progress",
            event['scanId']
        )
        
        ds = DataStore(db_config=db_config, region=region)
        ds.execute_dml(update_query, parameters)
        
        # Run tagging asynchronously in a separate thread
        def run_tagging():
            try:
                scan_id = event['scanId']
                tags_object = event['tags']
                tags_action = int(event['action'])
                max_workers = config.get_max_workers() if config else int(os.environ.get('MAX_WORKERS', '10'))
                
                # Select resources to tag
                ds_tagging = DataStore(db_config=db_config, region=region)
                
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
                    scan_id = %s
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
                    max_workers=max_workers,
                    role_name=config.get_iam_scan_role() if config else os.environ.get('IAM_SCAN_ROLE', 'CrossAccountTagReadRole')
                )
                
                # Load service modules from local directory
                tagger.load_local_modules()
                
                # Tag resources and get results
                results = tagger.tag_resources(resources, tags_string, tags_action)
                
                # Get summary results
                status_counter = Counter(item['status'] for item in results if 'status' in item)
                
                update_query = """
                UPDATE tbprocess
                SET end_time_tagging = %s, status_tagging = %s, message_tagging = %s, 
                    resources_tagged_success = %s, resources_tagged_error = %s, action = %s
                WHERE scan_id = %s
                """
                ds_tagging.execute_dml(
                    update_query,
                    (
                        (datetime.now()).strftime("%Y-%m-%d %H:%M:%S"),
                        'completed',
                        json.dumps(status_counter),
                        status_counter.get('success', 0),
                        status_counter.get('error', 0),
                        tags_action,
                        scan_id
                    )
                )
                
                error_items = [item for item in results if item.get('status') == 'error']
                ds_tagging.save_tags_errors(scan_id, error_items)
                
                logger.info(f"Tagging completed for scan_id: {scan_id}")
            
            except Exception as e:
                logger.error(f"Error in tagging thread: {str(e)}")
                # Update process status with error
                try:
                    ds_error = DataStore(db_config=db_config, region=region)
                    update_query = """
                    UPDATE tbprocess
                    SET end_time_tagging = %s, status_tagging = %s, message_tagging = %s
                    WHERE scan_id = %s
                    """
                    ds_error.execute_dml(
                        update_query,
                        (
                            (datetime.now()).strftime("%Y-%m-%d %H:%M:%S"),
                            'error',
                            str(e),
                            event['scanId']
                        )
                    )
                except Exception as update_error:
                    logger.error(f"Error updating process status: {str(update_error)}")
        
        # Start tagging in background thread
        tagging_thread = threading.Thread(target=run_tagging, daemon=True)
        tagging_thread.start()
        
        return create_response(200, {
            "response": {
                "scan_id": event['scanId'],
                "state": "success"
            }
        })
    
    except Exception as e:
        logger.error(f"Error in fn_05_create_tagging_process: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )


def fn_06_get_tagging_process_status(event: dict, db_config: dict, region: str) -> APIGatewayResponse:
    """
    Get status for tagging process.
    
    Args:
        event: Request parameters containing scanId
        db_config: Database configuration
        region: AWS region
        
    Returns:
        APIGatewayResponse with status and message
    """
    try:
        select_query = """
        SELECT
            status_tagging,
            message_tagging
        FROM
            tbprocess
        WHERE scan_id = %s
        """
        
        parameters = (event["scanId"],)
        
        ds = DataStore(db_config=db_config, region=region)
        rows = ds.execute_select(select_query, parameters)
        
        response = {
            "status": "",
            "message": ""
        }
        
        for row in rows:
            response['status'] = row[0]
            response['message'] = row[1]
        
        return create_response(200, {
            "response": response
        })
    
    except Exception as e:
        logger.error(f"Error in fn_06_get_tagging_process_status: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )


def fn_07_get_resource_metadata(event: dict, db_config: dict, region: str) -> APIGatewayResponse:
    """
    Get metadata for specific resource.
    
    Args:
        event: Request parameters containing scanId, seq
        db_config: Database configuration
        region: AWS region
        
    Returns:
        APIGatewayResponse with metadata
    """
    try:
        select_query = """
        SELECT
            metadata
        FROM
            tbresources
        WHERE 
            scan_id = %s
            and
            seq = %s
        """
        
        parameters = (event["scanId"], event["seq"])
        
        ds = DataStore(db_config=db_config, region=region)
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
        logger.error(f"Error in fn_07_get_resource_metadata: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )



def fn_08_get_dataset_tagging(event: dict, db_config: dict, region: str) -> APIGatewayResponse:
    """
    Get resources for specific tagging process with analytics.
    
    Args:
        event: Request parameters
        db_config: Database configuration
        region: AWS region
        
    Returns:
        APIGatewayResponse with processes, summary, and services
    """
    try:
        ds = DataStore(db_config=db_config, region=region)
        
        select_query = """
        SELECT
            scan_id,            
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
            type = 1
        ORDER BY
            scan_id DESC
        LIMIT
            %s
        """
        
        parameters = (100,)
        rows = ds.execute_select(select_query, parameters)
        
        processes = []
        summary = {"added": [], "removed": []}
        limit_records = 0
        for row in rows:
            processes.append({
                "scan_id": row[0],
                "parameters": row[1],
                "start_time": row[2],
                "end_time": row[3],
                "status": row[4],
                "message": row[5],
                "resources": row[6],
                "start_time_tagging": row[7],
                "end_time_tagging": row[8],
                "status_tagging": row[9],
                "message_tagging": row[10],
                "resources_tagged_success": row[11],
                "resources_tagged_error": row[12],
                "action": row[13]
            })
            if limit_records < 10:
                if row[13] == 1:
                    summary['added'].append({"x": row[0], "y": row[11]})
                    summary['removed'].append({"x": row[0], "y": 0})
                elif row[13] == 2:
                    summary['added'].append({"x": row[0], "y": 0})
                    summary['removed'].append({"x": row[0], "y": row[11]})
            
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
            ORDER BY
                scan_id DESC
            LIMIT
                %s
        )
            AND
            action = 1
        GROUP BY
            scan_id,
            service
        ORDER BY
            scan_id DESC
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
        logger.error(f"Error in fn_08_get_dataset_tagging: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )


def fn_09_create_profile(event: dict, db_config: dict, region: str) -> APIGatewayResponse:
    """
    Create a profile.
    
    Args:
        event: Request parameters containing profileId, jsonProfile
        db_config: Database configuration
        region: AWS region
        
    Returns:
        APIGatewayResponse with profile_id and state
    """
    try:
        create_table_query = """        
        CREATE TABLE IF NOT EXISTS tbprofiles (            
            profile_id VARCHAR,            
            json_profile VARCHAR,
            PRIMARY KEY (profile_id)
        )
        """
        
        insert_query = """
        INSERT INTO tbprofiles (
            profile_id,
            json_profile
        )
        VALUES (%s, %s)
        """
        
        insert_data = [
            (event['profileId'], json.dumps(event['jsonProfile']))
        ]
        
        ds = DataStore(db_config=db_config, region=region)
        ds.execute_command(create_table_query)
        ds.execute_insert(insert_query, insert_data)
        
        return create_response(200, {
            "response": {
                "profile_id": event['profileId'],
                "state": "success"
            }
        })
    
    except Exception as e:
        logger.error(f"Error in fn_09_create_profile: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )


def fn_10_update_profile(event: dict, db_config: dict, region: str) -> APIGatewayResponse:
    """
    Update a profile.
    
    Args:
        event: Request parameters containing profileId, jsonProfile
        db_config: Database configuration
        region: AWS region
        
    Returns:
        APIGatewayResponse with profileId, jsonProfile, and state
    """
    try:
        update_query = """
        UPDATE tbprofiles
        SET json_profile = %s
        WHERE profile_id = %s
        """
        
        parameters = (json.dumps(event['jsonProfile']), event['profileId'])
        
        ds = DataStore(db_config=db_config, region=region)
        ds.execute_dml(update_query, parameters)
        
        return create_response(200, {
            "response": {
                "profileId": event['profileId'],
                "jsonProfile": event['jsonProfile'],
                "state": "success"
            }
        })
    
    except Exception as e:
        logger.error(f"Error in fn_10_update_profile: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )


def fn_11_delete_profile(event: dict, db_config: dict, region: str) -> APIGatewayResponse:
    """
    Delete a profile.
    
    Args:
        event: Request parameters containing profileId
        db_config: Database configuration
        region: AWS region
        
    Returns:
        APIGatewayResponse with scan_id and state
    """
    try:
        update_query = """
        DELETE FROM tbprofiles      
        WHERE profile_id = %s
        """
        
        parameters = (event['profileId'],)
        
        ds = DataStore(db_config=db_config, region=region)
        ds.execute_dml(update_query, parameters)
        
        return create_response(200, {
            "response": {
                "scan_id": event['profileId'],
                "state": "success"
            }
        })
    
    except Exception as e:
        logger.error(f"Error in fn_11_delete_profile: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )


def fn_12_get_profiles(event: dict, db_config: dict, region: str) -> APIGatewayResponse:
    """
    Get profiles.
    
    Args:
        event: Request parameters
        db_config: Database configuration
        region: AWS region
        
    Returns:
        APIGatewayResponse with profiles array
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
        
        ds = DataStore(db_config=db_config, region=region)
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
        logger.error(f"Error in fn_12_get_profiles: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )


def fn_13_get_dataset_metadata_bases(event: dict, db_config: dict, region: str) -> APIGatewayResponse:
    """
    Get metadata bases.
    
    Args:
        event: Request parameters containing type
        db_config: Database configuration
        region: AWS region
        
    Returns:
        APIGatewayResponse with processes array
    """
    try:
        ds = DataStore(db_config=db_config, region=region)
        
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
            type = %s
        ORDER BY
            scan_id DESC
        LIMIT
            %s
        """
        
        parameters = (event['type'], 100,)
        rows = ds.execute_select(select_query, parameters)
        
        processes = []
        for row in rows:
            processes.append({
                "scan_id": row[0],
                "name": row[1],
                "parameters": row[2],
                "start_time": row[3],
                "end_time": row[4],
                "status": row[5],
                "message": row[6],
                "resources": row[7]
            })
        
        return create_response(200, {
            "response": {
                "processes": processes
            }
        })
    
    except Exception as e:
        logger.error(f"Error in fn_13_get_dataset_metadata_bases: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )


def fn_14_get_metadata_search(event: dict, db_config: dict, region: str) -> APIGatewayResponse:
    """
    Get resources for specific filter - metadata bases.
    
    Args:
        event: Request parameters containing scanId, filter
        db_config: Database configuration
        region: AWS region
        
    Returns:
        APIGatewayResponse with resources array
    """
    try:
        filter_clause = event['filter']
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
                            scan_id = %s     
        ) results       
        WHERE
            filtered = 1    
        ORDER BY
            resource_id ASC
        """
        
        parameters = (event['scanId'],)
        
        ds = DataStore(db_config=db_config, region=region)
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
        logger.error(f"Error in fn_14_get_metadata_search: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )


def fn_15_get_dataset_metadata_information(event: dict, db_config: dict, region: str) -> APIGatewayResponse:
    """
    Get information for specific metadata base.
    
    Args:
        event: Request parameters containing scanId
        db_config: Database configuration
        region: AWS region
        
    Returns:
        APIGatewayResponse with processes dictionary
    """
    try:
        ds = DataStore(db_config=db_config, region=region)
        
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
            scan_id = %s
        """
        
        parameters = (event['scanId'],)
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
        logger.error(f"Error in fn_15_get_dataset_metadata_information: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )


def fn_16_delete_metadata_base(event: dict, db_config: dict, region: str) -> APIGatewayResponse:
    """
    Delete a metadata base.
    
    Args:
        event: Request parameters containing scanId
        db_config: Database configuration
        region: AWS region
        
    Returns:
        APIGatewayResponse with status
    """
    try:
        ds = DataStore(db_config=db_config, region=region)
        parameters = (event['scanId'],)
        
        delete_query = """
        DELETE FROM tbprocess
        WHERE scan_id = %s
        """
        ds.execute_dml(delete_query, parameters)
        
        delete_query = """
        DELETE FROM tbresources
        WHERE scan_id = %s
        """
        ds.execute_dml(delete_query, parameters)
        
        return create_response(200, {
            "response": {
                "status": "success"
            }
        })
    
    except Exception as e:
        logger.error(f"Error in fn_16_delete_metadata_base: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )


def fn_17_get_list_modules_from_s3(event: dict, db_config: dict, region: str, config: classConfiguration = None) -> APIGatewayResponse:
    """
    List modules from S3.
    
    Args:
        event: Request parameters
        db_config: Database configuration
        region: AWS region
        
    Returns:
        APIGatewayResponse with modules array
    """
    try:
        s3_bucket = config.get_s3_bucket_modules() if config else os.environ.get('S3_BUCKET_MODULES', '')
        s3 = boto3.client('s3', region_name=region)
        response = s3.list_objects_v2(Bucket=s3_bucket)
        
        modules = [
            {
                'name': item['Key'][:-3],
                'size': item['Size'],
                'lastModified': item['LastModified'].isoformat()
            }
            for item in response.get('Contents', [])
            if item['Key'].endswith('.py')
        ]
        
        return create_response(200, {
            "response": {
                "modules": modules
            }
        })
    
    except Exception as e:
        logger.error(f"Error in fn_17_get_list_modules_from_s3: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )


def fn_18_get_module_content_from_s3(event: dict, db_config: dict, region: str, config: classConfiguration = None) -> APIGatewayResponse:
    """
    Get module content from S3.
    
    Args:
        event: Request parameters containing fileName
        db_config: Database configuration
        region: AWS region
        
    Returns:
        APIGatewayResponse with content
    """
    try:
        s3_bucket = config.get_s3_bucket_modules() if config else os.environ.get('S3_BUCKET_MODULES', '')
        s3 = boto3.client('s3', region_name=region)
        response = s3.get_object(Bucket=s3_bucket, Key=event['fileName'] + ".py")
        content = response['Body'].read().decode('utf-8')
        
        return create_response(200, {
            "response": {
                "content": content
            }
        })
    
    except Exception as e:
        logger.error(f"Error in fn_18_get_module_content_from_s3: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )


def fn_19_save_module_content_to_s3(event: dict, db_config: dict, region: str, config: classConfiguration = None) -> APIGatewayResponse:
    """
    Save module content to S3.
    
    Args:
        event: Request parameters containing fileName, content
        db_config: Database configuration
        region: AWS region
        
    Returns:
        APIGatewayResponse with status
    """
    try:
        s3_bucket = config.get_s3_bucket_modules() if config else os.environ.get('S3_BUCKET_MODULES', '')
        s3 = boto3.client('s3', region_name=region)
        
        s3.put_object(
            Bucket=s3_bucket,
            Key=event['fileName'] + ".py",
            Body=event['content'],
            ContentType='text/plain'
        )
        
        return create_response(200, {
            "response": {
                "status": "success"
            }
        })
    
    except Exception as e:
        logger.error(f"Error in fn_19_save_module_content_to_s3: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )


def fn_20_delete_module_content_fom_s3(event: dict, db_config: dict, region: str, config: classConfiguration = None) -> APIGatewayResponse:
    """
    Delete module content from S3.
    
    Args:
        event: Request parameters containing fileName
        db_config: Database configuration
        region: AWS region
        
    Returns:
        APIGatewayResponse with status
    """
    try:
        s3_bucket = config.get_s3_bucket_modules() if config else os.environ.get('S3_BUCKET_MODULES', '')
        s3 = boto3.client('s3', region_name=region)
        
        s3.delete_object(
            Bucket=s3_bucket,
            Key=event['fileName'] + ".py"
        )
        
        return create_response(200, {
            "response": {
                "status": "success"
            }
        })
    
    except Exception as e:
        logger.error(f"Error in fn_20_delete_module_content_fom_s3: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )



def fn_21_validate_module_content(event: dict, db_config: dict, region: str, config: classConfiguration = None) -> APIGatewayResponse:
    """
    Validate module content.
    
    Args:
        event: Request parameters containing accountId, region, fileName
        db_config: Database configuration
        region: AWS region
        
    Returns:
        APIGatewayResponse with validation results
    """
    try:
        account_id = event['accountId']
        test_region = event['region']
        file_name = event['fileName'] + ".py"
        service = event['fileName']
        s3_bucket = config.get_s3_bucket_modules() if config else os.environ.get('S3_BUCKET_MODULES', '')
        iam_role = config.get_iam_scan_role() if config else os.environ.get('IAM_SCAN_ROLE', 'CrossAccountTagReadRole')
        max_workers = config.get_max_workers() if config else int(os.environ.get('MAX_WORKERS', '10'))
        
        s3 = boto3.client('s3', region_name=region)
        response = s3.get_object(Bucket=s3_bucket, Key=file_name)
        code = response['Body'].read().decode('utf-8')
        
        # Assume role
        sts_client = boto3.client('sts')
        role_arn = f'arn:aws:iam::{account_id}:role/{iam_role}'
        
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f'MultiAccountTagCollection-{account_id}'
        )
        
        session = boto3.Session(
            aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
            aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
            aws_session_token=assumed_role['Credentials']['SessionToken']
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
                        logger
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
                    logger.info(f"{service_name}, {status}, {message}")
                    all_services.extend([{
                        "service": service_name,
                        "status": status,
                        "message": message
                    }])
                    all_resources.extend(resources)
                except Exception as e:
                    logger.error(f"Error processing future: {e}")
        
        return create_response(200, {
            "response": {
                "status": "success",
                "services": all_services,
                "resources": json.dumps(all_resources, default=str)
            }
        })
    
    except Exception as e:
        logger.error(f"Error in fn_21_validate_module_content: {str(e)}")
        return create_error_response(
            500,
            f'Internal server error: {e}',
            ERROR_CODES["INTERNAL_ERROR"]
        )


def fn_22_get_compliance_score(event: dict, db_config: dict, region: str) -> APIGatewayResponse:
    """
    Get compliance scores.
    
    Args:
        event: Request parameters containing scanId
        db_config: Database configuration
        region: AWS region
        
    Returns:
        APIGatewayResponse with compliance summary
    """
    try:
        ds = DataStore(db_config=db_config, region=region)
        
        # Summary
        select_query = """
        SELECT
            SUM(case when action = 2 then 1 else 0 end) in_compliance,
            SUM(case when action = 1 then 1 else 0 end) out_compliance,
            COUNT(*) total
        FROM
            tbresources
        WHERE
            scan_id = %s
        """
        
        parameters = (event['scanId'],)
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
            scan_id = %s
            AND 
            action = 2
        GROUP BY service
        """
        
        parameters = (event['scanId'],)
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
            scan_id = %s
            AND 
            action = 1
        GROUP BY service
        """
        
        parameters = (event['scanId'],)
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
        logger.error(f"Error in fn_22_get_compliance_score: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )


def fn_23_get_tagging_errors(event: dict, db_config: dict, region: str, config: classConfiguration = None) -> APIGatewayResponse:
    """
    Get tagging errors.
    
    Args:
        event: Request parameters containing scanId
        db_config: Database configuration
        region: AWS region
        
    Returns:
        APIGatewayResponse with error resources
    """
    try:
        ds = DataStore(db_config=db_config, region=region)
        
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
            scan_id = %s
        """
        
        parameters = (event['scanId'],)
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
        logger.error(f"Error in fn_23_get_tagging_errors: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )


def fn_24_get_profile_catalog(event: dict, db_config: dict, region: str, config: classConfiguration = None) -> APIGatewayResponse:
    """
    Get profile catalog (services and regions).
    
    Args:
        event: Request parameters
        db_config: Database configuration
        region: AWS region
        
    Returns:
        APIGatewayResponse with services and regions arrays
    """
    try:
        s3_bucket = config.get_s3_bucket_modules() if config else os.environ.get('S3_BUCKET_MODULES', '')
        s3 = boto3.client('s3', region_name=region)
        
        # Get regions
        response = s3.get_object(Bucket=s3_bucket, Key="regions.json")
        regions = json.loads(response['Body'].read().decode('utf-8'))
        
        # Get list of modules
        response = s3.list_objects_v2(Bucket=s3_bucket)
        modules = [
            {
                'name': item['Key'],
                'size': item['Size'],
                'lastModified': item['LastModified'].isoformat()
            }
            for item in response.get('Contents', [])
            if item['Key'].endswith('.py')
        ]
        
        # Get resources modules
        all_services = []
        for module_item in modules:
            response = s3.get_object(Bucket=s3_bucket, Key=module_item['name'])
            code = response['Body'].read().decode('utf-8')
            
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
                all_services.append(f'{module_item["name"][:-3]}::{service}')
        
        all_services.sort()
        
        return create_response(200, {
            "response": {
                "services": all_services,
                "regions": regions
            }
        })
    
    except Exception as e:
        logger.error(f"Error in fn_24_get_profile_catalog: {str(e)}")
        return create_error_response(
            500,
            f'Internal server error: {e}',
            ERROR_CODES["INTERNAL_ERROR"]
        )


def fn_25_sync_modules_from_repo(event: dict, db_config: dict, region: str, config: classConfiguration = None) -> APIGatewayResponse:
    """
    Sync modules from GitHub repository.
    
    Args:
        event: Request parameters
        db_config: Database configuration
        region: AWS region
        
    Returns:
        APIGatewayResponse with status and file count
    """
    try:
        s3_bucket = config.get_s3_bucket_modules() if config else os.environ.get('S3_BUCKET_MODULES', '')
        s3 = boto3.client('s3', region_name=region)
        
        # S3 configuration
        s3_prefix = ""
        
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
        
        logger.info(f"Downloading repository from {zip_url}")
        urllib.request.urlretrieve(zip_url, zip_path)
        
        # Extract the repo
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall("/tmp")
        
        # Path to the extracted directory containing the target folder
        extracted_dir = f"/tmp/sample-tagger-{github_branch}"
        source_dir = os.path.join(extracted_dir, github_dir)
        
        # Upload only .py files to S3
        file_count = 0
        for root, dirs, files in os.walk(source_dir):
            for file in files:
                # Only process Python files
                if file.endswith('.py'):
                    local_path = os.path.join(root, file)
                    # Get relative path from the modules directory
                    relative_path = os.path.relpath(local_path, source_dir)
                    s3_key = s3_prefix + relative_path
                    
                    logger.info(f"Uploading Python file {local_path} to s3://{s3_bucket}/{s3_key}")
                    s3.upload_file(local_path, s3_bucket, s3_key)
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
        logger.error(f"Error in fn_25_sync_modules_from_repo: {str(e)}")
        return create_error_response(
            500,
            f'Internal server error: {e}',
            ERROR_CODES["INTERNAL_ERROR"]
        )

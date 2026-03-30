"""
Shared Tools Module

This module contains shared classes and utilities used across the Taggr API:
- DataStore: Unified database operations class
- Type definitions: APIGatewayResponse, ErrorResponse, ResourceInfo
- Constants: CORS_HEADERS, ERROR_CODES
"""

import os
import json
import logging
from datetime import datetime
from typing import TypedDict, Any, List, Tuple, Optional
from dataclasses import dataclass
import psycopg2
from psycopg2 import pool
from psycopg2.extras import execute_values
import boto3


######################################################
# Type Definitions
######################################################

class APIGatewayResponse(TypedDict):
    """Response format matching API Gateway Lambda integration"""
    statusCode: int
    headers: dict[str, str]
    body: str


class ErrorResponse(TypedDict):
    """Error response format"""
    message: str
    code: str


@dataclass
class ResourceInfo:
    """Resource information for tagging operations"""
    account_id: str
    region: str
    service: str
    identifier: str
    arn: str


######################################################
# Constants
######################################################

CORS_HEADERS = {
    "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,X-Amz-Security-Token,Authorization,X-Api-Key,X-Requested-With,Accept,Access-Control-Allow-Methods,Access-Control-Allow-Origin,Access-Control-Allow-Headers",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT",
    "X-Requested-With": "*"
}

ERROR_CODES = {
    "BAD_REQUEST": "BAD_REQUEST",
    "NOT_FOUND": "NOT_FOUND",
    "INTERNAL_ERROR": "INTERNAL_ERROR"
}


######################################################
# DataStore Class - Unified from all Lambda sources
######################################################

class DataStore:
    """
    Unified database operations class for Aurora DSQL.
    
    Consolidates DataStore functionality from:
    - Lambda API: execute_query, execute_command, execute_insert, execute_dml, execute_select
    - Lambda Discovery: execute, save_tags_to_store, save_tags_to_file, create_table, 
                       timestamp_to_string, serialize_datetime
    - Lambda Tagger: save_tags_errors
    
    Attributes:
        scan_id: Optional scan identifier (used by Discovery)
        metadata_path: Path for metadata file storage
        connection_pool: PostgreSQL connection pool
        logger: Logger instance
    """
    
    def __init__(
        self,
        scan_id: Optional[str] = None,
        db_config: Optional[dict] = None,
        region: Optional[str] = None
    ):
        """
        Initialize DataStore with database configuration.
        
        Args:
            scan_id: Optional scan identifier (used by Discovery, optional for API/Tagger)
            db_config: Database connection parameters (host, database, user, port, sslmode)
            region: AWS region for IAM authentication
        """
        self.scan_id = scan_id
        self.metadata_path = '/tmp/metadata'
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Create connection pool with IAM authentication
        try:
            # Try to use DSQL IAM authentication if available
            try:
                client = boto3.client("dsql", region_name=region)
                password_token = client.generate_db_connect_admin_auth_token(
                    db_config['host'], 
                    region
                )
                self.db_config = {**db_config, 'password': password_token}
                self.logger.info("Using DSQL IAM authentication")
            except Exception as dsql_error:
                # DSQL service not available, try RDS IAM auth or use password
                self.logger.warning(f"DSQL service not available: {dsql_error}")
                self.logger.info("Attempting RDS IAM authentication fallback")
                
                try:
                    # Try RDS IAM authentication as fallback
                    rds_client = boto3.client('rds', region_name=region)
                    password_token = rds_client.generate_db_auth_token(
                        DBHostname=db_config['host'],
                        Port=db_config['port'],
                        DBUsername=db_config['user'],
                        Region=region
                    )
                    self.db_config = {**db_config, 'password': password_token}
                    self.logger.info("Using RDS IAM authentication")
                except Exception as rds_error:
                    # If both fail, try without password (for local dev)
                    self.logger.warning(f"RDS IAM auth also failed: {rds_error}")
                    self.logger.warning("Connecting without IAM authentication - ensure database allows this")
                    self.db_config = db_config
            
            self.connection_pool = psycopg2.pool.SimpleConnectionPool(
                1, 20, **self.db_config
            )
            self.logger.info("Database connection pool initialized successfully")
        except Exception as e:
            self.logger.error(f"Error creating database connection pool: {e}")
            raise
    
    # ========================================
    # Methods from Lambda API
    # ========================================
    
    def execute_query(self, query: str) -> list:
        """
        Execute a query without parameters and return results.
        
        Args:
            query: SQL query string
            
        Returns:
            List of query results
        """
        connection = None
        cursor = None
        results = []
        
        try:
            connection = self.connection_pool.getconn()
            cursor = connection.cursor()
            cursor.execute(query)
            results = cursor.fetchall()
            connection.commit()
        except Exception as e:
            self.logger.error(f"Error in execute_query: {e}")
            if connection:
                connection.rollback()
            raise
        finally:
            if cursor:
                cursor.close()
            if connection:
                self.connection_pool.putconn(connection)
        
        return results
    
    def execute_command(self, query: str) -> list:
        """
        Execute a DDL command without parameters.
        
        Args:
            query: SQL DDL command string
            
        Returns:
            Empty list
        """
        connection = None
        cursor = None
        results = []
        
        try:
            connection = self.connection_pool.getconn()
            cursor = connection.cursor()
            cursor.execute(query)
            connection.commit()
        except Exception as e:
            self.logger.error(f"Error in execute_command: {e}")
            if connection:
                connection.rollback()
            raise
        finally:
            if cursor:
                cursor.close()
            if connection:
                self.connection_pool.putconn(connection)
        
        return results
    
    def execute_insert(self, query: str, data: list) -> list:
        """
        Execute batch INSERT using executemany().
        
        Args:
            query: SQL INSERT statement
            data: List of tuples containing data to insert
            
        Returns:
            Empty list
        """
        connection = None
        cursor = None
        results = []
        
        try:
            connection = self.connection_pool.getconn()
            cursor = connection.cursor()
            cursor.executemany(query, data)
            connection.commit()
        except Exception as e:
            self.logger.error(f"Error in execute_insert: {e}")
            if connection:
                connection.rollback()
            raise
        finally:
            if cursor:
                cursor.close()
            if connection:
                self.connection_pool.putconn(connection)
        
        return results
    
    def execute_dml(self, query: str, data: tuple) -> list:
        """
        Execute single UPDATE/DELETE with parameters.
        
        Args:
            query: SQL DML statement
            data: Tuple of parameters
            
        Returns:
            Empty list
        """
        connection = None
        cursor = None
        results = []
        
        try:
            connection = self.connection_pool.getconn()
            cursor = connection.cursor()
            cursor.execute(query, data)
            connection.commit()
        except Exception as e:
            self.logger.error(f"Error in execute_dml: {e}")
            if connection:
                connection.rollback()
            raise
        finally:
            if cursor:
                cursor.close()
            if connection:
                self.connection_pool.putconn(connection)
        
        return results
    
    def execute_select(self, query: str, data: Optional[tuple]) -> list:
        """
        Execute parameterized SELECT and return results.
        
        Args:
            query: SQL SELECT statement
            data: Tuple of parameters (can be None)
            
        Returns:
            List of query results
        """
        connection = None
        cursor = None
        results = []
        
        try:
            connection = self.connection_pool.getconn()
            cursor = connection.cursor()
            cursor.execute(query, data)
            results = cursor.fetchall()
            connection.commit()
        except Exception as e:
            self.logger.error(f"Error in execute_select: {e}")
            if connection:
                connection.rollback()
            raise
        finally:
            if cursor:
                cursor.close()
            if connection:
                self.connection_pool.putconn(connection)
        
        return results
    
    # ========================================
    # Methods from Lambda Discovery
    # ========================================
    
    def execute(self, query: str, data: tuple) -> list:
        """
        Execute generic query with parameters.
        
        Args:
            query: SQL statement
            data: Tuple of parameters
            
        Returns:
            Empty list
        """
        connection = None
        cursor = None
        results = []
        
        try:
            connection = self.connection_pool.getconn()
            cursor = connection.cursor()
            cursor.execute(query, data)
            connection.commit()
        except Exception as e:
            self.logger.error(f"Error in execute: {e}")
            if connection:
                connection.rollback()
            raise
        finally:
            if cursor:
                cursor.close()
            if connection:
                self.connection_pool.putconn(connection)
        
        return results
    
    def save_tags_to_store(self, tags: list, batch_size: int = 1000):
        """
        Save discovered resources to database in batches.
        
        Args:
            tags: List of resource dictionaries
            batch_size: Number of records per batch (default: 1000)
        """
        insert_query = """
        INSERT INTO tbresources (
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
            metadata,
            arn
        ) VALUES %s      
        """
        
        connection = None
        cursor = None
        
        try:
            connection = self.connection_pool.getconn()
            cursor = connection.cursor()
            
            # Process tags in batches
            for i in range(0, len(tags), batch_size):
                batch = tags[i:i+batch_size]
                
                # Prepare batch data
                batch_data = [
                    (
                        self.scan_id,                        
                        tag['seq'], 
                        tag['account_id'], 
                        tag['region'], 
                        tag['service'], 
                        tag['resource_type'], 
                        tag['resource_id'], 
                        tag['name'],                                                 
                        self.timestamp_to_string(tag['creation_date']),                        
                        json.dumps(tag['tags']),
                        tag['tags_number'],
                        json.dumps(tag['metadata'], default=str),
                        tag['arn'],
                    ) for tag in batch
                ]
                
                # Use execute_values for efficient batch insert
                execute_values(cursor, insert_query, batch_data)
                
                # Commit each batch
                connection.commit()
                
                self.logger.info(f"Inserted {len(batch)} records")
        except Exception as e:
            self.logger.error(f"Error saving tags to database: {e}")
            if connection:
                connection.rollback()
            raise
        finally:
            if cursor:
                cursor.close()
            if connection:
                self.connection_pool.putconn(connection)
    
    def save_tags_to_file(self, tags: list, filename: str = 'multi_account_tags.json'):
        """
        Save tags to JSON file.
        
        Args:
            tags: List of resource dictionaries
            filename: Output filename (default: 'multi_account_tags.json')
        """
        try:
            with open(filename, 'w') as f:
                json.dump(tags, f, default=str, indent=4)
            self.logger.info(f"Tags saved to {filename}")
        except Exception as e:
            self.logger.error(f"Error saving tags to file: {e}")
    
    def create_table(self):
        """Create tbresources table if it doesn't exist."""
        create_table_query = """
        CREATE TABLE IF NOT EXISTS tbresources (            
            scan_id VARCHAR,            
            seq INT,
            account_id VARCHAR,
            region VARCHAR,
            service VARCHAR,
            resource_type VARCHAR,
            resource_id VARCHAR,
            name VARCHAR,
            creation_date VARCHAR,
            tags VARCHAR,
            metadata VARCHAR,
            action INT default 0,
            tags_number INT default 0,            
            arn VARCHAR,
            PRIMARY KEY (scan_id,seq)
        )
        """
        
        connection = None
        cursor = None
        
        try:
            connection = self.connection_pool.getconn()
            cursor = connection.cursor()
            cursor.execute(create_table_query)
            connection.commit()
            self.logger.info("Resources table ensured")
        except Exception as e:
            self.logger.error(f"Error creating results table: {e}")
            if connection:
                connection.rollback()
            raise
        finally:
            if cursor:
                cursor.close()
            if connection:
                self.connection_pool.putconn(connection)
    
    def timestamp_to_string(self, timestamp: Any) -> str:
        """
        Convert various timestamp formats to string.
        
        Args:
            timestamp: Timestamp in various formats (datetime, float, int, str)
            
        Returns:
            Formatted timestamp string (YYYY-MM-DD HH:MM:SS)
        """
        try:
            # If timestamp is already a datetime object
            if isinstance(timestamp, datetime):
                dt = timestamp
            # If timestamp is a float or int (Unix timestamp)
            elif isinstance(timestamp, (float, int)):
                dt = datetime.fromtimestamp(timestamp)
            # If timestamp is a string, try parsing it
            elif isinstance(timestamp, str):
                dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            else:
                return str(timestamp)
            
            # Convert to string using the specified format
            formatted_string = dt.strftime("%Y-%m-%d %H:%M:%S")
            return formatted_string
        except Exception as e:
            return str(timestamp)
    
    def serialize_datetime(self, obj: Any) -> str:
        """
        Serialize datetime objects to ISO format.
        
        Args:
            obj: Object to serialize
            
        Returns:
            ISO formatted string
            
        Raises:
            TypeError: If object is not serializable
        """
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError("Type not serializable")
    
    # ========================================
    # Methods from Lambda Tagger
    # ========================================
    
    def save_tags_errors(self, scan_id: str, tags: list, batch_size: int = 1000):
        """
        Save tagging errors to database in batches.
        
        Args:
            scan_id: Scan identifier
            tags: List of error dictionaries
            batch_size: Number of records per batch (default: 1000)
        """
        insert_query = """
        INSERT INTO tbtag_errors (
            scan_id,            
            account_id, 
            region, 
            service,
            resource_id, 
            arn,
            status,
            error
        ) VALUES %s      
        """
        
        connection = None
        cursor = None
        
        try:
            connection = self.connection_pool.getconn()
            cursor = connection.cursor()
            
            # Process tags in batches
            for i in range(0, len(tags), batch_size):
                batch = tags[i:i+batch_size]
                
                # Prepare batch data
                batch_data = [
                    (
                        scan_id,                        
                        tag['account_id'], 
                        tag['region'], 
                        tag['service'], 
                        tag['identifier'], 
                        tag.get('arn', ''), 
                        tag['status'], 
                        tag['error']
                    ) for tag in batch
                ]
                
                # Use execute_values for efficient batch insert
                execute_values(cursor, insert_query, batch_data)
                
                # Commit each batch
                connection.commit()
                
                self.logger.info(f"Inserted {len(batch)} error records")
        except Exception as e:
            self.logger.error(f"Error saving error tags to database: {e}")
            if connection:
                connection.rollback()
            raise
        finally:
            if cursor:
                cursor.close()
            if connection:
                self.connection_pool.putconn(connection)

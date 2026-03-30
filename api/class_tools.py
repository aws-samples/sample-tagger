"""
Shared Tools Module - SQLite Version

This module contains shared classes and utilities using SQLite3:
- DataStore: Unified database operations class (SQLite3)
- Type definitions: APIGatewayResponse, ErrorResponse, ResourceInfo
- Constants: CORS_HEADERS, ERROR_CODES
"""

import os
import json
import logging
import sqlite3
from datetime import datetime
from typing import TypedDict, Any, List, Tuple, Optional
from dataclasses import dataclass
from contextlib import contextmanager


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
# DataStore Class - SQLite3 Version
######################################################

class DataStore:
    """
    Unified database operations class for SQLite3.
    
    Migrated from PostgreSQL/DSQL to SQLite3 for simplified deployment.
    Maintains same interface as original DataStore class.
    
    Attributes:
        scan_id: Optional scan identifier (used by Discovery)
        metadata_path: Path for metadata file storage
        db_path: Path to SQLite database file
        logger: Logger instance
    """
    
    def __init__(
        self,
        scan_id: Optional[str] = None,
        db_config: Optional[dict] = None,
        region: Optional[str] = None
    ):
        """
        Initialize DataStore with SQLite database.
        
        Args:
            scan_id: Optional scan identifier (used by Discovery)
            db_config: Database configuration (contains 'path' key for SQLite file)
            region: AWS region (kept for compatibility, not used in SQLite)
        """
        self.scan_id = scan_id
        self.metadata_path = '/tmp/metadata'
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Get database path from config or environment
        if db_config and 'path' in db_config:
            self.db_path = db_config['path']
        else:
            self.db_path = os.environ.get('DB_PATH', '../dbstore/tagger.db')
        
        # Ensure database directory exists
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir)
            self.logger.info(f"Created database directory: {db_dir}")
        
        # Initialize database (create if doesn't exist)
        self._initialize_database()
        
        self.logger.info(f"SQLite database initialized: {self.db_path}")
    
    def _initialize_database(self):
        """Initialize SQLite database with required tables."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Enable foreign keys
                cursor.execute("PRAGMA foreign_keys = ON")
                
                # Create tables if they don't exist
                self._create_tables(cursor)
                
                conn.commit()
                self.logger.info("Database tables initialized")
        except Exception as e:
            self.logger.error(f"Error initializing database: {e}")
            raise
    
    def _create_tables(self, cursor):
        """Create all required tables."""
        # tbprocess table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tbprocess (            
                scan_id TEXT PRIMARY KEY,            
                name TEXT,
                parameters TEXT,
                start_time TEXT,
                end_time TEXT,
                status TEXT,
                message TEXT,
                resources INTEGER DEFAULT 0,
                start_time_tagging TEXT,
                end_time_tagging TEXT,
                status_tagging TEXT,
                message_tagging TEXT,
                resources_tagged_success INTEGER DEFAULT 0,
                resources_tagged_error INTEGER DEFAULT 0,
                action INTEGER DEFAULT 0,
                type INTEGER DEFAULT 0
            )
        """)
        
        # tbresources table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tbresources (            
                scan_id TEXT,            
                seq INTEGER,
                account_id TEXT,
                region TEXT,
                service TEXT,
                resource_type TEXT,
                resource_id TEXT,
                name TEXT,
                creation_date TEXT,
                tags TEXT,
                metadata TEXT,
                action INTEGER DEFAULT 0,
                tags_number INTEGER DEFAULT 0,            
                arn TEXT,
                PRIMARY KEY (scan_id, seq)
            )
        """)
        
        # tbprofiles table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tbprofiles (            
                profile_id TEXT PRIMARY KEY,            
                json_profile TEXT
            )
        """)
        
        # tbtag_errors table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tbtag_errors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,            
                account_id TEXT, 
                region TEXT, 
                service TEXT,
                resource_id TEXT, 
                arn TEXT,
                status TEXT,
                error TEXT
            )
        """)
    
    @contextmanager
    def _get_connection(self):
        """
        Context manager for database connections.
        
        Yields:
            sqlite3.Connection: Database connection
        """
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row  # Enable column access by name
        try:
            yield conn
        finally:
            conn.close()
    
    # ========================================
    # Methods from Lambda API
    # ========================================
    
    def execute_query(self, query: str) -> list:
        """
        Execute a query without parameters and return results.
        
        Args:
            query: SQL query string
            
        Returns:
            List of query results (as tuples)
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query)
                results = cursor.fetchall()
                conn.commit()
                # Convert Row objects to tuples
                return [tuple(row) for row in results]
        except Exception as e:
            self.logger.error(f"Error in execute_query: {e}")
            raise
    
    def execute_command(self, query: str) -> list:
        """
        Execute a DDL command without parameters.
        
        Args:
            query: SQL DDL command string
            
        Returns:
            Empty list
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query)
                conn.commit()
                return []
        except Exception as e:
            self.logger.error(f"Error in execute_command: {e}")
            raise
    
    def execute_insert(self, query: str, data: list) -> list:
        """
        Execute batch INSERT using executemany().
        
        Args:
            query: SQL INSERT statement (with ? placeholders)
            data: List of tuples containing data to insert
            
        Returns:
            Empty list
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.executemany(query, data)
                conn.commit()
                return []
        except Exception as e:
            self.logger.error(f"Error in execute_insert: {e}")
            raise
    
    def execute_dml(self, query: str, data: tuple) -> list:
        """
        Execute single UPDATE/DELETE with parameters.
        
        Args:
            query: SQL DML statement (with ? placeholders)
            data: Tuple of parameters
            
        Returns:
            Empty list
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, data)
                conn.commit()
                return []
        except Exception as e:
            self.logger.error(f"Error in execute_dml: {e}")
            raise
    
    def execute_select(self, query: str, data: Optional[tuple]) -> list:
        """
        Execute parameterized SELECT and return results.
        
        Args:
            query: SQL SELECT statement (with ? placeholders)
            data: Tuple of parameters (can be None)
            
        Returns:
            List of query results (as tuples)
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                if data:
                    cursor.execute(query, data)
                else:
                    cursor.execute(query)
                results = cursor.fetchall()
                # Convert Row objects to tuples
                return [tuple(row) for row in results]
        except Exception as e:
            self.logger.error(f"Error in execute_select: {e}")
            raise
    
    # ========================================
    # Methods from Lambda Discovery
    # ========================================
    
    def execute(self, query: str, data: tuple) -> list:
        """
        Execute generic query with parameters.
        
        Args:
            query: SQL statement (with ? placeholders)
            data: Tuple of parameters
            
        Returns:
            Empty list
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, data)
                conn.commit()
                return []
        except Exception as e:
            self.logger.error(f"Error in execute: {e}")
            raise
    
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
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
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
                    
                    # Use executemany for batch insert
                    cursor.executemany(insert_query, batch_data)
                    
                    # Commit each batch
                    conn.commit()
                    
                    self.logger.info(f"Inserted {len(batch)} records")
        except Exception as e:
            self.logger.error(f"Error saving tags to database: {e}")
            raise
    
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
        # Tables are created in _initialize_database, but keep this for compatibility
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                self._create_tables(cursor)
                conn.commit()
                self.logger.info("Resources table ensured")
        except Exception as e:
            self.logger.error(f"Error creating results table: {e}")
            raise
    
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
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
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
                    
                    # Use executemany for batch insert
                    cursor.executemany(insert_query, batch_data)
                    
                    # Commit each batch
                    conn.commit()
                    
                    self.logger.info(f"Inserted {len(batch)} error records")
        except Exception as e:
            self.logger.error(f"Error saving error tags to database: {e}")
            raise

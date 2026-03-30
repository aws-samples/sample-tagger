"""
AWS Resource Discovery Module

This module contains the AWSResourceDiscovery class for discovering AWS resources
across multiple accounts and regions.

Extracted from artifacts/lambda.discovery/lambda_function.py
"""

import boto3
import os
import concurrent.futures
import json
import logging
from typing import List, Dict, Tuple
import importlib.util
import zipfile
import io

from class_tools import DataStore
from class_scan_logger import ScanLogger


class AWSResourceDiscovery:
    """
    AWS Resource Discovery class for multi-account, multi-region resource discovery.
    
    This class handles:
    - Cross-account role assumption
    - Service module management from S3
    - Service and region catalog validation
    - Parallel resource discovery across accounts, regions, and services
    
    Attributes:
        scan_id: Unique identifier for this discovery scan
        accounts: List of AWS account IDs to scan
        services: List of service types to discover (format: "service::type")
        regions: List of AWS regions to scan
        max_workers: Maximum number of parallel workers
        root_role: IAM root role for local account
        child_role: IAM child role for remote accounts
        script_path: Local path for downloaded service modules
        metadata_path: Local path for metadata storage
        service_catalog: Dictionary of available services
        region_catalog: List of available regions
        logger: Logger instance
    """
    
    def __init__(
        self,
        scan_id: str,
        accounts: List[str],
        regions: List[str],
        services: List[str],
        max_workers: int = 10,
        root_role: str = '',
        child_role: str = ''
    ):
        """
        Initialize AWSResourceDiscovery.
        
        Args:
            scan_id: Unique identifier for this discovery scan
            accounts: List of AWS account IDs to scan
            regions: List of AWS regions to scan
            services: List of service types to discover
            max_workers: Maximum number of parallel workers (default: 10)
            root_role: IAM role to assume first in the local account
            child_role: IAM role to assume in remote accounts using root role credentials
        """
        self.scan_id = scan_id
        self.accounts = accounts
        self.services = services
        self.regions = regions
        self.max_workers = max_workers
        self.root_role = root_role
        self.child_role = child_role
        self.root_session = None
        self.script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'modules')
        self.metadata_path = '/tmp/metadata'
        self.service_catalog = {}
        self.region_catalog = []
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Initialize scan logger
        self.scan_logger = ScanLogger(scan_id=scan_id, process_type='discovery')
        self.scan_logger.info(f"Discovery process initialized for scan_id: {scan_id}")
    
    def assume_role(self, account_id: str) -> boto3.Session:
        """
        Assume cross-account IAM role using two-hop chain.
        
        Flow: Local credentials -> Root Role -> Child Role (remote account)
        
        Args:
            account_id: AWS account ID to assume role in
            
        Returns:
            boto3.Session with temporary credentials
            
        Returns None if role assumption fails.
        """
        try:
            # Step 1: Assume root role (if not already cached)
            if not self.root_session:
                sts_client = boto3.client('sts')
                caller = sts_client.get_caller_identity()
                local_account = caller['Account']
                root_role_arn = f'arn:aws:iam::{local_account}:role/{self.root_role}'
                
                self.scan_logger.info(f"Assuming root role: {root_role_arn}")
                assumed_root = sts_client.assume_role(
                    RoleArn=root_role_arn,
                    RoleSessionName='TaggrRootSession'
                )
                self.root_session = boto3.Session(
                    aws_access_key_id=assumed_root['Credentials']['AccessKeyId'],
                    aws_secret_access_key=assumed_root['Credentials']['SecretAccessKey'],
                    aws_session_token=assumed_root['Credentials']['SessionToken']
                )
                self.scan_logger.info(f"Root role assumed successfully")
            
            # Step 2: Use root session to assume child role in target account
            root_sts = self.root_session.client('sts')
            child_role_arn = f'arn:aws:iam::{account_id}:role/{self.child_role}'
            
            assumed_child = root_sts.assume_role(
                RoleArn=child_role_arn,
                RoleSessionName=f'TaggrDiscovery-{account_id}'
            )
            
            self.scan_logger.info(f"Assumed child role for account {account_id}")
            return boto3.Session(
                aws_access_key_id=assumed_child['Credentials']['AccessKeyId'],
                aws_secret_access_key=assumed_child['Credentials']['SecretAccessKey'],
                aws_session_token=assumed_child['Credentials']['SessionToken']
            )
        except Exception as e:
            self.logger.error(f"Error assuming role for account {account_id}: {e}")
            self.scan_logger.error(f"Failed to assume role for account {account_id}: {str(e)}")
            return None
    
    def collect_resource_tags(
        self,
        session: boto3.Session,
        account_id: str,
        region: str,
        service: str
    ) -> Tuple[str, str, str, List[Dict]]:
        """
        Collect resource tags for a specific service.
        
        Args:
            session: boto3 Session with appropriate credentials
            account_id: AWS account ID
            region: AWS region
            service: Service type (format: "service::type")
            
        Returns:
            Tuple of (service_name, status, error_message, resources)
        """
        try:
            module_name, service_type = service.split('::')
            module_name = module_name.lower()
            
            spec = importlib.util.spec_from_file_location(
                module_name,
                f'{self.script_path}/{module_name}.py'
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            return module.discovery(
                self,
                session,
                account_id,
                region,
                module_name,
                service_type,
                self.logger
            )
        except Exception as e:
            error_msg = f"Error collecting {service} tags in {region}: {e}"
            self.logger.error(error_msg)
            self.scan_logger.error(error_msg)
            return (service, "error", str(e), [])
    
    def collect_multi_account_tags(self) -> Tuple[List[Dict], Dict]:
        """
        Collect tags from multiple accounts in parallel.
        
        Returns:
            Tuple of (resources, metrics) where:
                - resources: List of resource dictionaries with tags
                - metrics: Dictionary with execution metrics
        """
        all_tags = []
        metrics = {
            'tasks_total': 0,
            'tasks_success': 0,
            'tasks_failed': 0,
            'resources_found': 0
        }
        
        total_tasks = len(self.accounts) * len(self.regions) * len(self.services)
        completed_tasks = 0
        
        self.scan_logger.info(f"Starting discovery across {len(self.accounts)} accounts, {len(self.regions)} regions, {len(self.services)} services")
        self.scan_logger.info(f"Total discovery tasks: {total_tasks}")
        
        # Parallel account and region processing
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Prepare futures for all accounts, regions, and services
            futures = []
            for account_id in self.accounts:
                # Assume role for the account
                session = self.assume_role(account_id)
                if not session:
                    self.scan_logger.warning(f"Skipping account {account_id} due to role assumption failure")
                    continue
                
                for region in self.regions:
                    for service in self.services:
                        futures.append(
                            executor.submit(
                                self.collect_resource_tags,
                                session,
                                account_id,
                                region,
                                service
                            )
                        )
            
            # Process results and collect metrics
            for future in concurrent.futures.as_completed(futures):
                try:
                    service_name, status, message, resources = future.result()
                    completed_tasks += 1
                    metrics['tasks_total'] += 1
                    
                    if status == "success":
                        metrics['tasks_success'] += 1
                        all_tags.extend(resources)
                        self.scan_logger.info(f"[{completed_tasks}/{total_tasks}] {service_name}: Found {len(resources)} resources")
                    else:
                        metrics['tasks_failed'] += 1
                        self.scan_logger.error(f"[{completed_tasks}/{total_tasks}] {service_name}: {message}")
                        
                except Exception as e:
                    completed_tasks += 1
                    metrics['tasks_total'] += 1
                    metrics['tasks_failed'] += 1
                    self.logger.error(f"Error processing future: {e}")
                    self.scan_logger.error(f"[{completed_tasks}/{total_tasks}] Unexpected error: {str(e)}")
        
        # Add sequence number
        for seq, tag in enumerate(all_tags, 1):
            tag['seq'] = seq
        
        metrics['resources_found'] = len(all_tags)
        
        self.scan_logger.success(f"Discovery completed: {len(all_tags)} total resources found")
        self.scan_logger.info(f"Metrics - Total: {metrics['tasks_total']}, Success: {metrics['tasks_success']}, Failed: {metrics['tasks_failed']}")
        
        return all_tags, metrics
    
    def load_local_modules(self):
        """
        Load service modules and region catalog from local modules directory.
        
        Verifies the local modules directory exists, lists available Python
        module files, and loads the region catalog from regions.json.
        """
        try:
            self.logger.info(f"Loading modules from local path: {self.script_path}")
            self.scan_logger.info(f"Loading service modules from local path: {self.script_path}")
            
            if not os.path.isdir(self.script_path):
                raise FileNotFoundError(f"Modules directory not found: {self.script_path}")
            
            # Create metadata directory if needed
            os.makedirs(self.metadata_path, exist_ok=True)
            
            # List available modules
            modules = [f for f in os.listdir(self.script_path) if f.endswith('.py')]
            
            self.scan_logger.info(f"Found {len(modules)} service modules in local directory")
            
            # Load region catalog from local file
            region_catalog_path = os.path.join(self.script_path, 'regions.json')
            if os.path.isfile(region_catalog_path):
                with open(region_catalog_path, 'r') as f:
                    self.region_catalog = json.load(f)
                self.scan_logger.info(f"Loaded region catalog from local path")
            else:
                self.logger.warning(f"Region catalog not found at {region_catalog_path}")
                self.region_catalog = []
            
            self.scan_logger.success(f"Successfully loaded {len(modules)} service modules from local path")
            
        except Exception as e:
            self.logger.error(f"Error loading local modules from {self.script_path}: {e}")
            self.scan_logger.error(f"Failed to load local modules: {str(e)}")
            raise
    
    def load_service_catalog(self):
        """Load service catalog from downloaded modules."""
        try:
            service_catalog = {}
            modules = []
            
            for filename in os.listdir(self.script_path):
                if filename.endswith('.py'):
                    modules.append(filename)
            
            for module_name in modules:
                try:
                    module_name = module_name[:-3]
                    spec = importlib.util.spec_from_file_location(
                        module_name,
                        f'{self.script_path}/{module_name}.py'
                    )
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    service_types = module.get_service_types(None, None, None, None)
                    services = [f"{module_name}::{key}" for key in service_types.keys()]
                    service_catalog = {**service_catalog, f'{module_name}': services}
                
                except Exception as e:
                    self.logger.error(f"Error getting service types for {module_name}: {e}")
            
            self.service_catalog = service_catalog
            
        except Exception as e:
            self.logger.error(f"Error loading service catalog: {e}")
    
    def validate_service_catalog(self):
        """Validate and expand service selections."""
        try:
            self.logger.info(f"Services before validation: {self.services}")
            self.scan_logger.info(f"Validating service catalog with {len(self.services)} service(s)")
            array_validated = []
            
            if len(self.services) == 1 and self.services[0] == "All":
                array_validated = [
                    item for sublist in self.service_catalog.values() for item in sublist
                ]
            else:
                for item in self.services:
                    if item.endswith('::*'):
                        # Handle wildcard replacement
                        prefix = item.split('::')[0]
                        if prefix in self.service_catalog:
                            array_validated.extend(self.service_catalog[prefix])
                    else:
                        # Check if the item exists in any of the lists in self.service_catalog
                        if any(item in values for values in self.service_catalog.values()):
                            array_validated.append(item)
            
            self.services = array_validated
            self.logger.info(f'Service array validated: {array_validated}')
            self.scan_logger.info(f'Service catalog validated: {len(array_validated)} service(s) in scope')
        
        except Exception as e:
            self.logger.error(f"Error validating service catalog: {e}")
            self.scan_logger.error(f"Service catalog validation failed: {str(e)}")
            raise
    
    def validate_region_catalog(self):
        """Validate and expand region selections."""
        try:
            self.scan_logger.info(f"Validating region catalog with {len(self.regions)} region(s)")
            array_validated = []
            
            if len(self.regions) == 1 and self.regions[0] == "All":
                array_validated = self.region_catalog
            else:
                for region in self.regions:
                    if region in self.region_catalog:
                        array_validated.append(region)
            
            self.regions = array_validated
            self.logger.info(f'Region array validated: {array_validated}')
            self.scan_logger.info(f'Region catalog validated: {len(array_validated)} region(s) in scope')
        
        except Exception as e:
            self.logger.error(f"Error validating region catalog: {e}")
            self.scan_logger.error(f"Region catalog validation failed: {str(e)}")
            raise

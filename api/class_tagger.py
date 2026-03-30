"""
AWS Resource Tagging Module

This module contains the AWSResourceTagger class for applying or removing tags
on AWS resources across multiple accounts and regions.

Extracted from artifacts/lambda.tagger/lambda_function.py
"""

import json
import boto3
from typing import List, Dict, Tuple
import logging
from collections import defaultdict
from botocore.exceptions import ClientError
import concurrent.futures
import importlib.util
import os

from class_tools import DataStore, ResourceInfo
from class_scan_logger import ScanLogger


class AWSResourceTagger:
    """
    AWS Resource Tagging class for multi-account, multi-region tagging operations.
    
    This class handles:
    - Cross-account role assumption with session caching
    - boto3 client caching for performance
    - Resource grouping by account/region/service
    - Parallel tagging operations
    - Error tracking and reporting
    
    Attributes:
        max_workers: Maximum number of parallel workers
        session_cache: Dictionary of cached boto3 sessions by account
        client_cache: Nested dictionary of cached boto3 clients
        root_role: IAM root role for local account
        child_role: IAM child role for remote accounts
        script_path: Local path for downloaded service modules
        logger: Logger instance
    """
    
    def __init__(self, scan_id: str = None, max_workers: int = 10, root_role: str = '', child_role: str = ''):
        """
        Initialize AWSResourceTagger.
        
        Args:
            scan_id: Unique identifier for this tagging scan (optional)
            max_workers: Maximum number of parallel workers (default: 10)
            root_role: IAM role to assume first in the local account
            child_role: IAM role to assume in remote accounts using root role credentials
        """
        self.scan_id = scan_id
        self.max_workers = max_workers
        self.session_cache: Dict[str, boto3.Session] = {}
        self.client_cache: Dict[str, Dict[str, Dict[str, boto3.client]]] = defaultdict(
            lambda: defaultdict(dict)
        )
        self.root_role = root_role
        self.child_role = child_role
        self.root_session = None
        self.script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'modules')
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Initialize scan logger if scan_id provided
        if scan_id:
            self.scan_logger = ScanLogger(scan_id=scan_id, process_type='tagger')
            self.scan_logger.info(f"Tagging process initialized for scan_id: {scan_id}")
    
    def get_session(
        self,
        account_id: str,
        role_name: str = None
    ) -> boto3.Session:
        """
        Get cached boto3 session or create new one using two-hop role chain.
        
        Flow: Local credentials -> Root Role -> Child Role (remote account)
        
        Args:
            account_id: AWS account ID
            role_name: Unused, kept for interface compatibility
            
        Returns:
            boto3.Session with temporary credentials
            
        Raises:
            ClientError: If role assumption fails
        """
        if account_id not in self.session_cache:
            try:
                # Step 1: Assume root role (if not already cached)
                if not self.root_session:
                    sts_client = boto3.client('sts')
                    caller = sts_client.get_caller_identity()
                    local_account = caller['Account']
                    root_role_arn = f'arn:aws:iam::{local_account}:role/{self.root_role}'
                    
                    if hasattr(self, 'scan_logger'):
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
                    if hasattr(self, 'scan_logger'):
                        self.scan_logger.info(f"Root role assumed successfully")
                
                # Step 2: Use root session to assume child role in target account
                root_sts = self.root_session.client('sts')
                child_role_arn = f'arn:aws:iam::{account_id}:role/{self.child_role}'
                
                assumed_child = root_sts.assume_role(
                    RoleArn=child_role_arn,
                    RoleSessionName=f'TaggrTagging-{account_id}'
                )
                
                credentials = assumed_child['Credentials']
                self.session_cache[account_id] = boto3.Session(
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken']
                )
                
                if hasattr(self, 'scan_logger'):
                    self.scan_logger.info(f"Assumed child role for account {account_id}")
                    
            except ClientError as e:
                self.logger.error(f"Failed to assume role for account {account_id}: {str(e)}")
                if hasattr(self, 'scan_logger'):
                    self.scan_logger.error(f"Failed to assume role for account {account_id}: {str(e)}")
                raise
        
        return self.session_cache[account_id]
    
    def get_client(self, account_id: str, region: str, service: str) -> boto3.client:
        """
        Get cached boto3 client or create new one.
        
        Args:
            account_id: AWS account ID
            region: AWS region
            service: AWS service name
            
        Returns:
            boto3 client for the specified service
        """
        if service not in self.client_cache[account_id][region]:
            session = self.get_session(account_id)
            self.client_cache[account_id][region][service] = session.client(
                service, region_name=region
            )
        return self.client_cache[account_id][region][service]
    
    def parse_tags(self, tags_string: str) -> List[Dict[str, str]]:
        """
        Parse tag string to list of tag dictionaries.
        
        Args:
            tags_string: Tag string in format "key1:value1,key2:value2"
            
        Returns:
            List of dictionaries with 'Key' and 'Value' fields
        """
        tags = []
        for tag_pair in tags_string.split(','):
            key, value = tag_pair.split(':')
            tags.append({
                'Key': key.strip(),
                'Value': value.strip()
            })
        return tags
    
    def group_resources(
        self,
        resources: List[Tuple[str, str, str, str, str]]
    ) -> Dict[str, Dict[str, Dict[str, List[ResourceInfo]]]]:
        """
        Group resources by account, region, and service.
        
        Args:
            resources: List of tuples (account_id, region, service, identifier, arn)
            
        Returns:
            Nested dictionary: {account_id: {region: {service: [ResourceInfo]}}}
        """
        grouped = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
        for resource in resources:
            resource_info = ResourceInfo(*resource)
            grouped[resource_info.account_id][resource_info.region][resource_info.service].append(
                resource_info
            )
        return grouped
    
    def tag_resource_batch(
        self,
        account_id: str,
        region: str,
        service: str,
        resources: List[ResourceInfo],
        tags: str,
        action: int
    ) -> List[Dict]:
        """
        Tag a batch of resources for a specific service.
        
        Args:
            account_id: AWS account ID
            region: AWS region
            service: AWS service name
            resources: List of ResourceInfo objects
            tags: Tag string in format "key1:value1,key2:value2"
            action: 1 for add tags, 2 for remove tags
            
        Returns:
            List of result dictionaries with status and error information
        """
        results = []
        client = self.get_client(account_id, region, service)
        
        if hasattr(self, 'scan_logger'):
            self.scan_logger.info(f"Tagging # Account : {account_id}, Region : {region}, Service : {service}")
        
        try:
            # Import module
            spec = importlib.util.spec_from_file_location(
                service,
                f'{self.script_path}/{service}.py'
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            results = module.tagging(
                account_id,
                region,
                service,
                client,
                resources,
                tags,
                action,
                self.logger
            )
            
            # Write per-resource errors to scan log
            if hasattr(self, 'scan_logger'):
                for result in results:
                    if result.get('status') == 'error':
                        self.scan_logger.error(
                            f"Error tagging {service} resource {result.get('identifier', '?')}: {result.get('error', 'Unknown error')}"
                        )
        
        except Exception as e:
            error_msg = f"Error processing batch for {service} in {account_id}/{region}: {str(e)}"
            self.logger.error(error_msg)
            if hasattr(self, 'scan_logger'):
                self.scan_logger.error(error_msg)
            for resource in resources:
                results.append({
                    'account_id': account_id,
                    'region': region,
                    'service': service,
                    'identifier': resource.identifier,
                    'status': 'error',
                    'error': str(e)
                })
        
        return results
    
    def tag_resources(
        self,
        resources: List[Tuple[str, str, str, str, str]],
        tags: str,
        action: int
    ) -> Tuple[List[Dict], Dict]:
        """
        Tag resources in parallel across accounts, regions, and services.
        
        Args:
            resources: List of tuples (account_id, region, service, identifier, arn)
            tags: Tag string in format "key1:value1,key2:value2"
            action: 1 for add tags, 2 for remove tags
            
        Returns:
            Tuple of (results, metrics) where:
                - results: List of result dictionaries with status and error information
                - metrics: Dictionary with execution metrics
        """
        grouped_resources = self.group_resources(resources)
        all_results = []
        metrics = {
            'total': 0,
            'success': 0,
            'failed': 0
        }
        
        total_resources = len(resources)
        action_name = "Adding" if action == 1 else "Removing"
        
        if hasattr(self, 'scan_logger'):
            self.scan_logger.info(f"{action_name} tags for {total_resources} resources")
            self.scan_logger.info(f"Tags: {tags}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_batch = {}
            
            # Submit batches for parallel processing
            for account_id, regions in grouped_resources.items():
                for region, services in regions.items():
                    for service, resource_list in services.items():
                        future = executor.submit(
                            self.tag_resource_batch,
                            account_id,
                            region,
                            service,
                            resource_list,
                            tags,
                            action
                        )
                        future_to_batch[future] = (account_id, region, service, len(resource_list))
            
            # Collect results and metrics
            completed = 0
            total_batches = len(future_to_batch)
            for future in concurrent.futures.as_completed(future_to_batch):
                account_id, region, service, batch_size = future_to_batch[future]
                completed += 1
                try:
                    results = future.result()
                    all_results.extend(results)
                    
                    # Update metrics
                    for result in results:
                        metrics['total'] += 1
                        if result.get('status') == 'success':
                            metrics['success'] += 1
                        else:
                            metrics['failed'] += 1
                    
                    success_count = sum(1 for r in results if r.get('status') == 'success')
                    error_count = sum(1 for r in results if r.get('status') == 'error')
                    
                    if hasattr(self, 'scan_logger'):
                        self.scan_logger.info(
                            f"[{completed}/{total_batches}] {service} in {account_id}/{region}: "
                            f"{success_count} success, {error_count} errors"
                        )
                        
                except Exception as e:
                    self.logger.error(
                        f"Unexpected error processing batch for {service} "
                        f"in {account_id}/{region}: {str(e)}"
                    )
                    if hasattr(self, 'scan_logger'):
                        self.scan_logger.error(
                            f"[{completed}/{total_batches}] {service} in {account_id}/{region}: {str(e)}"
                        )
        
        # Log summary with metrics
        if hasattr(self, 'scan_logger'):
            self.scan_logger.success(
                f"Tagging completed: {metrics['success']} successful, {metrics['failed']} errors"
            )
            self.scan_logger.info(f"Metrics - Total: {metrics['total']}, Success: {metrics['success']}, Failed: {metrics['failed']}")
        
        return all_results, metrics
    
    def load_local_modules(self):
        """
        Load service modules from local modules directory.
        
        Verifies the local modules directory exists and contains
        Python module files for service discovery and tagging.
        """
        try:
            if hasattr(self, 'scan_logger'):
                self.scan_logger.info(f"Loading service modules from local path: {self.script_path}")
            
            if not os.path.isdir(self.script_path):
                raise FileNotFoundError(f"Modules directory not found: {self.script_path}")
            
            # List available modules
            modules = [f for f in os.listdir(self.script_path) if f.endswith('.py')]
            
            if hasattr(self, 'scan_logger'):
                self.scan_logger.info(f"Found {len(modules)} service modules in local directory")
                self.scan_logger.success(f"Successfully loaded {len(modules)} service modules from local path")
        
        except Exception as e:
            self.logger.error(f"Error loading local modules from {self.script_path}: {e}")
            if hasattr(self, 'scan_logger'):
                self.scan_logger.error(f"Failed to load local modules: {str(e)}")
            raise

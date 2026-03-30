import json
import os
import boto3
from datetime import datetime
import concurrent.futures
from typing import List, Dict, Tuple
import logging
from collections import defaultdict
from dataclasses import dataclass
from botocore.exceptions import ClientError
import psycopg2
from psycopg2 import pool
import importlib
from collections import Counter
import zipfile
import io

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


######################################################
######################################################
###
###--------- CLASS : DataStore
###
######################################################
######################################################

class DataStore:
    ###
    ###-- Initialization
    ###
    
    def __init__(self,                  
                 db_config=None,
                 region=None):        
        

        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
                
        # Create connection pool
        try:
            client = boto3.client("dsql", region_name=region)    
            password_token = client.generate_db_connect_admin_auth_token(db_config['host'], region)
            self.db_config = { **db_config, 'password' : password_token }
            self.connection_pool = psycopg2.pool.SimpleConnectionPool(
                1, 20, **self.db_config
            )
        except Exception as e:
            self.logger.error(f"Error creating database connection pool: {e}")
            raise

      
    ###
    ###-- Execute dml command
    ###    

    def execute_dml(self,query, data):      

      connection = None
      cursor = None
      results = []
      try:
          connection = self.connection_pool.getconn()
          cursor = connection.cursor()          
          cursor.execute(query, data)
          connection.commit()          
      
      except Exception as e:
          self.logger.error(f"Error : {e}")
          if connection:
              connection.rollback()
          raise
      
      finally:
          if cursor:
              cursor.close()
          if connection:
              self.connection_pool.putconn(connection)            
      return results




    ###
    ###-- execute select command
    ###    

    def execute_select(self, query, data):      
      
      connection = None
      cursor = None
      results = []
      try:
          connection = self.connection_pool.getconn()
          cursor = connection.cursor()          
          cursor.execute(query,data)          
          results = cursor.fetchall()
          connection.commit()          
      
      except Exception as e:
          self.logger.error(f"Error : {e}")
          if connection:
              connection.rollback()
          raise
      
      finally:
          if cursor:
              cursor.close()
          if connection:
              self.connection_pool.putconn(connection)            
      return results



    ###
    ###-- Save tag errors to data store
    ###

    def save_tags_errors(self, scan_id, tags, batch_size=1000):
      
        print(tags)

        # Prepare INSERT statement
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
        
        
        # Get a connection from the pool
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
                        tag.get('arn',''), 
                        tag['status'], 
                        tag['error']
                    ) for tag in batch
                ]
                

                # Use execute_values for efficient batch insert
                from psycopg2.extras import execute_values
                execute_values(
                    cursor, 
                    insert_query, 
                    batch_data
                )
                
                # Commit each batch
                connection.commit()
                
                self.logger.info(f"Inserted {len(batch)} records")
        
        except Exception as e:
            self.logger.error(f"Error saving error tags to database: {e}")
            if connection:
                connection.rollback()
            raise
        
        finally:
            # Close cursor and return connection to pool
            if cursor:
                cursor.close()
            if connection:
                self.connection_pool.putconn(connection)

######################################################
######################################################
###
###--------- CLASS : ResourceInfo
###
######################################################
######################################################

@dataclass
class ResourceInfo:
    account_id: str
    region: str
    service: str
    identifier: str
    arn: str



######################################################
######################################################
###
###--------- CLASS : AWSResourceTagger
###
######################################################
######################################################

class AWSResourceTagger:
    ###
    ###-- Initialization
    ###

    def __init__(self, max_workers: int = 10, role_name='CrossAccountTagReadRole'):
        self.max_workers = max_workers
        self.session_cache: Dict[str, boto3.Session] = {}
        self.client_cache: Dict[str, Dict[str, Dict[str, boto3.client]]] = defaultdict(
            lambda: defaultdict(dict)
        )
        self.role_name = role_name
        self.script_path =  '/tmp/scripts'

        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)


    ###
    ###-- Get boto3 session
    ###

    def get_session(self, account_id: str, role_name: str = "CrossAccountTagReadRole") -> boto3.Session:
        if account_id not in self.session_cache:
            sts_client = boto3.client('sts')
            role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
            try:
                assumed_role = sts_client.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName="ResourceTagging"
                )
                
                credentials = assumed_role['Credentials']
                self.session_cache[account_id] = boto3.Session(
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken']
                )
            except ClientError as e:
                logger.error(f"Failed to assume role for account {account_id}: {str(e)}")
                raise
                
        return self.session_cache[account_id]



    ###
    ###-- Get boto3 client
    ###

    def get_client(self, account_id: str, region: str, service: str) -> boto3.client:        
        if service not in self.client_cache[account_id][region]:
            session = self.get_session(account_id, role_name=self.role_name)
            self.client_cache[account_id][region][service] = session.client(
                service, region_name=region
            )
        return self.client_cache[account_id][region][service]



    ###
    ###-- Parse Tags
    ###

    def parse_tags(self, tags_string: str) -> List[Dict[str, str]]:
        tags = []
        for tag_pair in tags_string.split(','):
            key, value = tag_pair.split(':')
            tags.append({
                'Key': key.strip(),
                'Value': value.strip()
            })
        return tags



    ###
    ###-- Get resources and perform grouping
    ###

    def group_resources(self, resources: List[Tuple[str, str, str, str, str , str]]) -> Dict:
        grouped = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
        for resource in resources:
            resource_info = ResourceInfo(*resource)
            grouped[resource_info.account_id][resource_info.region][resource_info.service].append(resource_info)
        return grouped




    ###
    ###-- Perfom batch tagging process
    ###

    def tag_resource_batch(self, account_id: str, region: str, service: str, resources: List[ResourceInfo], tags, action) -> List[Dict]:
        
        results = []
        client = self.get_client(account_id, region, service)
        
        try:

            # Import module            
            spec = importlib.util.spec_from_file_location(service, f'{self.script_path}/{service}.py')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)                      
            
            results = module.tagging(account_id, region, service, client, resources, tags, action, self.logger )
                      
        except Exception as e:
            logger.error(f"Error processing batch for {service} in {account_id}/{region}: {str(e)}")
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


    ###
    ###-- Perfom tagging per resource
    ###        

    def tag_resources(self, resources: List[Tuple[str, str, str, str, str]], tags, action ) -> List[Dict]:
        grouped_resources = self.group_resources(resources)
        all_results = []
        
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
                        future_to_batch[future] = (account_id, region, service)
            
            # Collect results
            for future in concurrent.futures.as_completed(future_to_batch):
                account_id, region, service = future_to_batch[future]
                try:
                    results = future.result()
                    all_results.extend(results)
                except Exception as e:
                    logger.error(f"Unexpected error processing batch for {service} in {account_id}/{region}: {str(e)}")
                    
        return all_results

    

    ###
    ###-- Download modules 
    ###
    
    def download_modules_from_s3(self, region, bucket_name, zip_key):
        
        try:

            
            s3 = boto3.client('s3',region_name=region)

            # Create a temporary directory to store unzipped scripts            
            os.makedirs(self.script_path, exist_ok=True)

        
            # Get list of modules
            response = s3.list_objects_v2(Bucket=bucket_name)    
            modules = [
                {
                    'name': item['Key'],
                    'size': item['Size'],
                    'lastModified': item['LastModified'].isoformat()
                }
                for item in response.get('Contents', [])
                if item['Key'].endswith('.py') 
            ]

            # Download modules
            for module in modules:
                s3.download_file(bucket_name, module['name'], f'{self.script_path}/{module["name"]}')                  

        except Exception as e:
            self.logger.error(f"Error downloading scripts from {bucket_name} : {e}")            
            raise


######################################################
######################################################
###
###--------- Main : lambda_handler
###
######################################################
######################################################


def lambda_handler(event, context):

    print(event)

    # Initialize variables
    scan_id = event['scanId']
    tags_object = event['tags']
    tags_action = int(event['action'])
    max_workers = int(os.environ['MAX_WORKERS'])

    db_config = {        
        'host': os.environ['DBHOST'],
        'database': os.environ['DBNAME'],
        'user': os.environ['DBUSER'],       
        'port': os.environ['DBPORT'],
        'sslmode': 'require'
    }   

    # Select resources to tag

    ds = DataStore(db_config=db_config, region = os.environ['REGION'])
    
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
    
    parameters = (event["scanId"],)
    rows = ds.execute_select(select_query, parameters)
    resources = [tuple(row) for row in rows]
    
    tags_string = ",".join([f"{obj['key']}:{obj['value']}" for obj in tags_object])
    
    # Initialize tagger with desired number of parallel workers
    tagger = AWSResourceTagger(max_workers=max_workers, role_name=os.environ['IAM_SCAN_ROLE'])

    # Download and import scripts from S3
    tagger.download_modules_from_s3(region=os.environ['REGION'],bucket_name = os.environ['S3_BUCKET_MODULES'],zip_key='scripts.zip')
    
    # Tag resources and get results
    results = tagger.tag_resources(resources, tags_string, tags_action)
    
    # Get summary results
    status_counter = Counter(item['status'] for item in results if 'status' in item)
            
    update_query = """
    UPDATE tbprocess
    SET end_time_tagging = %s, status_tagging = %s, message_tagging = %s, resources_tagged_success = %s, resources_tagged_error = %s, action = %s
    WHERE scan_id = %s
    """
    ds.execute_dml(update_query, ((datetime.now()).strftime("%Y-%m-%d %H:%M:%S"), 'completed', json.dumps(status_counter), status_counter.get('success',0), status_counter.get('error',0), tags_action, scan_id))

    error_items = [item for item in results if item.get('status') == 'error']
    ds.save_tags_errors(scan_id, error_items)
    
    return {
        'statusCode': 200,
        'body': json.dumps('success')
    }

import boto3
import os
import concurrent.futures
import json
import logging
from datetime import datetime
import psycopg2
from psycopg2 import pool
from botocore.exceptions import ClientError, NoCredentialsError
import importlib
import sys
import zipfile
import io

   
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
                scan_id,                
                 db_config=None,
                 region=None):
 
        
        self.scan_id = scan_id
        self.metadata_path =  '/tmp/metadata'

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
    ###-- Save records to data store
    ###

    def save_tags_to_store(self, tags, batch_size=1000):
      
        # Prepare INSERT statement
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
                        json.dumps(tag['metadata'],default=str),
                        tag['arn'],
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
            self.logger.error(f"Error saving tags to database: {e}")
            if connection:
                connection.rollback()
            raise
        
        finally:
            # Close cursor and return connection to pool
            if cursor:
                cursor.close()
            if connection:
                self.connection_pool.putconn(connection)

    def save_tags_to_file(self, tags, filename='multi_account_tags.json'):        
        try:
            with open(filename, 'w') as f:
                json.dump(tags, f, default=str,indent=4)
            self.logger.info(f"Tags saved to {filename}")
        except Exception as e:
            self.logger.error(f"Error saving tags to file: {e}")





    ###
    ###-- Create table resources if doesnt exists
    ###
   
    def create_table(self):
       
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
            self.logger.info("Results table ensured")
        
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
    
    def execute(self, query, data):      

      connection = None
      cursor = None
      results = []
      try:
          connection = self.connection_pool.getconn()
          cursor = connection.cursor()          
          cursor.execute(query,data)
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
    ###-- Convert JSON timestamp fields
    ###

    def serialize_datetime(self,obj): 
        if isinstance(obj, datetime): 
            return obj.isoformat() 
        raise TypeError("Type not serializable") 




    ###
    ###-- Convert JSON timestamp fields
    ###

    def timestamp_to_string(self, timestamp):
        try:
            # If timestamp is already a datetime object
            if isinstance(timestamp, datetime):
                dt = timestamp
            # If timestamp is a float or int (Unix timestamp)
            elif isinstance(timestamp, (float, int)):
                dt = datetime.fromtimestamp(timestamp)
            # If timestamp is a string, try parsing it
            elif isinstance(timestamp, str):
                # You might need to adjust the format string based on your input
                dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            
            # Try to convert to string using the specified format
            formatted_string = dt.strftime("%Y-%m-%d %H:%M:%S")
            return formatted_string
        except Exception as e:
            return str(timestamp)


   
######################################################
######################################################
###
###--------- CLASS : AWSResourceDiscovery
###
######################################################
######################################################


class AWSResourceDiscovery:
    def __init__(self, scan_id, accounts, regions, services, max_workers=10, role_name='CrossAccountTagReadRole'):
        self.scan_id = scan_id
        self.accounts = accounts
        self.services = services
        self.regions = regions
        self.max_workers = max_workers
        self.role_name = role_name
        self.script_path =  '/tmp/scripts'
        self.metadata_path =  '/tmp/metadata'
        self.service_catalog = {}
        self.region_catalog = []

        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)


    ###
    ###-- Assume Role
    ###

    def assume_role(self, account_id):
        try:
            sts_client = boto3.client('sts')
            role_arn = f'arn:aws:iam::{account_id}:role/{self.role_name}'
            
            assumed_role = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=f'MultiAccountTagCollection-{account_id}'
            )
            
            return boto3.Session(
                aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
                aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
                aws_session_token=assumed_role['Credentials']['SessionToken']
            )
        except Exception as e:
            self.logger.error(f"Error assuming role for account {account_id}: {e}")
            return None



    ###
    ###-- Collect resource tags
    ###

    def collect_resource_tags(self, session, account_id, region, service):
        try:
            module_name, service_type = service.split('::')    
            module_name = module_name.lower()        
            spec = importlib.util.spec_from_file_location(module_name, f'{self.script_path}/{module_name}.py')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)            
            
            return module.discovery(self, session, account_id, region, module_name, service_type, self.logger)                      

        except Exception as e:
            self.logger.error(f"Error collecting {service} tags in {region}: {e}")
            return []

    
    ###
    ###-- Collect tags from multiple accounts
    ###

    def collect_multi_account_tags(self):   

        all_tags = [] 

        # Parallel account and region processing
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Prepare futures for all accounts, regions, and services
            futures = []
            for account_id in self.accounts:
                # Assume role for the account
                session = self.assume_role(account_id)
                if not session:
                    continue
                
                for region in self.regions:
                    for service in self.services:
                        futures.append(executor.submit(self.collect_resource_tags, session, account_id, region, service))
                        
            
            # Process results
            for future in concurrent.futures.as_completed(futures):
                try:
                    #service_name, status, message, resources
                    service_name, status, message, resources = future.result()
                    all_tags.extend(resources)
                except Exception as e:
                    self.logger.error(f"Error processing future: {e}")
          
            # Add sequence number
            for seq, tag in enumerate(all_tags, 1):
              tag['seq'] = seq
              
        return all_tags



    ###
    ###-- Download modules from AWS S3
    ###

    def download_modules_from_s3(self, region, bucket_name):
        
        try:
            file_name_modules = "scripts.zip"
            file_name_service_catalog = "services.json"
            file_name_region_catalog = "regions.json"

            # Initialize S3 client        
            print(f"Downloading scripts from {bucket_name}/{file_name_modules}")

            s3 = boto3.client('s3',region_name=region)

            # Create a temporary directory to store unzipped scripts
            
            os.makedirs(self.script_path, exist_ok=True)
            os.makedirs(self.metadata_path, exist_ok=True)


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

            # Catalogs
            response = s3.get_object(Bucket=bucket_name, Key=file_name_region_catalog)
            self.region_catalog = json.loads(response['Body'].read())           
            

        except Exception as e:
            self.logger.error(f"Error downloading scripts from {bucket_name} : {e}")            
            raise



    ###
    ###-- Load service catalog
    ###

    def load_service_catalog(self):
        try:

            service_catalog = {}
            modules = []    
            
            for filename in os.listdir(self.script_path):                
                if filename.endswith('.py'):                    
                    modules.append(filename)

            for module_name in modules:         
                try:                      
                    module_name = module_name[:-3]                               
                    spec = importlib.util.spec_from_file_location(module_name, f'{self.script_path}/{module_name}.py')
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)            
                    
                    service_types = module.get_service_types(None,None,None,None)       
                    services = [f"{module_name}::{key}" for key in service_types.keys()]                           
                    service_catalog = {**service_catalog, f'{module_name}' : services }

                except Exception as e:
                    self.logger.error(f"Error getting service types for {module_name}: {e}")                    
            
            self.service_catalog = service_catalog
            
        except Exception as e:
            self.logger.error(f"Error loading service catalog: {e}")
            



    ###
    ###-- Validate Service Catalog
    ###

    def validate_service_catalog(self):                
        try:

            print(self.services)
            array_validated = []                        
            if len(self.services) == 1 and self.services[0] == "All":
                array_validated = [item for sublist in self.service_catalog.values() for item in sublist]
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

            print(f'Service array validated : {array_validated}')


        except Exception as e:
            self.logger.error(f"Error validating service catalog : {e}")            
            raise



    ###
    ###-- Validate Region Catalog
    ###

    def validate_region_catalog(self):                
        try:
            array_validated = []            
            if len(self.regions) == 1 and self.regions[0] == "All":
                array_validated = self.region_catalog
            else:                        
                for region in self.regions:
                    if region in self.region_catalog:
                        array_validated.append(region)
                

            self.regions = array_validated
            print(f'Region array validated : {array_validated}')


        except Exception as e:
            self.logger.error(f"Error validating region catalog : {e}")            
            raise



######################################################
######################################################
###
###--------- MAIN : lambda_handler
###
######################################################
######################################################

            
def lambda_handler(event, context):
    
    print(event)

    # Initialize variables
    scan_id = event['scanId']
    accounts = event['ruleset']['accounts']    
    regions = event['ruleset']['regions']    
    services = event['ruleset']['services'] 
    filter = event['ruleset']['filter'] 
    max_workers = int(os.environ['MAX_WORKERS'])
    
    # Create tag collector
    tag_collector = AWSResourceDiscovery(
        scan_id=scan_id,
        accounts=accounts, 
        regions=regions,
        services=services,
        max_workers=max_workers,
        role_name=os.environ['IAM_SCAN_ROLE']
    )

    # Download and import scripts from S3
    tag_collector.download_modules_from_s3(
                                                    region=os.environ['REGION'], 
                                                    bucket_name = os.environ['S3_BUCKET_MODULES']
    )

    # Loading service catalog
    tag_collector.load_service_catalog()

    # Validate service catalog
    tag_collector.validate_service_catalog()

    # Validate region catalog
    tag_collector.validate_region_catalog()

    # Collect tags
    resources = tag_collector.collect_multi_account_tags()
    

    # Save results in Data Store
    db_config = {        
        'host': os.environ['DBHOST'],
        'database': os.environ['DBNAME'],
        'user': os.environ['DBUSER'],       
        'port': os.environ['DBPORT'],
        'sslmode': 'require'
    }   

    db_store = DataStore(scan_id=scan_id, db_config=db_config, region = os.environ['REGION'])
    db_store.create_table()
    db_store.save_tags_to_store(resources)    

    # Update process status
    update_query = """
    UPDATE tbprocess
    SET end_time = %s, status = %s, resources = %s
    WHERE scan_id = %s
    """
    db_store.execute(update_query, ((datetime.now()).strftime("%Y-%m-%d %H:%M:%S"), 'completed', len(resources), scan_id))
    
    
    # Update filted-in and filter-out
    if not isinstance(filter, str) or not filter.strip():
        filter = 'true'
    
    update_query = f"""
    UPDATE tbresources
    SET action =  case  when ( {filter} ) then 1 else 2 end
    WHERE scan_id = %s
    """
    db_store.execute(update_query, (scan_id,))


    # Return code
    return {
        'statusCode': 200,
        'body': json.dumps('Code success')
    }


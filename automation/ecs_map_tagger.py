import json
import boto3
import os
import importlib.util
import sys
from datetime import datetime
from botocore.exceptions import ClientError
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MAP_TAG will be set dynamically from SQS message
MAP_TAG = None

class ServiceTagger:
    def __init__(self, session, region, account_id, start_date, map_tag):
        self.session = session
        self.region = region
        self.account_id = account_id
        self.start_date = start_date
        self.map_tag = map_tag
        self.modules_path = '/app/modules'  # Path to modules in container

    def load_service_module(self, service_name):
        """Dynamically load service module"""
        module_path = f"{self.modules_path}/{service_name}.py"
        if not os.path.exists(module_path):
            raise ImportError(f"Module for service {service_name} not found")
        
        spec = importlib.util.spec_from_file_location(service_name, module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def tag_service_resources(self, service_name):
        """Tag all resources for a specific service using its module"""
        try:
            module = self.load_service_module(service_name)
            client = self.session.client(service_name, region_name=self.region)
            
            # Get service types from module
            service_types = module.get_service_types(self.account_id, self.region, service_name, None)
            
            total_tagged = 0
            for service_type in service_types.keys():
                logger.info(f"Processing {service_name}:{service_type}")
                
                # Discover resources
                _, status, error_msg, resources = module.discovery(
                    None, self.session, self.account_id, self.region, 
                    service_name, service_type, logger
                )
                
                if status != "success":
                    logger.error(f"Discovery failed for {service_name}:{service_type}: {error_msg}")
                    continue
                
                # Filter resources by date and check for existing MAP tag
                resources_to_tag = []
                for resource in resources:
                    if self._should_tag_resource(resource):
                        resources_to_tag.append(resource)
                
                if resources_to_tag:
                    # Convert to expected format for tagging function
                    resource_objects = [ResourceObject(r) for r in resources_to_tag]
                    
                    # Tag resources
                    results = module.tagging(
                        self.account_id, self.region, service_name, client,
                        resource_objects, f"{self.map_tag['Key']}:{self.map_tag['Value']}", 1, logger
                    )
                    
                    successful_tags = sum(1 for r in results if r['status'] == 'success')
                    total_tagged += successful_tags
                    logger.info(f"Tagged {successful_tags}/{len(resources_to_tag)} {service_name}:{service_type} resources")
            
            logger.info(f"Total tagged for {service_name}: {total_tagged}")
            return total_tagged
            
        except Exception as e:
            logger.error(f"Error tagging {service_name}: {e}")
            raise

    def _should_tag_resource(self, resource):
        """Check if resource should be tagged based on date and existing tags"""
        # Check if already has MAP tag
        if self.map_tag['Key'] in resource.get('tags', {}):
            return False
        
        # ALTERNATIVE: Uncomment below to overwrite existing MAP tags with wrong values
        # Use this if customer needs to fix incorrectly tagged resources
        # current_value = resource.get('tags', {}).get(self.map_tag['Key'])
        # if current_value == self.map_tag['Value']:
        #     return False  # Already has correct value, skip
        # # Continue to tag if: no tag exists OR wrong value exists
        
        # Check creation date if available
        creation_date = resource.get('creation_date')
        if creation_date and self.start_date:
            try:
                if isinstance(creation_date, str):
                    resource_date = datetime.fromisoformat(creation_date.replace('Z', '+00:00'))
                else:
                    resource_date = creation_date
                
                if resource_date.replace(tzinfo=None) <= self.start_date:
                    return False
            except Exception as e:
                logger.warning(f"Could not parse date for resource {resource.get('resource_id')}: {e}")
        
        return True

class ResourceObject:
    """Wrapper class to match expected interface for tagging functions"""
    def __init__(self, resource_dict):
        self.identifier = resource_dict['resource_id']
        self.arn = resource_dict['arn']

def assume_role(account_id):
    """Assume IAM role for cross-account access"""
    sts_client = boto3.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/IAMChildRoleTaggerSolution"
    try:
        assumed_role_object = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="MapTaggerECSSession"
        )
        return assumed_role_object["Credentials"]
    except ClientError as e:
        logger.error(f"Error assuming role for account {account_id}: {e}")
        return None

def process_sqs_message():
    """Process messages from SQS queue until empty"""
    queue_url = os.environ.get('QUEUE_URL')
    if not queue_url:
        logger.error("QUEUE_URL environment variable not set")
        return

    sqs = boto3.client('sqs')
    messages_processed = 0
    empty_polls = 0
    max_empty_polls = int(os.environ.get('MAX_EMPTY_POLLS', '3'))
    
    while True:
        try:
            response = sqs.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=10,  # Process up to 10 messages at once
                WaitTimeSeconds=20
            )
            
            messages = response.get('Messages', [])
            if not messages:
                empty_polls += 1
                logger.info(f"No messages in queue (empty poll {empty_polls}/{max_empty_polls})")
                if empty_polls >= max_empty_polls:
                    logger.info(f"Queue appears empty after {max_empty_polls} polls. Exiting.")
                    break
                continue
            
            # Reset empty poll counter when messages are found
            empty_polls = 0
                
            for message in messages:
                try:
                    job = json.loads(message['Body'])
                    process_job(job)
                    
                    # Delete message after successful processing
                    sqs.delete_message(
                        QueueUrl=queue_url,
                        ReceiptHandle=message['ReceiptHandle']
                    )
                    messages_processed += 1
                    logger.info(f"Successfully processed message {messages_processed} for {job['service']}")
                    
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
                    
        except Exception as e:
            logger.error(f"Error receiving messages from SQS: {e}")
            break
    
    logger.info(f"Task completed. Processed {messages_processed} messages total.")

def process_job(job):
    """Process individual tagging job"""
    service = job['service']
    account_id = job['account_id']
    region = job['region']
    start_date = datetime.strptime(job.get('start_date', '2024-01-01'), '%Y-%m-%d')
    map_tag = {'Key': job.get('map_tag_key', 'map-migrated'), 'Value': job.get('map_tag_value', '12345')}
    
    logger.info(f"Processing {service} for account {account_id} in region {region}")
    
    # Assume role for the target account
    creds = assume_role(account_id)
    if not creds:
        raise Exception(f"Failed to assume role for account {account_id}")

    session = boto3.Session(
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken'],
    )

    tagger = ServiceTagger(session, region, account_id, start_date, map_tag)
    tagger.tag_service_resources(service)

def main():
    """Main entry point"""
    logger.info("Starting MAP Tagger ECS Task...")
    process_sqs_message()

if __name__ == "__main__":
    main()
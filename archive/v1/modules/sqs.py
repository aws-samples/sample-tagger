import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    """
    AWS SQS resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sqs/client/tag_queue.html
    
    SQS supports tagging for:
    - Queue (SQS queues for message queuing)
    """

    resource_configs = {
        'Queue': {
            'method': 'list_queues',
            'key': 'QueueUrls',
            'id_field': None,  # Queue URLs are returned directly
            'name_field': None,
            'date_field': None,
            'nested': False,
            'arn_format': None  # Will be constructed from queue URL
        }
    }
    
    return resource_configs


def discovery(self, session, account_id, region, service, service_type, logger):    
    
    status = "success"
    error_message = ""
    resources = []

    try:
        
        service_types_list = get_service_types(account_id, region, service, service_type)        
        if service_type not in service_types_list:
            raise ValueError(f"Unsupported service type: {service_type}")

        config = service_types_list[service_type]
        
        # SQS is regional
        client = session.client('sqs', region_name=region)
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for sqs client")

        method = getattr(client, config['method'])
        params = {}

        # Get queue URLs
        try:
            response = method(**params)
            queue_urls = response.get(config['key'], [])
        except Exception as e:
            # If no queues exist, list_queues might not return QueueUrls key
            queue_urls = []

        # Process each queue URL
        for queue_url in queue_urls:
            try:
                # Extract queue name from URL
                queue_name = queue_url.split('/')[-1]
                
                # Get queue attributes to get more information
                queue_attributes = {}
                try:
                    attrs_response = client.get_queue_attributes(
                        QueueUrl=queue_url,
                        AttributeNames=['All']
                    )
                    queue_attributes = attrs_response.get('Attributes', {})
                except Exception as attr_error:
                    logger.warning(f"Could not get attributes for queue {queue_name}: {attr_error}")

                # Get creation timestamp
                creation_date = None
                if 'CreatedTimestamp' in queue_attributes:
                    import datetime
                    creation_timestamp = int(queue_attributes['CreatedTimestamp'])
                    creation_date = datetime.datetime.fromtimestamp(creation_timestamp).isoformat()

                # Build ARN from queue attributes or construct it
                arn = queue_attributes.get('QueueArn')
                if not arn:
                    # Construct ARN if not available in attributes
                    arn = f"arn:aws:sqs:{region}:{account_id}:{queue_name}"

                # Get existing tags
                resource_tags = {}
                try:
                    tags_response = client.list_queue_tags(QueueUrl=queue_url)
                    tags_dict = tags_response.get('Tags', {})
                    resource_tags = tags_dict
                except Exception as tag_error:
                    logger.warning(f"Could not retrieve tags for {queue_name}: {tag_error}")
                    resource_tags = {}

                resources.append({
                    "account_id": account_id,
                    "region": region,
                    "service": service,
                    "resource_type": service_type,
                    "resource_id": queue_name,
                    "name": queue_name,
                    "creation_date": creation_date,
                    "tags": resource_tags,
                    "tags_number": len(resource_tags),
                    "metadata": {
                        "QueueUrl": queue_url,
                        "Attributes": queue_attributes
                    },
                    "arn": arn
                })

            except Exception as queue_error:
                logger.warning(f"Error processing queue {queue_url}: {queue_error}")

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} {service_type.lower()}s')

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources


####----| Tagging method
def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    if tags_action == 2:        
        tag_keys = [item['Key'] for item in tags]

    # Create SQS client
    session = boto3.Session()
    sqs_client = session.client('sqs', region_name=region)

    for resource in resources:            
        try:
            # Get queue URL from metadata
            queue_url = resource.metadata.get('QueueUrl')
            if not queue_url:
                # Construct queue URL if not available
                queue_url = f"https://sqs.{region}.amazonaws.com/{account_id}/{resource.identifier}"
            
            if tags_action == 1:
                # Add tags - Convert to SQS format (dict)
                sqs_tags = {tag['Key']: tag['Value'] for tag in tags}
                sqs_client.tag_queue(
                    QueueUrl=queue_url,
                    Tags=sqs_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                sqs_client.untag_queue(
                    QueueUrl=queue_url,
                    TagKeys=tag_keys
                )
                    
            results.append({
                'account_id': account_id,
                'region': region,
                'service': service,
                'identifier': resource.identifier,
                'arn': resource.arn,
                'status': 'success',
                'error': ""
            })
            
        except Exception as e:
            logger.error(f"Error processing {service} resource {resource.identifier}: {str(e)}")
            
            results.append({
                'account_id': account_id,
                'region': region,
                'service': service,
                'identifier': resource.identifier,
                'arn': resource.arn,
                'status': 'error',
                'error': str(e)
            })    
    
    return results


def parse_tags(tags_string):
    """Parse tags from string format to list of dictionaries"""
    tags = []
    if tags_string:
        for tag_pair in tags_string.split(','):
            if ':' in tag_pair:
                key, value = tag_pair.split(':', 1)
                tags.append({'Key': key.strip(), 'Value': value.strip()})
    return tags

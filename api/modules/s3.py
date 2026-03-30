import boto3
import json
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError
import datetime

def get_service_types(account_id, region, service, service_type):
    resource_configs = {
        'Bucket': {
            'method': 'list_buckets',
            'key': 'Buckets',
            'id_field': 'Name',
            'date_field': 'CreationDate',
            'nested': False,
            'arn_format': 'arn:aws:s3:::{resource_id}'
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
        client = session.client(service)

        method = getattr(client, config['method'])
        params = {}

        # S3 is a global service, but we need to check bucket location to filter by region
        response = method(**params)
        items = response[config['key']]

        for item in items:
            resource_id = item[config['id_field']]
            
            # Check if bucket is in the specified region
            try:
                bucket_location = client.get_bucket_location(Bucket=resource_id)
                bucket_region = bucket_location.get('LocationConstraint', 'us-east-1')
                
                # AWS returns None for us-east-1 region
                if bucket_region is None:
                    bucket_region = 'us-east-1'
                
                # Skip buckets that aren't in the specified region
                if region != 'all' and bucket_region != region:
                    continue
                
                # Get bucket tags
                resource_tags = {}
                try:
                    tag_response = client.get_bucket_tagging(Bucket=resource_id)
                    resource_tags = {tag['Key']: tag['Value'] for tag in tag_response.get('TagSet', [])}
                except client.exceptions.ClientError as e:
                    # Bucket might not have tags
                    if e.response['Error']['Code'] != 'NoSuchTagSet':
                        logger.warning(f"Error getting tags for bucket {resource_id}: {str(e)}")
                
                creation_date = item.get(config['date_field']) if config['date_field'] else ''
                
                # Format datetime object to string if needed
                if isinstance(creation_date, datetime.datetime):
                    creation_date = creation_date.isoformat()
                
                arn = config['arn_format'].format(resource_id=resource_id)

                resources.append({
                    "seq": 0,
                    "account_id": account_id,
                    "region": bucket_region,
                    "service": service,
                    "resource_type": service_type,
                    "resource_id": resource_id,
                    "name": resource_id,
                    "creation_date": creation_date,
                    "tags": resource_tags,
                    "tags_number": len(resource_tags),
                    "metadata": item,
                    "arn": arn
                })
                
            except Exception as e:
                logger.warning(f"Error processing bucket {resource_id}: {str(e)}")

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources

def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    logger.info(f'Discovery # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    for resource in resources:
        try:
            bucket_name = resource.identifier
            
            if tags_action == 1:  # Add tags
                # For S3, we need to either set all tags or add to existing ones
                try:
                    # Get current tags
                    current_tags_response = client.get_bucket_tagging(Bucket=bucket_name)
                    current_tags = current_tags_response.get('TagSet', [])
                except client.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchTagSet':
                        current_tags = []
                    else:
                        raise
                
                # Create a dict of current tags for easy update
                tag_dict = {tag['Key']: tag['Value'] for tag in current_tags}
                
                # Update with new tags
                for tag in tags:
                    tag_dict[tag['Key']] = tag['Value']
                
                # Convert back to list format S3 expects
                tag_set = [{'Key': k, 'Value': v} for k, v in tag_dict.items()]
                
                # Put the tags
                client.put_bucket_tagging(
                    Bucket=bucket_name,
                    Tagging={'TagSet': tag_set}
                )
                
            elif tags_action == 2:  # Remove tags
                try:
                    # Get current tags
                    current_tags_response = client.get_bucket_tagging(Bucket=bucket_name)
                    current_tags = current_tags_response.get('TagSet', [])
                    
                    # Skip keys that should be removed
                    keys_to_remove = [tag['Key'] for tag in tags]
                    filtered_tags = [tag for tag in current_tags if tag['Key'] not in keys_to_remove]
                    
                    if filtered_tags:
                        # Update with filtered tags
                        client.put_bucket_tagging(
                            Bucket=bucket_name,
                            Tagging={'TagSet': filtered_tags}
                        )
                    else:
                        # Remove all tags
                        client.delete_bucket_tagging(Bucket=bucket_name)
                        
                except client.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchTagSet':
                        # No tags to delete
                        pass
                    else:
                        raise
                
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
            logger.error(f"Error processing batch for {service} in {account_id}/{region}:{resource.identifier} # {str(e)}")
            
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

def parse_tags(tags_string: str) -> List[Dict[str, str]]:
    tags = []
    for tag_pair in tags_string.split(','):
        key, value = tag_pair.split(':')
        tags.append({
            'Key': key.strip(),
            'Value': value.strip()
        })
    return tags

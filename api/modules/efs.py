import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    resource_configs = {
        'FileSystem': {
            'method': 'describe_file_systems',
            'key': 'FileSystems',
            'id_field': 'FileSystemId',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': 'arn:aws:elasticfilesystem:{region}:{account_id}:file-system/{resource_id}'
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
        client = session.client('efs', region_name=region)
        method = getattr(client, config['method'])

        try:
            paginator = client.get_paginator(config['method'])
            response_iterator = paginator.paginate()
        except OperationNotPageableError:
            response_iterator = [method()]

        for page in response_iterator:
            items = page[config['key']]

            for item in items:
                resource_id = item[config['id_field']]
                
                # Get the file system's ARN
                arn = config['arn_format'].format(
                    region=region, 
                    account_id=account_id,
                    resource_id=resource_id
                )
                
                # EFS tags are stored in a different format, so we need to convert them
                try:
                    tags_response = client.describe_tags(FileSystemId=resource_id)
                    tags_list = tags_response.get('Tags', [])
                    # Convert the tag format to a dict for consistency
                    resource_tags = {tag['Key']: tag['Value'] for tag in tags_list}
                except Exception as tag_error:
                    logger.warning(f"Could not get tags for EFS {resource_id}: {str(tag_error)}")
                    resource_tags = {}
                
                # Get name from tags (convention for EFS) or use "untitled"
                name_tag = resource_tags.get('Name', '')
                creation_date = item.get(config['date_field']) if config['date_field'] else ''

                resources.append({
                    "seq": 0,
                    "account_id": account_id,
                    "region": region,
                    "service": service,
                    "resource_type": service_type,
                    "resource_id": resource_id,
                    "name": name_tag,
                    "creation_date": creation_date,
                    "tags": resource_tags,
                    "tags_number": len(resource_tags),
                    "metadata": item,
                    "arn": arn
                })

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources

def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    logger.info(f'Tagging # Account: {account_id}, Region: {region}, Service: {service}')
    
    # We need the EFS client for file system tagging
    results = []
    tags = parse_tags(tags_string)
    
    for resource in resources:
        try:
            resource_id = resource.identifier
            
            if tags_action == 1:  # Add tags
                # EFS uses a list of key-value pairs for tagging
                client.tag_resource(
                    ResourceId=resource_id,  # For EFS, we use the ID directly, not the ARN
                    Tags=tags  # This is already in the format EFS expects
                )
            elif tags_action == 2:  # Remove tags
                # For delete, we just need the keys
                tag_keys = [item['Key'] for item in tags]
                client.untag_resource(
                    ResourceId=resource_id,
                    TagKeys=tag_keys
                )
                    
            results.append({
                'account_id': account_id,
                'region': region,
                'service': service,
                'identifier': resource.identifier,
                'arn': resource.arn,
                'status': 'success',
                'error' : ""
                
            })
            
        except Exception as e:
            logger.error(f"Error processing tagging for {service} in {account_id}/{region}:{resource.identifier} # {str(e)}")
            
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
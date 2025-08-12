import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    """
    AWS Directory Service resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ds/client/add_tags_to_resource.html
    
    Directory Service supports tagging for:
    - Directory (the main resource type)
    """

    resource_configs = {
        'Directory': {
            'method': 'describe_directories',
            'key': 'DirectoryDescriptions',
            'id_field': 'DirectoryId',
            'name_field': 'Name',
            'date_field': 'LaunchTime',
            'nested': False,
            'arn_format': 'arn:aws:ds:{region}:{account_id}:directory/{resource_id}'
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
        
        # Directory Service is regional
        client = session.client('ds', region_name=region)
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for ds client")

        method = getattr(client, config['method'])
        params = {}

        # Handle pagination
        try:
            paginator = client.get_paginator(config['method'])
            page_iterator = paginator.paginate(**params)
        except OperationNotPageableError:
            response = method(**params)
            page_iterator = [response]

        # Process each page of results
        for page in page_iterator:
            items = page[config['key']]

            for item in items:
                resource_id = item[config['id_field']]
                
                # Get resource name
                resource_name = item.get(config['name_field'], resource_id) if config['name_field'] else resource_id

                # Get creation date (launch time)
                creation_date = None
                if config['date_field'] and config['date_field'] in item:
                    creation_date = item[config['date_field']]
                    if hasattr(creation_date, 'isoformat'):
                        creation_date = creation_date.isoformat()

                # Build ARN
                arn = config['arn_format'].format(
                    region=region,
                    account_id=account_id,
                    resource_id=resource_id
                )

                # Get existing tags
                resource_tags = {}
                try:
                    tags_response = client.list_tags_for_resource(ResourceId=resource_id)
                    tags_list = tags_response.get('Tags', [])
                    resource_tags = {tag['Key']: tag['Value'] for tag in tags_list}
                except Exception as tag_error:
                    logger.warning(f"Could not retrieve tags for {resource_id}: {tag_error}")
                    resource_tags = {}

                resources.append({
                    "account_id": account_id,
                    "region": region,
                    "service": service,
                    "resource_type": service_type,
                    "resource_id": resource_id,
                    "name": resource_name,
                    "creation_date": creation_date,
                    "tags": resource_tags,
                    "tags_number": len(resource_tags),
                    "metadata": item,
                    "arn": arn
                })

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} directories')

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

    # Create Directory Service client
    session = boto3.Session()
    ds_client = session.client('ds', region_name=region)

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to Directory Service format
                ds_tags = [{'Key': tag['Key'], 'Value': tag['Value']} for tag in tags]
                ds_client.add_tags_to_resource(
                    ResourceId=resource.identifier,
                    Tags=ds_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                ds_client.remove_tags_from_resource(
                    ResourceId=resource.identifier,
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

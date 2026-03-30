import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError
from typing import List, Dict, Tuple

def get_service_types(account_id, region, service, service_type):
    """
    Returns configuration for DynamoDB resource types for discovery and tagging
    """
    resource_configs = {
        'Table': {
            'method': 'list_tables',
            'key': 'TableNames',
            'id_field': None,  # Tables are identified by name in DynamoDB
            'date_field': None,  # Will fetch from describe_table
            'nested': False,
            'arn_format': 'arn:aws:dynamodb:{region}:{account_id}:table/{resource_id}'
        }
    }
    
    return resource_configs

def discovery(self, session, account_id, region, service, service_type, logger):    
    """
    Discovers DynamoDB resources based on service_type
    """
    status = "success"
    error_message = ""
    resources = []

    try:
        service_types_list = get_service_types(account_id, region, service, service_type)        
        if service_type not in service_types_list:
            raise ValueError(f"Unsupported service type: {service_type}")

        config = service_types_list[service_type]        
        client = session.client(service, region_name=region)

        method = getattr(client, config['method'])
        params = {}

        try:
            paginator = client.get_paginator(config['method'])
            response_iterator = paginator.paginate(**params)
        except OperationNotPageableError:
            response_iterator = [method(**params)]

        for page in response_iterator:
            table_names = page[config['key']]
            
            for table_name in table_names:
                # For DynamoDB tables, we need to get additional details with describe_table
                table_details = client.describe_table(TableName=table_name)['Table']
                
                resource_id = table_name
                
                # Get tags for the table
                arn = config['arn_format'].format(
                    region=region,
                    account_id=account_id,
                    resource_id=resource_id
                )
                
                # Get tags using the resource ARN
                try:
                    tags_response = client.list_tags_of_resource(ResourceArn=arn)
                    resource_tags = {tag['Key']: tag['Value'] for tag in tags_response.get('Tags', [])}
                except Exception as e:
                    logger.warning(f"Could not fetch tags for table {table_name}: {str(e)}")
                    resource_tags = {}
                
                name_tag = resource_tags.get('Name', table_name)
                
                # Get creation date from the table details
                creation_date = table_details.get('CreationDateTime', '')

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
                    "metadata": table_details,
                    "arn": arn
                })

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources

def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    """
    Apply or remove tags for DynamoDB resources
    """
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    for resource in resources:
        try:
            if tags_action == 1:  # Add tags
                client.tag_resource(
                    ResourceArn=resource.arn,
                    Tags=tags
                )
            elif tags_action == 2:  # Remove tags
                tag_keys = [item['Key'] for item in tags]
                client.untag_resource(
                    ResourceArn=resource.arn,
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
    """
    Parse a string of tags in format key1:value1,key2:value2 into a list of tag dictionaries
    """
    tags = []
    for tag_pair in tags_string.split(','):
        key, value = tag_pair.split(':')
        tags.append({
            'Key': key.strip(),
            'Value': value.strip()
        })
    return tags
import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    resource_configs = {
        'RestApi': {
            'method': 'get_rest_apis',
            'key': 'items',
            'id_field': 'id',
            'date_field': 'createdDate',
            'nested': False,
            'endpoint_type_filter': None,  # All REST APIs (public, private, etc.)
            'arn_format': 'arn:aws:apigateway:{region}::/restapis/{resource_id}'
        },
        'RestApiPrivate': {
            'method': 'get_rest_apis',
            'key': 'items',
            'id_field': 'id',
            'date_field': 'createdDate',
            'nested': False,
            'endpoint_type_filter': 'PRIVATE',  # Only private REST APIs
            'arn_format': 'arn:aws:apigateway:{region}::/restapis/{resource_id}'
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
        client = session.client('apigateway', region_name=region)
        method = getattr(client, config['method'])

        try:
            paginator = client.get_paginator(config['method'])
            response_iterator = paginator.paginate()
        except OperationNotPageableError:
            response_iterator = [method()]

        for page in response_iterator:
            items = page[config['key']]

            for item in items:
                # Filter for specific endpoint type if needed (like PRIVATE)
                if config['endpoint_type_filter']:
                    endpoint_configuration = item.get('endpointConfiguration', {})
                    types = endpoint_configuration.get('types', [])
                    if config['endpoint_type_filter'] not in types:
                        continue
                # For RestApi type, we want to exclude private REST APIs
                elif service_type == 'RestApi':
                    endpoint_configuration = item.get('endpointConfiguration', {})
                    types = endpoint_configuration.get('types', [])
                    if 'PRIVATE' in types:
                        continue

                resource_id = item[config['id_field']]
                
                # Get tags for the API
                resource_tags = {}
                try:
                    arn = config['arn_format'].format(
                        region=region, 
                        account_id=account_id,
                        resource_id=resource_id
                    )
                    tags_response = client.get_tags(resourceArn=arn)
                    resource_tags = tags_response.get('tags', {})
                except Exception as tag_error:
                    logger.warning(f"Could not get tags for API Gateway {resource_id}: {str(tag_error)}")

                # Get name from API definition or tags
                name_tag = item.get('name') or resource_tags.get('Name', '')
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
    
    results = []
    tags = parse_tags(tags_string)
    
    for resource in resources:
        try:
            resource_id = resource.identifier
            arn = resource.arn
            
            if tags_action == 1:  # Add tags
                # Convert to dictionary format for apigateway
                tag_dict = {item['Key']: item['Value'] for item in tags}
                client.tag_resource(
                    resourceArn=arn,
                    tags=tag_dict
                )
            elif tags_action == 2:  # Remove tags
                # For delete, we just need the keys
                tag_keys = [item['Key'] for item in tags]
                client.untag_resource(
                    resourceArn=arn,
                    tagKeys=tag_keys
                )
                    
            results.append({
                'account_id': account_id,
                'region': region,
                'service': service,
                'identifier': resource_id,
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
    tags = []
    for tag_pair in tags_string.split(','):
        key, value = tag_pair.split(':')
        tags.append({
            'Key': key.strip(),
            'Value': value.strip()
        })
    return tags
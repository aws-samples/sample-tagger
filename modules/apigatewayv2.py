import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    resource_configs = {
        'HttpApi': {
            'method': 'get_apis',
            'key': 'Items',
            'id_field': 'ApiId',
            'date_field': 'CreatedDate',
            'nested': False,
            'protocol_type': 'HTTP',
            'arn_format': 'arn:aws:apigateway:{region}::/apis/{resource_id}'
        },
        'WebSocketApi': {
            'method': 'get_apis',
            'key': 'Items',
            'id_field': 'ApiId',
            'date_field': 'CreatedDate',
            'nested': False,
            'protocol_type': 'WEBSOCKET',
            'arn_format': 'arn:aws:apigateway:{region}::/apis/{resource_id}'
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
        client = session.client('apigatewayv2', region_name=region)
        method = getattr(client, config['method'])

        try:
            paginator = client.get_paginator(config['method'])
            response_iterator = paginator.paginate()
        except OperationNotPageableError:
            response_iterator = [method()]

        for page in response_iterator:
            items = page.get(config['key'], [])

            for item in items:
                # Filter based on protocol type
                if item.get('ProtocolType') != config['protocol_type']:
                    continue

                resource_id = item[config['id_field']]
                
                # Get the API's ARN
                arn = config['arn_format'].format(
                    region=region, 
                    resource_id=resource_id
                )
                
                # Get tags - for apigatewayv2, tags are included in the API response
                resource_tags = item.get('Tags', {})
                
                # For apigatewayv2, tags are a dict, not a list of key-value pairs
                tags_list = [{'Key': k, 'Value': v} for k, v in resource_tags.items()]
                
                # Get name from API definition or tags
                name_tag = item.get('Name') or resource_tags.get('Name', '')
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
    
    # We'll need the apigatewayv2 client for HTTP and WebSocket APIs
    results = []
    tags = parse_tags(tags_string)
    for resource in resources:
        try:
            resource_id = resource.identifier
            arn = resource.arn
            
            if tags_action == 1:  # Add tags
                # Convert to dictionary format for apigatewayv2
                tag_dict = {item['Key']: item['Value'] for item in tags}
                client.tag_resource(
                    ResourceArn=arn,  # Note: Capital R in ResourceArn for apigatewayv2
                    Tags=tag_dict      # Note: Capital T in Tags for apigatewayv2
                )
            elif tags_action == 2:  # Remove tags
                # For delete, we just need the keys
                tag_keys = [item['Key'] for item in tags]
                client.untag_resource(
                    ResourceArn=arn,   # Note: Capital R in ResourceArn for apigatewayv2
                    TagKeys=tag_keys   # Note: Capital T in TagKeys for apigatewayv2
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
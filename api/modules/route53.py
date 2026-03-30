import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    """
    Route53 DNS resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/route53/client/change_tags_for_resource.html
    Valid ResourceType values: healthcheck, hostedzone
    """

    resource_configs = {
        'HostedZone': {
            'method': 'list_hosted_zones',
            'key': 'HostedZones',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:route53:::hostedzone/{resource_id}',
            'resource_type_for_tagging': 'hostedzone'
        },
        'HealthCheck': {
            'method': 'list_health_checks',
            'key': 'HealthChecks',
            'id_field': 'Id',
            'name_field': None,
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:route53:::healthcheck/{resource_id}',
            'resource_type_for_tagging': 'healthcheck'
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
        
        # Route53 is always global
        client = session.client('route53')
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for route53 client")

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
            if config.get('nested', False):
                items = []
                for reservation in page[config['key']]:
                    items.extend(reservation.get('Instances', []))
            else:
                items = page[config['key']]

            for item in items:
                resource_id = item[config['id_field']]
                
                # Clean up resource ID for HostedZone
                clean_resource_id = resource_id
                if service_type == 'HostedZone':
                    clean_resource_id = resource_id.replace('/hostedzone/', '')

                # Get resource name
                resource_name = item.get(config['name_field'], clean_resource_id) if config['name_field'] else clean_resource_id

                # Get creation date
                creation_date = None
                if config['date_field'] and config['date_field'] in item:
                    creation_date = item[config['date_field']]
                    if hasattr(creation_date, 'isoformat'):
                        creation_date = creation_date.isoformat()

                # Build ARN
                arn = config['arn_format'].format(
                    region=region,
                    account_id=account_id,
                    resource_id=clean_resource_id
                )

                # Get existing tags
                resource_tags = {}
                try:
                    tags_response = client.list_tags_for_resource(
                        ResourceType=config['resource_type_for_tagging'],
                        ResourceId=clean_resource_id
                    )
                    resource_tags = {tag['Key']: tag['Value'] for tag in tags_response.get('ResourceTagSet', {}).get('Tags', [])}
                except Exception as tag_error:
                    logger.warning(f"Could not retrieve tags for {clean_resource_id}: {tag_error}")
                    resource_tags = {}

                resources.append({
                    "account_id": account_id,
                    "region": "global",  # Route53 is always global
                    "service": service,
                    "resource_type": service_type,
                    "resource_id": clean_resource_id,
                    "name": resource_name,
                    "creation_date": creation_date,
                    "tags": resource_tags,
                    "tags_number": len(resource_tags),
                    "metadata": item,
                    "arn": arn
                })

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} resources')

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

    for resource in resources:            
        try:
            service_types_list = get_service_types(account_id, region, service, 'HostedZone')
            
            # Determine resource type from ARN
            resource_type = None
            if 'hostedzone' in resource.arn:
                resource_type = 'HostedZone'
            elif 'healthcheck' in resource.arn:
                resource_type = 'HealthCheck'
            else:
                results.append({
                    'account_id': account_id,
                    'region': 'global',
                    'service': service,
                    'identifier': resource.identifier,
                    'arn': resource.arn,
                    'status': 'skipped',
                    'error': 'Unknown Route53 resource type'
                })
                continue
            
            if resource_type not in service_types_list:
                results.append({
                    'account_id': account_id,
                    'region': 'global',
                    'service': service,
                    'identifier': resource.identifier,
                    'arn': resource.arn,
                    'status': 'skipped',
                    'error': f'Resource type {resource_type} does not support tagging'
                })
                continue

            config = service_types_list[resource_type]

            if tags_action == 1:
                # Add tags
                client.change_tags_for_resource(
                    ResourceType=config['resource_type_for_tagging'],
                    ResourceId=resource.identifier,
                    AddTags=tags
                )
            elif tags_action == 2:
                # Remove tags
                client.change_tags_for_resource(
                    ResourceType=config['resource_type_for_tagging'],
                    ResourceId=resource.identifier,
                    RemoveTagKeys=tag_keys
                )
                    
            results.append({
                'account_id': account_id,
                'region': 'global',
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
                'region': 'global',
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

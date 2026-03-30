import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    """
    AWS Security Hub resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/securityhub/client/tag_resource.html
    
    Security Hub supports tagging for:
    - Hub (Security Hub instance)
    - Insight (Custom insights)
    - Standard (Security standards)
    """

    resource_configs = {
        'Hub': {
            'method': 'describe_hub',
            'key': None,  # Single resource
            'id_field': None,
            'name_field': None,
            'date_field': 'SubscribedAt',
            'nested': False,
            'arn_format': 'arn:aws:securityhub:{region}:{account_id}:hub/default'
        },
        'Insight': {
            'method': 'get_insights',
            'key': 'Insights',
            'id_field': 'InsightArn',
            'name_field': 'Name',
            'date_field': None,
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'Standard': {
            'method': 'get_enabled_standards',
            'key': 'StandardsSubscriptions',
            'id_field': 'StandardsSubscriptionArn',
            'name_field': 'StandardsArn',
            'date_field': 'StandardsStatusReason',
            'nested': False,
            'arn_format': None  # ARN is provided directly
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
        
        # Security Hub is regional
        client = session.client('securityhub', region_name=region)
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for securityhub client")

        method = getattr(client, config['method'])

        if service_type == 'Hub':
            # Hub is a single resource per region
            try:
                response = method()
                
                # Extract hub information
                hub_arn = response.get('HubArn', f"arn:aws:securityhub:{region}:{account_id}:hub/default")
                subscribed_at = response.get('SubscribedAt')
                auto_enable_controls = response.get('AutoEnableControls', False)
                
                # Get creation date
                creation_date = None
                if subscribed_at and hasattr(subscribed_at, 'isoformat'):
                    creation_date = subscribed_at.isoformat()

                # Get existing tags
                resource_tags = {}
                try:
                    tags_response = client.list_tags_for_resource(ResourceArn=hub_arn)
                    tags_dict = tags_response.get('Tags', {})
                    resource_tags = tags_dict
                except Exception as tag_error:
                    logger.warning(f"Could not retrieve tags for hub: {tag_error}")
                    resource_tags = {}

                resources.append({
                    "account_id": account_id,
                    "region": region,
                    "service": service,
                    "resource_type": service_type,
                    "resource_id": "default",
                    "name": "Security Hub",
                    "creation_date": creation_date,
                    "tags": resource_tags,
                    "tags_number": len(resource_tags),
                    "metadata": {
                        "HubArn": hub_arn,
                        "AutoEnableControls": auto_enable_controls
                    },
                    "arn": hub_arn
                })

            except Exception as hub_error:
                if "is not subscribed to AWS Security Hub" in str(hub_error):
                    logger.info("Security Hub is not enabled in this region")
                else:
                    raise hub_error

        elif service_type in ['Insight', 'Standard']:
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
                    if service_type == 'Insight':
                        resource_id = item[config['id_field']]
                        arn = resource_id  # InsightArn is the full ARN
                        resource_name = item.get(config['name_field'], resource_id.split('/')[-1])
                    elif service_type == 'Standard':
                        resource_id = item[config['id_field']]
                        arn = resource_id  # StandardsSubscriptionArn is the full ARN
                        resource_name = item.get(config['name_field'], resource_id.split('/')[-1])

                    # Get creation date
                    creation_date = None
                    if config['date_field'] and config['date_field'] in item:
                        creation_date = item[config['date_field']]
                        if hasattr(creation_date, 'isoformat'):
                            creation_date = creation_date.isoformat()

                    # Get existing tags
                    resource_tags = {}
                    try:
                        tags_response = client.list_tags_for_resource(ResourceArn=arn)
                        tags_dict = tags_response.get('Tags', {})
                        resource_tags = tags_dict
                    except Exception as tag_error:
                        logger.warning(f"Could not retrieve tags for {resource_id}: {tag_error}")
                        resource_tags = {}

                    resources.append({
                        "account_id": account_id,
                        "region": region,
                        "service": service,
                        "resource_type": service_type,
                        "resource_id": resource_id.split('/')[-1] if '/' in resource_id else resource_id,
                        "name": resource_name,
                        "creation_date": creation_date,
                        "tags": resource_tags,
                        "tags_number": len(resource_tags),
                        "metadata": item,
                        "arn": arn
                    })

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

    # Create Security Hub client
    session = boto3.Session()
    securityhub_client = session.client('securityhub', region_name=region)

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to Security Hub format (dict)
                securityhub_tags = {tag['Key']: tag['Value'] for tag in tags}
                securityhub_client.tag_resource(
                    ResourceArn=resource.arn,
                    Tags=securityhub_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                securityhub_client.untag_resource(
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

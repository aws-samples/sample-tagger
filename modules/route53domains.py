import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    """
    Route53 Domains resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/route53domains/client/update_tags_for_domain.html
    Note: Route53 Domains uses different tagging APIs (update_tags_for_domain, list_tags_for_domain)
    """

    resource_configs = {
        'Domain': {
            'method': 'list_domains',
            'key': 'Domains',
            'id_field': 'DomainName',
            'name_field': 'DomainName',
            'date_field': 'Expiry',
            'nested': False,
            'arn_format': 'arn:aws:route53domains::{account_id}:domain/{resource_id}'
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
        
        # Route53 Domains is global but client must be created in us-east-1
        client = session.client('route53domains', region_name='us-east-1')
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for route53domains client")

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
                resource_name = item.get(config['name_field'], resource_id) if config['name_field'] else resource_id

                # Get expiry date
                expiry_date = None
                if config['date_field'] and config['date_field'] in item:
                    expiry_date = item[config['date_field']]
                    if hasattr(expiry_date, 'isoformat'):
                        expiry_date = expiry_date.isoformat()

                # Build ARN
                arn = config['arn_format'].format(
                    account_id=account_id,
                    resource_id=resource_id
                )

                # Get existing tags
                resource_tags = {}
                try:
                    tags_response = client.list_tags_for_domain(DomainName=resource_id)
                    resource_tags = {tag['Key']: tag['Value'] for tag in tags_response.get('TagList', [])}
                except Exception as tag_error:
                    logger.warning(f"Could not retrieve tags for {resource_id}: {tag_error}")
                    resource_tags = {}

                resources.append({
                    "account_id": account_id,
                    "region": "global",  # Route53 Domains is global
                    "service": service,
                    "resource_type": service_type,
                    "resource_id": resource_id,
                    "name": resource_name,
                    "creation_date": expiry_date,  # Using expiry date as the date field
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

    # Create Route53 Domains client (must be us-east-1)
    session = boto3.Session()
    domains_client = session.client('route53domains', region_name='us-east-1')

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags using update_tags_for_domain
                domains_client.update_tags_for_domain(
                    DomainName=resource.identifier,
                    TagsToUpdate=tags
                )
            elif tags_action == 2:
                # Remove tags using update_tags_for_domain with empty values
                tags_to_remove = [{'Key': key, 'Value': ''} for key in tag_keys]
                domains_client.update_tags_for_domain(
                    DomainName=resource.identifier,
                    TagsToUpdate=tags_to_remove
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

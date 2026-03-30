import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    """
    AWS Cognito Identity resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-identity/client/tag_resource.html
    
    Cognito Identity supports tagging for:
    - IdentityPool (identity pools for federated identities)
    """

    resource_configs = {
        'IdentityPool': {
            'method': 'list_identity_pools',
            'key': 'IdentityPools',
            'id_field': 'IdentityPoolId',
            'name_field': 'IdentityPoolName',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:cognito-identity:{region}:{account_id}:identitypool/{resource_id}'
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
        
        # Cognito Identity is regional
        client = session.client('cognito-identity', region_name=region)
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for cognito-identity client")

        method = getattr(client, config['method'])
        
        # list_identity_pools requires MaxResults parameter
        params = {'MaxResults': 60}  # Maximum allowed value

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

                # Get creation date - need to describe the identity pool for more details
                creation_date = None
                try:
                    pool_details = client.describe_identity_pool(IdentityPoolId=resource_id)
                    # Cognito Identity pools don't have a creation date in the API response
                    # We'll leave it as None
                except Exception as detail_error:
                    logger.warning(f"Could not get details for identity pool {resource_id}: {detail_error}")

                # Build ARN
                arn = config['arn_format'].format(
                    region=region,
                    account_id=account_id,
                    resource_id=resource_id
                )

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
                    "resource_id": resource_id,
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

    # Create Cognito Identity client
    session = boto3.Session()
    cognito_client = session.client('cognito-identity', region_name=region)

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to Cognito Identity format (dict)
                cognito_tags = {tag['Key']: tag['Value'] for tag in tags}
                cognito_client.tag_resource(
                    ResourceArn=resource.arn,
                    Tags=cognito_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                cognito_client.untag_resource(
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

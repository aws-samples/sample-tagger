import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    """
    AWS Cognito IDP resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp/client/list_tags_for_resource.html
    
    Cognito IDP supports tagging for:
    - UserPool (Cognito User Pools for user authentication)
    - UserPoolDomain (Custom domains for User Pools)
    """

    resource_configs = {
        'UserPool': {
            'method': 'list_user_pools',
            'key': 'UserPools',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': 'CreationDate',
            'nested': False,
            'arn_format': 'arn:aws:cognito-idp:{region}:{account_id}:userpool/{resource_id}'
        },
        'UserPoolDomain': {
            'method': 'list_user_pools',  # We'll get domains from user pools
            'key': 'UserPools',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': 'CreationDate',
            'nested': True,  # Special handling needed
            'arn_format': 'arn:aws:cognito-idp:{region}:{account_id}:userpool/{user_pool_id}'
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
        
        # Cognito IDP is regional
        client = session.client('cognito-idp', region_name=region)
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for cognito-idp client")

        method = getattr(client, config['method'])
        
        # Set MaxResults for list_user_pools
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

            # Special handling for UserPoolDomain
            if service_type == 'UserPoolDomain':
                # For each user pool, check if it has a domain
                for user_pool in items:
                    user_pool_id = user_pool[config['id_field']]
                    user_pool_name = user_pool.get(config['name_field'], user_pool_id)
                    
                    try:
                        # Check if this user pool has a domain
                        domain_response = client.describe_user_pool_domain(Domain=user_pool_id)
                        domain_config = domain_response.get('DomainDescription', {})
                        
                        if domain_config and domain_config.get('Domain'):
                            domain_name = domain_config['Domain']
                            
                            # Build ARN for the domain
                            arn = f"arn:aws:cognito-idp:{region}:{account_id}:userpool/{user_pool_id}/domain/{domain_name}"
                            
                            # Get creation date from user pool
                            creation_date = user_pool.get(config['date_field'])
                            if hasattr(creation_date, 'isoformat'):
                                creation_date = creation_date.isoformat()

                            # Additional metadata for domain
                            additional_metadata = {
                                'UserPoolId': user_pool_id,
                                'UserPoolName': user_pool_name,
                                'DomainStatus': domain_config.get('Status', ''),
                                'CloudFrontDistribution': domain_config.get('CloudFrontDistribution', ''),
                                'CustomDomainConfig': domain_config.get('CustomDomainConfig', {})
                            }

                            # Get existing tags (domains inherit user pool tags)
                            resource_tags = {}
                            try:
                                user_pool_arn = f"arn:aws:cognito-idp:{region}:{account_id}:userpool/{user_pool_id}"
                                tags_response = client.list_tags_for_resource(ResourceArn=user_pool_arn)
                                resource_tags = tags_response.get('Tags', {})
                            except Exception as tag_error:
                                logger.warning(f"Could not retrieve tags for domain {domain_name}: {tag_error}")
                                resource_tags = {}

                            # Combine metadata
                            metadata = {**domain_config, **additional_metadata}

                            resources.append({
                                "account_id": account_id,
                                "region": region,
                                "service": service,
                                "resource_type": service_type,
                                "resource_id": domain_name,
                                "name": domain_name,
                                "creation_date": creation_date,
                                "tags": resource_tags,
                                "tags_number": len(resource_tags),
                                "metadata": metadata,
                                "arn": arn
                            })
                            
                    except Exception as domain_error:
                        # This user pool doesn't have a domain, which is normal
                        if "ResourceNotFoundException" not in str(domain_error):
                            logger.warning(f"Could not check domain for user pool {user_pool_id}: {domain_error}")
                        continue
            else:
                # Regular processing for UserPool
                for item in items:
                    resource_id = item[config['id_field']]
                    
                    # Get resource name
                    resource_name = item.get(config['name_field'], resource_id) if config['name_field'] else resource_id

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
                        resource_id=resource_id
                    )

                    # Get existing tags
                    resource_tags = {}
                    try:
                        tags_response = client.list_tags_for_resource(ResourceArn=arn)
                        tags_dict = tags_response.get('Tags', {})
                        resource_tags = tags_dict
                    except Exception as tag_error:
                        logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                        resource_tags = {}

                    # Get additional metadata for UserPool
                    additional_metadata = {}
                    if service_type == 'UserPool':
                        try:
                            # Get detailed user pool information
                            pool_response = client.describe_user_pool(UserPoolId=resource_id)
                            pool_details = pool_response.get('UserPool', {})
                            
                            additional_metadata = {
                                'Status': pool_details.get('Status', ''),
                                'Policies': pool_details.get('Policies', {}),
                                'LambdaConfig': pool_details.get('LambdaConfig', {}),
                                'AutoVerifiedAttributes': pool_details.get('AutoVerifiedAttributes', []),
                                'AliasAttributes': pool_details.get('AliasAttributes', []),
                                'UsernameAttributes': pool_details.get('UsernameAttributes', []),
                                'MfaConfiguration': pool_details.get('MfaConfiguration', 'OFF'),
                                'EstimatedNumberOfUsers': pool_details.get('EstimatedNumberOfUsers', 0)
                            }
                            
                        except Exception as detail_error:
                            logger.warning(f"Could not get details for user pool {resource_name}: {detail_error}")

                    # Combine original item with additional metadata
                    metadata = {**item, **additional_metadata}

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
                        "metadata": metadata,
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

    # Create Cognito IDP client
    session = boto3.Session()
    cognitoidp_client = session.client('cognito-idp', region_name=region)

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to Cognito IDP format (dict)
                cognitoidp_tags = {tag['Key']: tag['Value'] for tag in tags}
                cognitoidp_client.tag_resource(
                    ResourceArn=resource.arn,
                    Tags=cognitoidp_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                cognitoidp_client.untag_resource(
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

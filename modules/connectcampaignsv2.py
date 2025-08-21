import json
import boto3
import time
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError, ClientError, ConnectTimeoutError, ReadTimeoutError
from botocore.config import Config

def get_service_types(account_id, region, service, service_type):
    """
    Amazon Connect Campaign Service V2 resources that support tagging.
    
    Based on AWS Connect Campaigns V2 documentation:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/connectcampaignsv2.html
    
    Connect Campaigns V2 supports tagging for:
    - Campaign (Outbound campaigns for automated calling with enhanced features)
    
    Note: Connect Campaigns V2 is the enhanced version with additional features like:
    - Multi-channel support (voice, SMS, email)
    - Advanced communication limits
    - Enhanced flow associations
    - Profile-based outbound requests
    """

    resource_configs = {
        'Campaign': {
            'method': 'list_campaigns',
            'key': 'campaignSummaryList',
            'id_field': 'id',
            'name_field': 'name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:connect-campaigns:{region}:{account_id}:campaign/{resource_id}',
            'describe_method': 'describe_campaign',
            'describe_param': 'id'
        }
    }
    
    return resource_configs


def retry_with_backoff(func, max_retries=5, base_delay=1, max_delay=60):
    """
    Retry function with exponential backoff for handling rate limiting
    """
    for attempt in range(max_retries):
        try:
            return func()
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code in ['TooManyRequestsException', 'Throttling', 'ThrottlingException']:
                if attempt < max_retries - 1:
                    delay = min(base_delay * (2 ** attempt), max_delay)
                    time.sleep(delay)
                    continue
            raise
        except Exception as e:
            raise
    return None


def discovery(self, session, account_id, region, service, service_type, logger):    
    
    status = "success"
    error_message = ""
    resources = []

    try:
        service_types_list = get_service_types(account_id, region, service, service_type)        
        if service_type not in service_types_list:
            raise ValueError(f"Unsupported service type: {service_type}")

        config = service_types_list[service_type]
        
        # Configure client with timeouts
        client_config = Config(
            read_timeout=15,
            connect_timeout=10,
            retries={'max_attempts': 3, 'mode': 'standard'}
        )
        
        try:
            client = session.client('connectcampaignsv2', region_name=region, config=client_config)
        except Exception as e:
            logger.warning(f"Connect Campaigns V2 client creation failed in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        
        if not hasattr(client, config['method']):
            logger.warning(f"Method {config['method']} not available for connectcampaignsv2 client")
            return f'{service}:{service_type}', "success", "", []

        method = getattr(client, config['method'])
        params = {}
        
        # Handle Connect Campaigns V2 API calls with proper error handling and retry logic
        try:
            logger.info(f"Calling Connect Campaigns V2 {config['method']} in region {region}")
            
            def get_resources():
                # Handle pagination
                try:
                    paginator = client.get_paginator(config['method'])
                    pages = []
                    for page in paginator.paginate(**params):
                        pages.append(page)
                    return pages
                except OperationNotPageableError:
                    response = method(**params)
                    return [response]
            
            page_iterator = retry_with_backoff(get_resources, max_retries=5)
            if page_iterator is None:
                logger.warning(f"Failed to get {service_type} after retries")
                return f'{service}:{service_type}', "success", "", []
                
        except (ConnectTimeoutError, ReadTimeoutError) as e:
            logger.warning(f"Connect Campaigns V2 timeout in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code in ['UnauthorizedOperation', 'AccessDenied', 'InvalidAction']:
                logger.warning(f"Connect Campaigns V2 not available in region {region}: {error_code}")
                return f'{service}:{service_type}', "success", "", []
            elif error_code in ['ResourceNotFoundException', 'InvalidParameterException']:
                logger.info(f"Connect Campaigns V2 {service_type} not found in region {region}")
                return f'{service}:{service_type}', "success", "", []
            else:
                logger.error(f"Connect Campaigns V2 API error in region {region}: {str(e)}")
                return f'{service}:{service_type}', "error", str(e), []
        except Exception as e:
            logger.warning(f"Connect Campaigns V2 general error in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []

        # Process results
        for page in page_iterator:
            items = page.get(config['key'], [])

            for item in items:
                try:
                    resource_id = item[config['id_field']]
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

                    # Get existing tags with retry logic
                    resource_tags = {}
                    try:
                        def get_tags():
                            return client.list_tags_for_resource(arn=arn)
                        
                        tags_response = retry_with_backoff(get_tags, max_retries=3)
                        if tags_response:
                            # Connect Campaigns V2 returns tags as a dictionary
                            resource_tags = tags_response.get('tags', {})
                        else:
                            logger.warning(f"Failed to get tags for Connect Campaigns V2 resource {resource_name}")
                            resource_tags = {}
                            
                    except (ConnectTimeoutError, ReadTimeoutError):
                        logger.warning(f"Timeout retrieving tags for Connect Campaigns V2 resource {resource_name}")
                        resource_tags = {}
                    except ClientError as tag_error:
                        tag_error_code = tag_error.response.get('Error', {}).get('Code', 'Unknown')
                        if tag_error_code in ['ResourceNotFoundException', 'AccessDenied']:
                            logger.info(f"No tags found for Connect Campaigns V2 resource {resource_name}")
                            resource_tags = {}
                        else:
                            logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                            resource_tags = {}
                    except Exception as tag_error:
                        logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                        resource_tags = {}

                    # Get additional metadata for Campaign
                    additional_metadata = {}
                    if service_type == 'Campaign':
                        additional_metadata = {
                            'connectInstanceId': item.get('connectInstanceId', ''),
                            'channelSubtypeConfig': item.get('channelSubtypeConfig', {}),
                            'source': item.get('source', {}),
                            'connectCampaignFlowArn': item.get('connectCampaignFlowArn', ''),
                            'tags': item.get('tags', {})
                        }

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
                except Exception as item_error:
                    logger.warning(f"Error processing Connect Campaigns V2 item: {str(item_error)}")
                    continue

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} {service_type.lower()}s')

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in Connect Campaigns V2 discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources


def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    # Create Connect Campaigns V2 client with timeout protection
    session = boto3.Session()
    client_config = Config(
        read_timeout=15,
        connect_timeout=10,
        retries={'max_attempts': 3, 'mode': 'standard'}
    )
    
    try:
        campaigns_client = session.client('connectcampaignsv2', region_name=region, config=client_config)
    except Exception as e:
        logger.error(f"Failed to create Connect Campaigns V2 client: {str(e)}")
        return []

    for resource in resources:
        try:
            def tag_resource():
                if tags_action == 1:  # Add tags
                    # Convert tags to dictionary format for Connect Campaigns V2
                    tags_dict = {tag['Key']: tag['Value'] for tag in tags}
                    campaigns_client.tag_resource(
                        arn=resource.arn,
                        tags=tags_dict
                    )
                elif tags_action == 2:  # Remove tags
                    campaigns_client.untag_resource(
                        arn=resource.arn,
                        tagKeys=[tag['Key'] for tag in tags]
                    )
            
            # Use retry logic for tagging operations
            retry_with_backoff(tag_resource, max_retries=3)
                
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
            logger.error(f"Error processing batch for {service} in {account_id}/{region}:{resource.identifier} # {str(e)}")
            
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

import json
import boto3
import time
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError, ClientError, ConnectTimeoutError, ReadTimeoutError
from botocore.config import Config

def get_service_types(account_id, region, service, service_type):
    """
    Amazon CloudFront resources that support tagging.
    
    Based on AWS CloudFront documentation:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudfront.html
    
    CloudFront supports tagging for:
    - Distribution (CloudFront distributions)
    - StreamingDistribution (CloudFront streaming distributions - legacy)
    - Function (CloudFront Functions)
    - CachePolicy (Cache policies)
    - OriginRequestPolicy (Origin request policies)
    - ResponseHeadersPolicy (Response headers policies)
    - RealtimeLogConfig (Real-time log configurations)
    - KeyGroup (Key groups for signed URLs/cookies)
    - FieldLevelEncryptionConfig (Field-level encryption configurations)
    - FieldLevelEncryptionProfile (Field-level encryption profiles)
    - ContinuousDeploymentPolicy (Continuous deployment policies)
    - OriginAccessControl (Origin access controls)
    - VpcOrigin (VPC origins)
    - AnycastIpList (Anycast IP lists)
    """

    resource_configs = {
        'Distribution': {
            'method': 'list_distributions',
            'key': 'DistributionList',
            'items_key': 'Items',
            'id_field': 'Id',
            'name_field': 'DomainName',
            'date_field': 'LastModifiedTime',
            'nested': False,
            'arn_format': 'arn:aws:cloudfront::{account_id}:distribution/{resource_id}',
            'describe_method': 'get_distribution',
            'describe_param': 'Id'
        },
        'StreamingDistribution': {
            'method': 'list_streaming_distributions',
            'key': 'StreamingDistributionList',
            'items_key': 'Items',
            'id_field': 'Id',
            'name_field': 'DomainName',
            'date_field': 'LastModifiedTime',
            'nested': False,
            'arn_format': 'arn:aws:cloudfront::{account_id}:streaming-distribution/{resource_id}',
            'describe_method': 'get_streaming_distribution',
            'describe_param': 'Id'
        },
        'Function': {
            'method': 'list_functions',
            'key': 'FunctionList',
            'items_key': 'Items',
            'id_field': 'Name',
            'name_field': 'Name',
            'date_field': 'LastModifiedTime',
            'nested': False,
            'arn_format': 'arn:aws:cloudfront::{account_id}:function/{resource_id}',
            'describe_method': 'get_function',
            'describe_param': 'Name'
        },
        'CachePolicy': {
            'method': 'list_cache_policies',
            'key': 'CachePolicyList',
            'items_key': 'Items',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': 'LastModifiedTime',
            'nested': False,
            'arn_format': 'arn:aws:cloudfront::{account_id}:cache-policy/{resource_id}',
            'describe_method': 'get_cache_policy',
            'describe_param': 'Id',
            'type_filter': 'custom'  # Only list custom policies
        },
        'OriginRequestPolicy': {
            'method': 'list_origin_request_policies',
            'key': 'OriginRequestPolicyList',
            'items_key': 'Items',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': 'LastModifiedTime',
            'nested': False,
            'arn_format': 'arn:aws:cloudfront::{account_id}:origin-request-policy/{resource_id}',
            'describe_method': 'get_origin_request_policy',
            'describe_param': 'Id',
            'type_filter': 'custom'  # Only list custom policies
        },
        'ResponseHeadersPolicy': {
            'method': 'list_response_headers_policies',
            'key': 'ResponseHeadersPolicyList',
            'items_key': 'Items',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': 'LastModifiedTime',
            'nested': False,
            'arn_format': 'arn:aws:cloudfront::{account_id}:response-headers-policy/{resource_id}',
            'describe_method': 'get_response_headers_policy',
            'describe_param': 'Id',
            'type_filter': 'custom'  # Only list custom policies
        },
        'RealtimeLogConfig': {
            'method': 'list_realtime_log_configs',
            'key': 'RealtimeLogConfigs',
            'items_key': 'Items',
            'id_field': 'Name',
            'name_field': 'Name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:cloudfront::{account_id}:realtime-log-config/{resource_id}',
            'describe_method': 'get_realtime_log_config',
            'describe_param': 'Name'
        },
        'KeyGroup': {
            'method': 'list_key_groups',
            'key': 'KeyGroupList',
            'items_key': 'Items',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': 'LastModifiedTime',
            'nested': False,
            'arn_format': 'arn:aws:cloudfront::{account_id}:key-group/{resource_id}',
            'describe_method': 'get_key_group',
            'describe_param': 'Id'
        },
        'FieldLevelEncryptionConfig': {
            'method': 'list_field_level_encryption_configs',
            'key': 'FieldLevelEncryptionList',
            'items_key': 'Items',
            'id_field': 'Id',
            'name_field': 'Comment',
            'date_field': 'LastModifiedTime',
            'nested': False,
            'arn_format': 'arn:aws:cloudfront::{account_id}:field-level-encryption-config/{resource_id}',
            'describe_method': 'get_field_level_encryption',
            'describe_param': 'Id'
        },
        'FieldLevelEncryptionProfile': {
            'method': 'list_field_level_encryption_profiles',
            'key': 'FieldLevelEncryptionProfileList',
            'items_key': 'Items',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': 'LastModifiedTime',
            'nested': False,
            'arn_format': 'arn:aws:cloudfront::{account_id}:field-level-encryption-profile/{resource_id}',
            'describe_method': 'get_field_level_encryption_profile',
            'describe_param': 'Id'
        },
        'ContinuousDeploymentPolicy': {
            'method': 'list_continuous_deployment_policies',
            'key': 'ContinuousDeploymentPolicyList',
            'items_key': 'Items',
            'id_field': 'Id',
            'name_field': 'Id',
            'date_field': 'LastModifiedTime',
            'nested': False,
            'arn_format': 'arn:aws:cloudfront::{account_id}:continuous-deployment-policy/{resource_id}',
            'describe_method': 'get_continuous_deployment_policy',
            'describe_param': 'Id'
        },
        'OriginAccessControl': {
            'method': 'list_origin_access_controls',
            'key': 'OriginAccessControlList',
            'items_key': 'Items',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:cloudfront::{account_id}:origin-access-control/{resource_id}',
            'describe_method': 'get_origin_access_control',
            'describe_param': 'Id'
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
        
        # Configure client with timeouts - CloudFront is global service
        client_config = Config(
            read_timeout=15,
            connect_timeout=10,
            retries={'max_attempts': 3, 'mode': 'standard'}
        )
        
        try:
            # CloudFront is a global service, always use us-east-1
            client = session.client('cloudfront', region_name='us-east-1', config=client_config)
        except Exception as e:
            logger.warning(f"CloudFront client creation failed: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        
        if not hasattr(client, config['method']):
            logger.warning(f"Method {config['method']} not available for cloudfront client")
            return f'{service}:{service_type}', "success", "", []

        method = getattr(client, config['method'])
        params = {}
        
        # Add type filter for policies if specified
        if config.get('type_filter'):
            params['Type'] = config['type_filter']
        
        # Handle CloudFront API calls with proper error handling and retry logic
        try:
            logger.info(f"Calling CloudFront {config['method']}")
            
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
            logger.warning(f"CloudFront timeout: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code in ['UnauthorizedOperation', 'AccessDenied', 'InvalidAction']:
                logger.warning(f"CloudFront not available: {error_code}")
                return f'{service}:{service_type}', "success", "", []
            elif error_code in ['ResourceNotFoundException', 'InvalidParameterException', 'NoSuchResource']:
                logger.info(f"CloudFront {service_type} not found")
                return f'{service}:{service_type}', "success", "", []
            else:
                logger.error(f"CloudFront API error: {str(e)}")
                return f'{service}:{service_type}', "error", str(e), []
        except Exception as e:
            logger.warning(f"CloudFront general error: {str(e)}")
            return f'{service}:{service_type}', "success", "", []

        # Process results
        for page in page_iterator:
            # Get the list container
            list_container = page.get(config['key'], {})
            
            # Handle different response structures
            if config.get('items_key'):
                items = list_container.get(config['items_key'], [])
            else:
                items = list_container if isinstance(list_container, list) else []

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
                        account_id=account_id,
                        resource_id=resource_id
                    )

                    # Get existing tags with retry logic
                    resource_tags = {}
                    try:
                        def get_tags():
                            return client.list_tags_for_resource(Resource=arn)
                        
                        tags_response = retry_with_backoff(get_tags, max_retries=3)
                        if tags_response:
                            # CloudFront returns tags in Tags.Items array
                            tags_container = tags_response.get('Tags', {})
                            tags_list = tags_container.get('Items', [])
                            resource_tags = {tag.get('Key', ''): tag.get('Value', '') for tag in tags_list}
                        else:
                            logger.warning(f"Failed to get tags for CloudFront resource {resource_name}")
                            resource_tags = {}
                            
                    except (ConnectTimeoutError, ReadTimeoutError):
                        logger.warning(f"Timeout retrieving tags for CloudFront resource {resource_name}")
                        resource_tags = {}
                    except ClientError as tag_error:
                        tag_error_code = tag_error.response.get('Error', {}).get('Code', 'Unknown')
                        if tag_error_code in ['ResourceNotFoundException', 'AccessDenied', 'NoSuchResource']:
                            logger.info(f"No tags found for CloudFront resource {resource_name}")
                            resource_tags = {}
                        else:
                            logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                            resource_tags = {}
                    except Exception as tag_error:
                        logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                        resource_tags = {}

                    # Get additional metadata based on resource type
                    additional_metadata = {}
                    if service_type == 'Distribution':
                        additional_metadata = {
                            'Status': item.get('Status', ''),
                            'Enabled': item.get('Enabled', False),
                            'Comment': item.get('Comment', ''),
                            'PriceClass': item.get('PriceClass', ''),
                            'HttpVersion': item.get('HttpVersion', ''),
                            'IsIPV6Enabled': item.get('IsIPV6Enabled', False),
                            'WebACLId': item.get('WebACLId', ''),
                            'Staging': item.get('Staging', False)
                        }
                    elif service_type == 'StreamingDistribution':
                        additional_metadata = {
                            'Status': item.get('Status', ''),
                            'Enabled': item.get('Enabled', False),
                            'Comment': item.get('Comment', ''),
                            'PriceClass': item.get('PriceClass', ''),
                            'TrustedSigners': item.get('TrustedSigners', {})
                        }
                    elif service_type == 'Function':
                        additional_metadata = {
                            'Status': item.get('Status', ''),
                            'FunctionConfig': item.get('FunctionConfig', {}),
                            'FunctionMetadata': item.get('FunctionMetadata', {})
                        }
                    elif service_type in ['CachePolicy', 'OriginRequestPolicy', 'ResponseHeadersPolicy']:
                        additional_metadata = {
                            'Type': item.get('Type', ''),
                            'Comment': item.get('Comment', '')
                        }
                    elif service_type == 'KeyGroup':
                        additional_metadata = {
                            'Comment': item.get('Comment', ''),
                            'Items': item.get('Items', [])
                        }
                    elif service_type == 'RealtimeLogConfig':
                        additional_metadata = {
                            'EndPoints': item.get('EndPoints', []),
                            'Fields': item.get('Fields', []),
                            'SamplingRate': item.get('SamplingRate', 0)
                        }

                    # Combine original item with additional metadata
                    metadata = {**item, **additional_metadata}

                    resources.append({
                        "account_id": account_id,
                        "region": "global",  # CloudFront is global
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
                    logger.warning(f"Error processing CloudFront item: {str(item_error)}")
                    continue

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} {service_type.lower()}s')

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in CloudFront discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources


def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    logger.info(f'Tagging # Account : {account_id}, Region : global, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    # Create CloudFront client with timeout protection
    session = boto3.Session()
    client_config = Config(
        read_timeout=15,
        connect_timeout=10,
        retries={'max_attempts': 3, 'mode': 'standard'}
    )
    
    try:
        # CloudFront is a global service, always use us-east-1
        cf_client = session.client('cloudfront', region_name='us-east-1', config=client_config)
    except Exception as e:
        logger.error(f"Failed to create CloudFront client: {str(e)}")
        return []

    for resource in resources:
        try:
            def tag_resource():
                if tags_action == 1:  # Add tags
                    # Convert tags to CloudFront format (list of Key-Value objects)
                    tags_list = [{'Key': tag['Key'], 'Value': tag['Value']} for tag in tags]
                    cf_client.tag_resource(
                        Resource=resource.arn,
                        Tags={'Items': tags_list}
                    )
                elif tags_action == 2:  # Remove tags
                    cf_client.untag_resource(
                        Resource=resource.arn,
                        TagKeys={'Items': [tag['Key'] for tag in tags]}
                    )
            
            # Use retry logic for tagging operations
            retry_with_backoff(tag_resource, max_retries=3)
                
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
            logger.error(f"Error processing batch for {service} in {account_id}/global:{resource.identifier} # {str(e)}")
            
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


def parse_tags(tags_string: str) -> List[Dict[str, str]]:
    tags = []
    for tag_pair in tags_string.split(','):
        key, value = tag_pair.split(':')
        tags.append({
            'Key': key.strip(),
            'Value': value.strip()
        })
    return tags

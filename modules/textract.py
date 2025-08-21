import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError, ClientError, ConnectTimeoutError, ReadTimeoutError
from botocore.config import Config

def get_service_types(account_id, region, service, service_type):
    """
    Amazon Textract resources that support tagging.
    
    Based on AWS Textract documentation:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/textract.html
    
    Textract supports tagging for:
    - Adapter (Custom adapters for document analysis)
    - AdapterVersion (Versions of custom adapters)
    
    Note: Textract is primarily a service-based API for document analysis.
    The main taggable resources are adapters which are used to customize
    document analysis for specific use cases.
    """

    resource_configs = {
        'Adapter': {
            'method': 'list_adapters',
            'key': 'Adapters',
            'id_field': 'AdapterId',
            'name_field': 'AdapterName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': 'arn:aws:textract:{region}:{account_id}:adapter/{resource_id}',
            'describe_method': 'get_adapter',
            'describe_param': 'AdapterId'
        },
        'AdapterVersion': {
            'method': 'list_adapter_versions',
            'key': 'AdapterVersions',
            'id_field': 'AdapterVersionArn',
            'name_field': 'AdapterVersion',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'describe_method': 'get_adapter_version',
            'describe_param': 'AdapterId',
            'requires_adapter': True  # Requires adapter ID parameter
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
        
        # Configure client with timeouts
        client_config = Config(
            read_timeout=15,
            connect_timeout=10,
            retries={'max_attempts': 2, 'mode': 'standard'}
        )
        
        try:
            client = session.client('textract', region_name=region, config=client_config)
        except Exception as e:
            logger.warning(f"Textract client creation failed in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        
        if not hasattr(client, config['method']):
            logger.warning(f"Method {config['method']} not available for textract client")
            return f'{service}:{service_type}', "success", "", []

        method = getattr(client, config['method'])
        params = {}
        
        # Special handling for AdapterVersion which requires adapter IDs
        if config.get('requires_adapter', False):
            # First get list of adapters
            try:
                adapters_response = client.list_adapters()
                adapter_ids = [adapter['AdapterId'] for adapter in adapters_response.get('Adapters', [])]
                if not adapter_ids:
                    logger.info(f"No adapters found for {service_type} discovery")
                    return f'{service}:{service_type}', "success", "", []
                
                # Get adapter versions for each adapter
                all_items = []
                for adapter_id in adapter_ids:
                    try:
                        response = method(AdapterId=adapter_id)
                        all_items.extend(response.get(config['key'], []))
                    except Exception as adapter_error:
                        logger.warning(f"Error getting adapter versions for adapter {adapter_id}: {adapter_error}")
                        continue
                page_iterator = [{'AdapterVersions': all_items}]
            except Exception as adapter_error:
                logger.warning(f"Error listing adapters for {service_type}: {adapter_error}")
                return f'{service}:{service_type}', "success", "", []
        else:
            # Handle Textract API calls with proper error handling
            try:
                logger.info(f"Calling Textract {config['method']} in region {region}")
                
                # Handle pagination
                try:
                    paginator = client.get_paginator(config['method'])
                    page_iterator = paginator.paginate(**params)
                except OperationNotPageableError:
                    response = method(**params)
                    page_iterator = [response]
                    
            except (ConnectTimeoutError, ReadTimeoutError) as e:
                logger.warning(f"Textract timeout in region {region}: {str(e)}")
                return f'{service}:{service_type}', "success", "", []
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                if error_code in ['UnauthorizedOperation', 'AccessDenied', 'InvalidAction']:
                    logger.warning(f"Textract not available in region {region}: {error_code}")
                    return f'{service}:{service_type}', "success", "", []
                else:
                    logger.error(f"Textract API error in region {region}: {str(e)}")
                    return f'{service}:{service_type}', "error", str(e), []
            except Exception as e:
                logger.warning(f"Textract general error in region {region}: {str(e)}")
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
                    if config['arn_format']:
                        arn = config['arn_format'].format(
                            region=region,
                            account_id=account_id,
                            resource_id=resource_id
                        )
                    else:
                        arn = resource_id  # ARN is provided directly

                    # Get existing tags
                    resource_tags = {}
                    try:
                        tags_response = client.list_tags_for_resource(ResourceARN=arn)
                        tags_dict = tags_response.get('Tags', {})
                        # Textract returns tags as a dictionary
                        resource_tags = tags_dict
                    except (ConnectTimeoutError, ReadTimeoutError):
                        logger.warning(f"Timeout retrieving tags for Textract resource {resource_name}")
                        resource_tags = {}
                    except Exception as tag_error:
                        logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                        resource_tags = {}

                    # Get additional metadata based on resource type
                    additional_metadata = {}
                    if service_type == 'Adapter':
                        additional_metadata = {
                            'AdapterName': item.get('AdapterName', ''),
                            'Description': item.get('Description', ''),
                            'FeatureTypes': item.get('FeatureTypes', []),
                            'AutoUpdate': item.get('AutoUpdate', ''),
                            'Tags': item.get('Tags', {})
                        }
                        
                        # Get detailed adapter information
                        try:
                            adapter_details = client.get_adapter(AdapterId=resource_id)
                            additional_metadata.update({
                                'AdapterName': adapter_details.get('AdapterName', ''),
                                'Description': adapter_details.get('Description', ''),
                                'FeatureTypes': adapter_details.get('FeatureTypes', []),
                                'AutoUpdate': adapter_details.get('AutoUpdate', ''),
                                'CreationTime': adapter_details.get('CreationTime', ''),
                                'Tags': adapter_details.get('Tags', {})
                            })
                        except Exception as detail_error:
                            logger.warning(f"Could not get adapter details for {resource_name}: {detail_error}")
                            
                    elif service_type == 'AdapterVersion':
                        additional_metadata = {
                            'AdapterId': item.get('AdapterId', ''),
                            'AdapterVersion': item.get('AdapterVersion', ''),
                            'Status': item.get('Status', ''),
                            'StatusMessage': item.get('StatusMessage', ''),
                            'DatasetConfig': item.get('DatasetConfig', {}),
                            'KMSKeyId': item.get('KMSKeyId', ''),
                            'OutputConfig': item.get('OutputConfig', {}),
                            'EvaluationMetrics': item.get('EvaluationMetrics', []),
                            'Tags': item.get('Tags', {})
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
                    logger.warning(f"Error processing Textract item: {str(item_error)}")
                    continue

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} {service_type.lower()}s')

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in Textract discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources


def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    if tags_action == 2:        
        tag_keys = list(tags.keys()) if isinstance(tags, dict) else [tag['Key'] for tag in tags]

    # Create Textract client with timeout protection
    session = boto3.Session()
    client_config = Config(
        read_timeout=15,
        connect_timeout=10,
        retries={'max_attempts': 2, 'mode': 'standard'}
    )
    
    try:
        textract_client = session.client('textract', region_name=region, config=client_config)
    except Exception as e:
        logger.error(f"Failed to create Textract client: {str(e)}")
        return []

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Textract uses dictionary format
                if isinstance(tags, list):
                    textract_tags = {tag['Key']: tag['Value'] for tag in tags}
                else:
                    textract_tags = tags
                    
                textract_client.tag_resource(
                    ResourceARN=resource.arn,
                    Tags=textract_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                textract_client.untag_resource(
                    ResourceARN=resource.arn,
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
    """Parse tags from string format to dictionary"""
    tags = {}
    if tags_string:
        for tag_pair in tags_string.split(','):
            if ':' in tag_pair:
                key, value = tag_pair.split(':', 1)
                tags[key.strip()] = value.strip()
    return tags

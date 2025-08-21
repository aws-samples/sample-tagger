import json
import boto3
import time
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError, ClientError, ConnectTimeoutError, ReadTimeoutError
from botocore.config import Config

def get_service_types(account_id, region, service, service_type):
    """
    Amazon Kendra resources that support tagging.
    
    Based on AWS Kendra documentation:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kendra.html
    
    Kendra supports tagging for:
    - Index (Kendra search indexes)
    - DataSource (Data sources for indexes)
    - FAQ (Frequently Asked Questions)
    - Thesaurus (Thesaurus for query expansion)
    - Experience (Search experiences)
    - QuerySuggestionsBlockList (Query suggestions block lists)
    - FeaturedResultsSet (Featured results sets)
    - AccessControlConfiguration (Access control configurations)
    """

    resource_configs = {
        'Index': {
            'method': 'list_indices',
            'key': 'IndexConfigurationSummaryItems',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': 'CreatedAt',
            'nested': False,
            'arn_format': 'arn:aws:kendra:{region}:{account_id}:index/{resource_id}',
            'describe_method': 'describe_index',
            'describe_param': 'Id'
        },
        'DataSource': {
            'method': 'list_data_sources',
            'key': 'SummaryItems',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': 'CreatedAt',
            'nested': False,
            'arn_format': 'arn:aws:kendra:{region}:{account_id}:index/{index_id}/data-source/{resource_id}',
            'describe_method': 'describe_data_source',
            'describe_param': 'Id',
            'requires_index': True
        },
        'FAQ': {
            'method': 'list_faqs',
            'key': 'FaqSummaryItems',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': 'CreatedAt',
            'nested': False,
            'arn_format': 'arn:aws:kendra:{region}:{account_id}:index/{index_id}/faq/{resource_id}',
            'describe_method': 'describe_faq',
            'describe_param': 'Id',
            'requires_index': True
        },
        'Thesaurus': {
            'method': 'list_thesauri',
            'key': 'ThesaurusSummaryItems',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': 'CreatedAt',
            'nested': False,
            'arn_format': 'arn:aws:kendra:{region}:{account_id}:index/{index_id}/thesaurus/{resource_id}',
            'describe_method': 'describe_thesaurus',
            'describe_param': 'Id',
            'requires_index': True
        },
        'Experience': {
            'method': 'list_experiences',
            'key': 'SummaryItems',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': 'CreatedAt',
            'nested': False,
            'arn_format': 'arn:aws:kendra:{region}:{account_id}:index/{index_id}/experience/{resource_id}',
            'describe_method': 'describe_experience',
            'describe_param': 'Id',
            'requires_index': True
        },
        'QuerySuggestionsBlockList': {
            'method': 'list_query_suggestions_block_lists',
            'key': 'BlockListSummaryItems',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': 'CreatedAt',
            'nested': False,
            'arn_format': 'arn:aws:kendra:{region}:{account_id}:index/{index_id}/query-suggestions-block-list/{resource_id}',
            'describe_method': 'describe_query_suggestions_block_list',
            'describe_param': 'Id',
            'requires_index': True
        },
        'FeaturedResultsSet': {
            'method': 'list_featured_results_sets',
            'key': 'FeaturedResultsSetSummaryItems',
            'id_field': 'FeaturedResultsSetId',
            'name_field': 'FeaturedResultsSetName',
            'date_field': 'CreationTimestamp',
            'nested': False,
            'arn_format': 'arn:aws:kendra:{region}:{account_id}:index/{index_id}/featured-results-set/{resource_id}',
            'describe_method': 'describe_featured_results_set',
            'describe_param': 'FeaturedResultsSetId',
            'requires_index': True
        },
        'AccessControlConfiguration': {
            'method': 'list_access_control_configurations',
            'key': 'AccessControlConfigurations',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:kendra:{region}:{account_id}:index/{index_id}/access-control-configuration/{resource_id}',
            'describe_method': 'describe_access_control_configuration',
            'describe_param': 'Id',
            'requires_index': True
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
            client = session.client('kendra', region_name=region, config=client_config)
        except Exception as e:
            logger.warning(f"Kendra client creation failed in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        
        if not hasattr(client, config['method']):
            logger.warning(f"Method {config['method']} not available for kendra client")
            return f'{service}:{service_type}', "success", "", []

        method = getattr(client, config['method'])
        params = {}
        
        # Special handling for resources that require index IDs
        if config.get('requires_index', False):
            # First get list of indexes
            try:
                def get_indexes():
                    return client.list_indices()
                
                indexes_response = retry_with_backoff(get_indexes, max_retries=3)
                if not indexes_response:
                    logger.info(f"No Kendra indexes found for {service_type} discovery")
                    return f'{service}:{service_type}', "success", "", []
                    
                index_ids = [idx['Id'] for idx in indexes_response.get('IndexConfigurationSummaryItems', [])]
                if not index_ids:
                    logger.info(f"No Kendra indexes found for {service_type} discovery")
                    return f'{service}:{service_type}', "success", "", []
                
                # Get resources for each index
                all_items = []
                for index_id in index_ids:
                    try:
                        def get_index_resources():
                            index_params = {'IndexId': index_id}
                            response = method(**index_params)
                            items = response.get(config['key'], [])
                            
                            # Add index_id to each item for ARN construction
                            for item in items:
                                item['_index_id'] = index_id
                            return items
                        
                        index_items = retry_with_backoff(get_index_resources, max_retries=3)
                        if index_items is not None:
                            all_items.extend(index_items)
                        else:
                            logger.warning(f"Failed to get {service_type} for index {index_id}")
                            
                    except Exception as index_error:
                        logger.warning(f"Error getting {service_type} for index {index_id}: {index_error}")
                        continue
                        
                page_iterator = [{config['key']: all_items}]
                
            except Exception as index_error:
                logger.warning(f"Error listing indexes for {service_type}: {index_error}")
                return f'{service}:{service_type}', "success", "", []
        else:
            # Handle Kendra API calls with proper error handling and retry logic
            try:
                logger.info(f"Calling Kendra {config['method']} in region {region}")
                
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
                logger.warning(f"Kendra timeout in region {region}: {str(e)}")
                return f'{service}:{service_type}', "success", "", []
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                if error_code in ['UnauthorizedOperation', 'AccessDenied', 'InvalidAction']:
                    logger.warning(f"Kendra not available in region {region}: {error_code}")
                    return f'{service}:{service_type}', "success", "", []
                elif error_code in ['ResourceNotFoundException', 'InvalidParameterException']:
                    logger.info(f"Kendra {service_type} not found in region {region}")
                    return f'{service}:{service_type}', "success", "", []
                else:
                    logger.error(f"Kendra API error in region {region}: {str(e)}")
                    return f'{service}:{service_type}', "error", str(e), []
            except Exception as e:
                logger.warning(f"Kendra general error in region {region}: {str(e)}")
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
                    if config.get('requires_index', False):
                        index_id = item.get('_index_id', '')
                        arn = config['arn_format'].format(
                            region=region,
                            account_id=account_id,
                            index_id=index_id,
                            resource_id=resource_id
                        )
                    else:
                        arn = config['arn_format'].format(
                            region=region,
                            account_id=account_id,
                            resource_id=resource_id
                        )

                    # Get existing tags with retry logic
                    resource_tags = {}
                    try:
                        def get_tags():
                            return client.list_tags_for_resource(ResourceARN=arn)
                        
                        tags_response = retry_with_backoff(get_tags, max_retries=3)
                        if tags_response:
                            # Kendra returns tags as a list of Key-Value objects
                            tags_list = tags_response.get('Tags', [])
                            resource_tags = {tag.get('Key', ''): tag.get('Value', '') for tag in tags_list}
                        else:
                            logger.warning(f"Failed to get tags for Kendra resource {resource_name}")
                            resource_tags = {}
                            
                    except (ConnectTimeoutError, ReadTimeoutError):
                        logger.warning(f"Timeout retrieving tags for Kendra resource {resource_name}")
                        resource_tags = {}
                    except ClientError as tag_error:
                        tag_error_code = tag_error.response.get('Error', {}).get('Code', 'Unknown')
                        if tag_error_code in ['ResourceNotFoundException', 'AccessDenied']:
                            logger.info(f"No tags found for Kendra resource {resource_name}")
                            resource_tags = {}
                        else:
                            logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                            resource_tags = {}
                    except Exception as tag_error:
                        logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                        resource_tags = {}

                    # Get additional metadata based on resource type
                    additional_metadata = {}
                    if service_type == 'Index':
                        additional_metadata = {
                            'Status': item.get('Status', ''),
                            'Edition': item.get('Edition', ''),
                            'UpdatedAt': item.get('UpdatedAt', ''),
                            'Description': item.get('Description', '')
                        }
                    elif service_type == 'DataSource':
                        additional_metadata = {
                            'Type': item.get('Type', ''),
                            'Status': item.get('Status', ''),
                            'UpdatedAt': item.get('UpdatedAt', ''),
                            'LanguageCode': item.get('LanguageCode', '')
                        }
                    elif service_type == 'FAQ':
                        additional_metadata = {
                            'Status': item.get('Status', ''),
                            'UpdatedAt': item.get('UpdatedAt', ''),
                            'FileFormat': item.get('FileFormat', ''),
                            'LanguageCode': item.get('LanguageCode', '')
                        }
                    elif service_type == 'Thesaurus':
                        additional_metadata = {
                            'Status': item.get('Status', ''),
                            'UpdatedAt': item.get('UpdatedAt', ''),
                            'Description': item.get('Description', '')
                        }
                    elif service_type == 'Experience':
                        additional_metadata = {
                            'Status': item.get('Status', ''),
                            'UpdatedAt': item.get('UpdatedAt', ''),
                            'Endpoints': item.get('Endpoints', [])
                        }
                    elif service_type == 'QuerySuggestionsBlockList':
                        additional_metadata = {
                            'Status': item.get('Status', ''),
                            'UpdatedAt': item.get('UpdatedAt', ''),
                            'ItemCount': item.get('ItemCount', 0),
                            'Description': item.get('Description', '')
                        }
                    elif service_type == 'FeaturedResultsSet':
                        additional_metadata = {
                            'Status': item.get('Status', ''),
                            'LastUpdatedTimestamp': item.get('LastUpdatedTimestamp', ''),
                            'Description': item.get('Description', '')
                        }
                    elif service_type == 'AccessControlConfiguration':
                        additional_metadata = {
                            'Description': item.get('Description', '')
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
                    logger.warning(f"Error processing Kendra item: {str(item_error)}")
                    continue

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} {service_type.lower()}s')

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in Kendra discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources


def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    # Create Kendra client with timeout protection
    session = boto3.Session()
    client_config = Config(
        read_timeout=15,
        connect_timeout=10,
        retries={'max_attempts': 3, 'mode': 'standard'}
    )
    
    try:
        kendra_client = session.client('kendra', region_name=region, config=client_config)
    except Exception as e:
        logger.error(f"Failed to create Kendra client: {str(e)}")
        return []

    for resource in resources:
        try:
            def tag_resource():
                if tags_action == 1:  # Add tags
                    # Convert tags to Kendra format (list of Key-Value objects)
                    tags_list = [{'Key': tag['Key'], 'Value': tag['Value']} for tag in tags]
                    kendra_client.tag_resource(
                        ResourceARN=resource.arn,
                        Tags=tags_list
                    )
                elif tags_action == 2:  # Remove tags
                    kendra_client.untag_resource(
                        ResourceARN=resource.arn,
                        TagKeys=[tag['Key'] for tag in tags]
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

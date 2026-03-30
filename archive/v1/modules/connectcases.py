import json
import boto3
import time
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError, ClientError, ConnectTimeoutError, ReadTimeoutError
from botocore.config import Config

def get_service_types(account_id, region, service, service_type):
    """
    Amazon Connect Cases resources that support tagging.
    
    Based on AWS Connect Cases documentation:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/connectcases.html
    
    Connect Cases supports tagging for:
    - Domain (Cases domains for case management)
    - Case (Individual cases)
    - Field (Custom fields for cases)
    - Layout (Case layouts for UI presentation)
    - Template (Case templates for standardization)
    - CaseRule (Rules for case automation)
    """

    resource_configs = {
        'Domain': {
            'method': 'list_domains',
            'key': 'domains',
            'id_field': 'domainId',
            'name_field': 'name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:cases:{region}:{account_id}:domain/{resource_id}',
            'describe_method': 'get_domain',
            'describe_param': 'domainId'
        },
        'Case': {
            'method': 'search_cases',
            'key': 'cases',
            'id_field': 'caseId',
            'name_field': 'caseId',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:cases:{region}:{account_id}:domain/{domain_id}/case/{resource_id}',
            'describe_method': 'get_case',
            'describe_param': 'caseId',
            'requires_domain': True,
            'search_based': True
        },
        'Field': {
            'method': 'list_fields',
            'key': 'fields',
            'id_field': 'fieldId',
            'name_field': 'name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:cases:{region}:{account_id}:domain/{domain_id}/field/{resource_id}',
            'requires_domain': True
        },
        'Layout': {
            'method': 'list_layouts',
            'key': 'layouts',
            'id_field': 'layoutId',
            'name_field': 'name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:cases:{region}:{account_id}:domain/{domain_id}/layout/{resource_id}',
            'describe_method': 'get_layout',
            'describe_param': 'layoutId',
            'requires_domain': True
        },
        'Template': {
            'method': 'list_templates',
            'key': 'templates',
            'id_field': 'templateId',
            'name_field': 'name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:cases:{region}:{account_id}:domain/{domain_id}/template/{resource_id}',
            'describe_method': 'get_template',
            'describe_param': 'templateId',
            'requires_domain': True
        },
        'CaseRule': {
            'method': 'list_case_rules',
            'key': 'caseRules',
            'id_field': 'ruleId',
            'name_field': 'name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:cases:{region}:{account_id}:domain/{domain_id}/case-rule/{resource_id}',
            'requires_domain': True
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
            client = session.client('connectcases', region_name=region, config=client_config)
        except Exception as e:
            logger.warning(f"Connect Cases client creation failed in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        
        if not hasattr(client, config['method']):
            logger.warning(f"Method {config['method']} not available for connectcases client")
            return f'{service}:{service_type}', "success", "", []

        method = getattr(client, config['method'])
        params = {}
        
        # Special handling for resources that require domain IDs
        if config.get('requires_domain', False):
            # First get list of domains
            try:
                def get_domains():
                    return client.list_domains()
                
                domains_response = retry_with_backoff(get_domains, max_retries=3)
                if not domains_response:
                    logger.warning(f"Failed to get domains for {service_type}")
                    return f'{service}:{service_type}', "success", "", []
                    
                domain_ids = [domain['domainId'] for domain in domains_response.get('domains', [])]
                if not domain_ids:
                    logger.info(f"No Connect Cases domains found for {service_type} discovery")
                    return f'{service}:{service_type}', "success", "", []
                
                # Get resources for each domain
                all_items = []
                for domain_id in domain_ids:
                    try:
                        def get_domain_resources():
                            domain_params = {'domainId': domain_id}
                            
                            # Special handling for Case search
                            if config.get('search_based', False):
                                # Use search_cases with minimal filter
                                domain_params['filter'] = {}
                                domain_params['sorts'] = []
                                
                            response = method(**domain_params)
                            items = response.get(config['key'], [])
                            
                            # Add domain_id to each item for ARN construction
                            for item in items:
                                item['_domain_id'] = domain_id
                            return items
                        
                        domain_items = retry_with_backoff(get_domain_resources, max_retries=3)
                        if domain_items is not None:
                            all_items.extend(domain_items)
                        else:
                            logger.warning(f"Failed to get {service_type} for domain {domain_id}")
                            
                    except Exception as domain_error:
                        logger.warning(f"Error getting {service_type} for domain {domain_id}: {domain_error}")
                        continue
                        
                page_iterator = [{config['key']: all_items}]
                
            except Exception as domain_error:
                logger.warning(f"Error listing domains for {service_type}: {domain_error}")
                return f'{service}:{service_type}', "success", "", []
        else:
            # Handle Connect Cases API calls with proper error handling and retry logic
            try:
                logger.info(f"Calling Connect Cases {config['method']} in region {region}")
                
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
                logger.warning(f"Connect Cases timeout in region {region}: {str(e)}")
                return f'{service}:{service_type}', "success", "", []
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                if error_code in ['UnauthorizedOperation', 'AccessDenied', 'InvalidAction']:
                    logger.warning(f"Connect Cases not available in region {region}: {error_code}")
                    return f'{service}:{service_type}', "success", "", []
                elif error_code in ['ResourceNotFoundException', 'InvalidParameterException']:
                    logger.info(f"Connect Cases {service_type} not found in region {region}")
                    return f'{service}:{service_type}', "success", "", []
                else:
                    logger.error(f"Connect Cases API error in region {region}: {str(e)}")
                    return f'{service}:{service_type}', "error", str(e), []
            except Exception as e:
                logger.warning(f"Connect Cases general error in region {region}: {str(e)}")
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
                    if config.get('requires_domain', False):
                        domain_id = item.get('_domain_id', '')
                        arn = config['arn_format'].format(
                            region=region,
                            account_id=account_id,
                            domain_id=domain_id,
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
                            return client.list_tags_for_resource(arn=arn)
                        
                        tags_response = retry_with_backoff(get_tags, max_retries=3)
                        if tags_response:
                            # Connect Cases returns tags as a dictionary
                            resource_tags = tags_response.get('tags', {})
                        else:
                            logger.warning(f"Failed to get tags for Connect Cases resource {resource_name}")
                            resource_tags = {}
                            
                    except (ConnectTimeoutError, ReadTimeoutError):
                        logger.warning(f"Timeout retrieving tags for Connect Cases resource {resource_name}")
                        resource_tags = {}
                    except ClientError as tag_error:
                        tag_error_code = tag_error.response.get('Error', {}).get('Code', 'Unknown')
                        if tag_error_code in ['ResourceNotFoundException', 'AccessDenied']:
                            logger.info(f"No tags found for Connect Cases resource {resource_name}")
                            resource_tags = {}
                        else:
                            logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                            resource_tags = {}
                    except Exception as tag_error:
                        logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                        resource_tags = {}

                    # Get additional metadata based on resource type
                    additional_metadata = {}
                    if service_type == 'Domain':
                        additional_metadata = {
                            'domainStatus': item.get('domainStatus', ''),
                            'name': item.get('name', ''),
                            'domainArn': item.get('domainArn', '')
                        }
                    elif service_type == 'Case':
                        additional_metadata = {
                            'templateId': item.get('templateId', ''),
                            'fields': item.get('fields', []),
                            'tags': item.get('tags', {})
                        }
                    elif service_type == 'Field':
                        additional_metadata = {
                            'type': item.get('type', ''),
                            'namespace': item.get('namespace', ''),
                            'description': item.get('description', '')
                        }
                    elif service_type == 'Layout':
                        additional_metadata = {
                            'layoutArn': item.get('layoutArn', ''),
                            'content': item.get('content', {}),
                            'tags': item.get('tags', {})
                        }
                    elif service_type == 'Template':
                        additional_metadata = {
                            'templateArn': item.get('templateArn', ''),
                            'description': item.get('description', ''),
                            'layoutConfiguration': item.get('layoutConfiguration', {}),
                            'requiredFields': item.get('requiredFields', []),
                            'tags': item.get('tags', {}),
                            'status': item.get('status', '')
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
                    logger.warning(f"Error processing Connect Cases item: {str(item_error)}")
                    continue

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} {service_type.lower()}s')

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in Connect Cases discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources


def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    # Create Connect Cases client with timeout protection
    session = boto3.Session()
    client_config = Config(
        read_timeout=15,
        connect_timeout=10,
        retries={'max_attempts': 3, 'mode': 'standard'}
    )
    
    try:
        cases_client = session.client('connectcases', region_name=region, config=client_config)
    except Exception as e:
        logger.error(f"Failed to create Connect Cases client: {str(e)}")
        return []

    for resource in resources:
        try:
            def tag_resource():
                if tags_action == 1:  # Add tags
                    # Convert tags to dictionary format for Connect Cases
                    tags_dict = {tag['Key']: tag['Value'] for tag in tags}
                    cases_client.tag_resource(
                        arn=resource.arn,
                        tags=tags_dict
                    )
                elif tags_action == 2:  # Remove tags
                    cases_client.untag_resource(
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

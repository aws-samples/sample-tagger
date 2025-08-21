import json
import boto3
import time
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError, ClientError, ConnectTimeoutError, ReadTimeoutError
from botocore.config import Config

def get_service_types(account_id, region, service, service_type):
    """
    Amazon Connect Wisdom resources that support tagging.
    
    Based on AWS Connect Wisdom documentation:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/wisdom.html
    
    Connect Wisdom supports tagging for:
    - Assistant (AI assistants for agent guidance)
    - KnowledgeBase (Knowledge bases for content storage)
    - Content (Individual content items)
    - QuickResponse (Quick response templates)
    - AssistantAssociation (Associations between assistants and knowledge bases)
    - Session (Wisdom sessions)
    - ImportJob (Content import jobs)
    """

    resource_configs = {
        'Assistant': {
            'method': 'list_assistants',
            'key': 'assistantSummaries',
            'id_field': 'assistantId',
            'name_field': 'name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:wisdom:{region}:{account_id}:assistant/{resource_id}',
            'describe_method': 'get_assistant',
            'describe_param': 'assistantId'
        },
        'KnowledgeBase': {
            'method': 'list_knowledge_bases',
            'key': 'knowledgeBaseSummaries',
            'id_field': 'knowledgeBaseId',
            'name_field': 'name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:wisdom:{region}:{account_id}:knowledge-base/{resource_id}',
            'describe_method': 'get_knowledge_base',
            'describe_param': 'knowledgeBaseId'
        },
        'Content': {
            'method': 'list_contents',
            'key': 'contentSummaries',
            'id_field': 'contentId',
            'name_field': 'name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:wisdom:{region}:{account_id}:content/{knowledge_base_id}/{resource_id}',
            'describe_method': 'get_content',
            'describe_param': 'contentId',
            'requires_knowledge_base': True
        },
        'QuickResponse': {
            'method': 'list_quick_responses',
            'key': 'quickResponseSummaries',
            'id_field': 'quickResponseId',
            'name_field': 'name',
            'date_field': 'createdTime',
            'nested': False,
            'arn_format': 'arn:aws:wisdom:{region}:{account_id}:quick-response/{knowledge_base_id}/{resource_id}',
            'describe_method': 'get_quick_response',
            'describe_param': 'quickResponseId',
            'requires_knowledge_base': True
        },
        'AssistantAssociation': {
            'method': 'list_assistant_associations',
            'key': 'assistantAssociationSummaries',
            'id_field': 'assistantAssociationId',
            'name_field': 'assistantAssociationId',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:wisdom:{region}:{account_id}:association/{assistant_id}/{resource_id}',
            'describe_method': 'get_assistant_association',
            'describe_param': 'assistantAssociationId',
            'requires_assistant': True
        },
        'Session': {
            'method': 'search_sessions',
            'key': 'sessionSummaries',
            'id_field': 'sessionId',
            'name_field': 'sessionId',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:wisdom:{region}:{account_id}:session/{assistant_id}/{resource_id}',
            'describe_method': 'get_session',
            'describe_param': 'sessionId',
            'requires_assistant': True,
            'search_based': True
        },
        'ImportJob': {
            'method': 'list_import_jobs',
            'key': 'importJobSummaries',
            'id_field': 'importJobId',
            'name_field': 'importJobId',
            'date_field': 'createdTime',
            'nested': False,
            'arn_format': 'arn:aws:wisdom:{region}:{account_id}:import-job/{knowledge_base_id}/{resource_id}',
            'describe_method': 'get_import_job',
            'describe_param': 'importJobId',
            'requires_knowledge_base': True
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
            client = session.client('wisdom', region_name=region, config=client_config)
        except Exception as e:
            logger.warning(f"Connect Wisdom client creation failed in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        
        if not hasattr(client, config['method']):
            logger.warning(f"Method {config['method']} not available for wisdom client")
            return f'{service}:{service_type}', "success", "", []

        method = getattr(client, config['method'])
        params = {}
        
        # Special handling for resources that require knowledge base IDs
        if config.get('requires_knowledge_base', False):
            # First get list of knowledge bases
            try:
                def get_knowledge_bases():
                    return client.list_knowledge_bases()
                
                kb_response = retry_with_backoff(get_knowledge_bases, max_retries=3)
                if not kb_response:
                    logger.warning(f"Failed to get knowledge bases for {service_type}")
                    return f'{service}:{service_type}', "success", "", []
                    
                kb_ids = [kb['knowledgeBaseId'] for kb in kb_response.get('knowledgeBaseSummaries', [])]
                if not kb_ids:
                    logger.info(f"No Connect Wisdom knowledge bases found for {service_type} discovery")
                    return f'{service}:{service_type}', "success", "", []
                
                # Get resources for each knowledge base
                all_items = []
                for kb_id in kb_ids:
                    try:
                        def get_kb_resources():
                            kb_params = {'knowledgeBaseId': kb_id}
                            response = method(**kb_params)
                            items = response.get(config['key'], [])
                            
                            # Add knowledge_base_id to each item for ARN construction
                            for item in items:
                                item['_knowledge_base_id'] = kb_id
                            return items
                        
                        kb_items = retry_with_backoff(get_kb_resources, max_retries=3)
                        if kb_items is not None:
                            all_items.extend(kb_items)
                        else:
                            logger.warning(f"Failed to get {service_type} for knowledge base {kb_id}")
                            
                    except Exception as kb_error:
                        logger.warning(f"Error getting {service_type} for knowledge base {kb_id}: {kb_error}")
                        continue
                        
                page_iterator = [{config['key']: all_items}]
                
            except Exception as kb_error:
                logger.warning(f"Error listing knowledge bases for {service_type}: {kb_error}")
                return f'{service}:{service_type}', "success", "", []
                
        # Special handling for resources that require assistant IDs
        elif config.get('requires_assistant', False):
            # First get list of assistants
            try:
                def get_assistants():
                    return client.list_assistants()
                
                assistant_response = retry_with_backoff(get_assistants, max_retries=3)
                if not assistant_response:
                    logger.warning(f"Failed to get assistants for {service_type}")
                    return f'{service}:{service_type}', "success", "", []
                    
                assistant_ids = [assistant['assistantId'] for assistant in assistant_response.get('assistantSummaries', [])]
                if not assistant_ids:
                    logger.info(f"No Connect Wisdom assistants found for {service_type} discovery")
                    return f'{service}:{service_type}', "success", "", []
                
                # Get resources for each assistant
                all_items = []
                for assistant_id in assistant_ids:
                    try:
                        def get_assistant_resources():
                            assistant_params = {'assistantId': assistant_id}
                            
                            # Special handling for Session search
                            if config.get('search_based', False):
                                assistant_params['searchExpression'] = {'filters': []}
                                
                            response = method(**assistant_params)
                            items = response.get(config['key'], [])
                            
                            # Add assistant_id to each item for ARN construction
                            for item in items:
                                item['_assistant_id'] = assistant_id
                            return items
                        
                        assistant_items = retry_with_backoff(get_assistant_resources, max_retries=3)
                        if assistant_items is not None:
                            all_items.extend(assistant_items)
                        else:
                            logger.warning(f"Failed to get {service_type} for assistant {assistant_id}")
                            
                    except Exception as assistant_error:
                        logger.warning(f"Error getting {service_type} for assistant {assistant_id}: {assistant_error}")
                        continue
                        
                page_iterator = [{config['key']: all_items}]
                
            except Exception as assistant_error:
                logger.warning(f"Error listing assistants for {service_type}: {assistant_error}")
                return f'{service}:{service_type}', "success", "", []
        else:
            # Handle Connect Wisdom API calls with proper error handling and retry logic
            try:
                logger.info(f"Calling Connect Wisdom {config['method']} in region {region}")
                
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
                logger.warning(f"Connect Wisdom timeout in region {region}: {str(e)}")
                return f'{service}:{service_type}', "success", "", []
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                if error_code in ['UnauthorizedOperation', 'AccessDenied', 'InvalidAction']:
                    logger.warning(f"Connect Wisdom not available in region {region}: {error_code}")
                    return f'{service}:{service_type}', "success", "", []
                elif error_code in ['ResourceNotFoundException', 'InvalidParameterException']:
                    logger.info(f"Connect Wisdom {service_type} not found in region {region}")
                    return f'{service}:{service_type}', "success", "", []
                else:
                    logger.error(f"Connect Wisdom API error in region {region}: {str(e)}")
                    return f'{service}:{service_type}', "error", str(e), []
            except Exception as e:
                logger.warning(f"Connect Wisdom general error in region {region}: {str(e)}")
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
                    if config.get('requires_knowledge_base', False):
                        kb_id = item.get('_knowledge_base_id', '')
                        arn = config['arn_format'].format(
                            region=region,
                            account_id=account_id,
                            knowledge_base_id=kb_id,
                            resource_id=resource_id
                        )
                    elif config.get('requires_assistant', False):
                        assistant_id = item.get('_assistant_id', '')
                        arn = config['arn_format'].format(
                            region=region,
                            account_id=account_id,
                            assistant_id=assistant_id,
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
                            return client.list_tags_for_resource(resourceArn=arn)
                        
                        tags_response = retry_with_backoff(get_tags, max_retries=3)
                        if tags_response:
                            # Connect Wisdom returns tags as a dictionary
                            resource_tags = tags_response.get('tags', {})
                        else:
                            logger.warning(f"Failed to get tags for Connect Wisdom resource {resource_name}")
                            resource_tags = {}
                            
                    except (ConnectTimeoutError, ReadTimeoutError):
                        logger.warning(f"Timeout retrieving tags for Connect Wisdom resource {resource_name}")
                        resource_tags = {}
                    except ClientError as tag_error:
                        tag_error_code = tag_error.response.get('Error', {}).get('Code', 'Unknown')
                        if tag_error_code in ['ResourceNotFoundException', 'AccessDenied']:
                            logger.info(f"No tags found for Connect Wisdom resource {resource_name}")
                            resource_tags = {}
                        else:
                            logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                            resource_tags = {}
                    except Exception as tag_error:
                        logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                        resource_tags = {}

                    # Get additional metadata based on resource type
                    additional_metadata = {}
                    if service_type == 'Assistant':
                        additional_metadata = {
                            'assistantArn': item.get('assistantArn', ''),
                            'type': item.get('type', ''),
                            'status': item.get('status', ''),
                            'description': item.get('description', ''),
                            'tags': item.get('tags', {})
                        }
                    elif service_type == 'KnowledgeBase':
                        additional_metadata = {
                            'knowledgeBaseArn': item.get('knowledgeBaseArn', ''),
                            'knowledgeBaseType': item.get('knowledgeBaseType', ''),
                            'status': item.get('status', ''),
                            'description': item.get('description', ''),
                            'tags': item.get('tags', {})
                        }
                    elif service_type == 'Content':
                        additional_metadata = {
                            'contentArn': item.get('contentArn', ''),
                            'contentType': item.get('contentType', ''),
                            'status': item.get('status', ''),
                            'title': item.get('title', ''),
                            'tags': item.get('tags', {})
                        }
                    elif service_type == 'QuickResponse':
                        additional_metadata = {
                            'quickResponseArn': item.get('quickResponseArn', ''),
                            'contentType': item.get('contentType', ''),
                            'status': item.get('status', ''),
                            'description': item.get('description', ''),
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
                    logger.warning(f"Error processing Connect Wisdom item: {str(item_error)}")
                    continue

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} {service_type.lower()}s')

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in Connect Wisdom discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources


def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    # Create Connect Wisdom client with timeout protection
    session = boto3.Session()
    client_config = Config(
        read_timeout=15,
        connect_timeout=10,
        retries={'max_attempts': 3, 'mode': 'standard'}
    )
    
    try:
        wisdom_client = session.client('wisdom', region_name=region, config=client_config)
    except Exception as e:
        logger.error(f"Failed to create Connect Wisdom client: {str(e)}")
        return []

    for resource in resources:
        try:
            def tag_resource():
                if tags_action == 1:  # Add tags
                    # Convert tags to dictionary format for Connect Wisdom
                    tags_dict = {tag['Key']: tag['Value'] for tag in tags}
                    wisdom_client.tag_resource(
                        resourceArn=resource.arn,
                        tags=tags_dict
                    )
                elif tags_action == 2:  # Remove tags
                    wisdom_client.untag_resource(
                        resourceArn=resource.arn,
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

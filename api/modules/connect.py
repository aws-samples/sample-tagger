import json
import boto3
import time
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError, ClientError, ConnectTimeoutError, ReadTimeoutError
from botocore.config import Config

def get_service_types(account_id, region, service, service_type):
    """
    Amazon Connect resources that support tagging.
    
    Based on AWS Connect documentation:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/connect.html
    
    Connect supports tagging for:
    - Instance (Connect instances/contact centers)
    - ContactFlow (Contact flows for call routing)
    - ContactFlowModule (Reusable contact flow modules)
    - Queue (Contact queues for routing)
    - QuickConnect (Quick connect configurations)
    - RoutingProfile (Agent routing profiles)
    - SecurityProfile (Security profiles for permissions)
    - User (Connect users/agents)
    - UserHierarchyGroup (User hierarchy groups)
    - HoursOfOperation (Hours of operation configurations)
    - Prompt (Audio prompts)
    - EvaluationForm (Contact evaluation forms)
    - TaskTemplate (Task templates)
    - TrafficDistributionGroup (Traffic distribution groups)
    - PhoneNumber (Phone numbers)
    - Vocabulary (Custom vocabularies for transcription)
    - IntegrationAssociation (Third-party integrations)
    - UseCase (Use case configurations)
    """

    resource_configs = {
        'Instance': {
            'method': 'list_instances',
            'key': 'InstanceSummaryList',
            'id_field': 'Id',
            'name_field': 'InstanceAlias',
            'date_field': 'CreatedTime',
            'nested': False,
            'arn_format': 'arn:aws:connect:{region}:{account_id}:instance/{resource_id}',
            'describe_method': 'describe_instance',
            'describe_param': 'InstanceId'
        },
        'ContactFlow': {
            'method': 'list_contact_flows',
            'key': 'ContactFlowSummaryList',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:connect:{region}:{account_id}:instance/{instance_id}/contact-flow/{resource_id}',
            'describe_method': 'describe_contact_flow',
            'describe_param': 'ContactFlowId',
            'requires_instance': True
        },
        'ContactFlowModule': {
            'method': 'list_contact_flow_modules',
            'key': 'ContactFlowModulesSummaryList',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:connect:{region}:{account_id}:instance/{instance_id}/contact-flow-module/{resource_id}',
            'describe_method': 'describe_contact_flow_module',
            'describe_param': 'ContactFlowModuleId',
            'requires_instance': True
        },
        'Queue': {
            'method': 'list_queues',
            'key': 'QueueSummaryList',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:connect:{region}:{account_id}:instance/{instance_id}/queue/{resource_id}',
            'describe_method': 'describe_queue',
            'describe_param': 'QueueId',
            'requires_instance': True
        },
        'QuickConnect': {
            'method': 'list_quick_connects',
            'key': 'QuickConnectSummaryList',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:connect:{region}:{account_id}:instance/{instance_id}/transfer-destination/{resource_id}',
            'describe_method': 'describe_quick_connect',
            'describe_param': 'QuickConnectId',
            'requires_instance': True
        },
        'RoutingProfile': {
            'method': 'list_routing_profiles',
            'key': 'RoutingProfileSummaryList',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:connect:{region}:{account_id}:instance/{instance_id}/routing-profile/{resource_id}',
            'describe_method': 'describe_routing_profile',
            'describe_param': 'RoutingProfileId',
            'requires_instance': True
        },
        'SecurityProfile': {
            'method': 'list_security_profiles',
            'key': 'SecurityProfileSummaryList',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:connect:{region}:{account_id}:instance/{instance_id}/security-profile/{resource_id}',
            'describe_method': 'describe_security_profile',
            'describe_param': 'SecurityProfileId',
            'requires_instance': True
        },
        'User': {
            'method': 'list_users',
            'key': 'UserSummaryList',
            'id_field': 'Id',
            'name_field': 'Username',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:connect:{region}:{account_id}:instance/{instance_id}/agent/{resource_id}',
            'describe_method': 'describe_user',
            'describe_param': 'UserId',
            'requires_instance': True
        },
        'UserHierarchyGroup': {
            'method': 'list_user_hierarchy_groups',
            'key': 'UserHierarchyGroupSummaryList',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:connect:{region}:{account_id}:instance/{instance_id}/agent-group/{resource_id}',
            'describe_method': 'describe_user_hierarchy_group',
            'describe_param': 'HierarchyGroupId',
            'requires_instance': True
        },
        'HoursOfOperation': {
            'method': 'list_hours_of_operations',
            'key': 'HoursOfOperationSummaryList',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:connect:{region}:{account_id}:instance/{instance_id}/operating-hours/{resource_id}',
            'describe_method': 'describe_hours_of_operation',
            'describe_param': 'HoursOfOperationId',
            'requires_instance': True
        },
        'Prompt': {
            'method': 'list_prompts',
            'key': 'PromptSummaryList',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:connect:{region}:{account_id}:instance/{instance_id}/prompt/{resource_id}',
            'describe_method': 'describe_prompt',
            'describe_param': 'PromptId',
            'requires_instance': True
        },
        'EvaluationForm': {
            'method': 'list_evaluation_forms',
            'key': 'EvaluationFormSummaryList',
            'id_field': 'EvaluationFormId',
            'name_field': 'Title',
            'date_field': 'CreatedTime',
            'nested': False,
            'arn_format': 'arn:aws:connect:{region}:{account_id}:instance/{instance_id}/evaluation-form/{resource_id}',
            'describe_method': 'describe_evaluation_form',
            'describe_param': 'EvaluationFormId',
            'requires_instance': True
        },
        'TaskTemplate': {
            'method': 'list_task_templates',
            'key': 'TaskTemplates',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': 'CreatedTime',
            'nested': False,
            'arn_format': 'arn:aws:connect:{region}:{account_id}:instance/{instance_id}/task/template/{resource_id}',
            'describe_method': 'get_task_template',
            'describe_param': 'TaskTemplateId',
            'requires_instance': True
        },
        'TrafficDistributionGroup': {
            'method': 'list_traffic_distribution_groups',
            'key': 'TrafficDistributionGroupSummaryList',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:connect:{region}:{account_id}:traffic-distribution-group/{resource_id}',
            'describe_method': 'describe_traffic_distribution_group',
            'describe_param': 'TrafficDistributionGroupId'
        },
        'PhoneNumber': {
            'method': 'list_phone_numbers_v2',
            'key': 'ListPhoneNumbersSummaryList',
            'id_field': 'PhoneNumberId',
            'name_field': 'PhoneNumber',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:connect:{region}:{account_id}:phone-number/{resource_id}',
            'describe_method': 'describe_phone_number',
            'describe_param': 'PhoneNumberId'
        },
        'Vocabulary': {
            'method': 'list_default_vocabularies',
            'key': 'DefaultVocabularyList',
            'id_field': 'VocabularyId',
            'name_field': 'VocabularyName',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:connect:{region}:{account_id}:instance/{instance_id}/vocabulary/{resource_id}',
            'requires_instance': True
        },
        'IntegrationAssociation': {
            'method': 'list_integration_associations',
            'key': 'IntegrationAssociationSummaryList',
            'id_field': 'IntegrationAssociationId',
            'name_field': 'IntegrationAssociationId',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:connect:{region}:{account_id}:instance/{instance_id}/integration-association/{resource_id}',
            'requires_instance': True
        },
        'UseCase': {
            'method': 'list_use_cases',
            'key': 'UseCaseSummaryList',
            'id_field': 'UseCaseId',
            'name_field': 'UseCaseType',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:connect:{region}:{account_id}:instance/{instance_id}/use-case/{resource_id}',
            'requires_instance': True,
            'requires_integration': True
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
        
        # Configure client with more aggressive retry settings for Connect
        client_config = Config(
            read_timeout=30,
            connect_timeout=15,
            retries={
                'max_attempts': 5,
                'mode': 'adaptive',
                'total_max_attempts': 10
            }
        )
        
        try:
            client = session.client('connect', region_name=region, config=client_config)
        except Exception as e:
            logger.warning(f"Connect client creation failed in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        
        if not hasattr(client, config['method']):
            logger.warning(f"Method {config['method']} not available for connect client")
            return f'{service}:{service_type}', "success", "", []

        method = getattr(client, config['method'])
        params = {}
        
        # Special handling for resources that require instance IDs
        if config.get('requires_instance', False):
            # First get list of instances with retry logic
            try:
                def get_instances():
                    return client.list_instances()
                
                instances_response = retry_with_backoff(get_instances, max_retries=5)
                if instances_response is None:
                    logger.warning(f"Failed to get instances after retries for {service_type}")
                    return f'{service}:{service_type}', "success", "", []
                    
                instance_ids = [instance['Id'] for instance in instances_response.get('InstanceSummaryList', [])]
                if not instance_ids:
                    logger.info(f"No Connect instances found for {service_type} discovery")
                    return f'{service}:{service_type}', "success", "", []
                
                # Get resources for each instance with retry logic
                all_items = []
                for instance_id in instance_ids:
                    try:
                        def get_instance_resources():
                            instance_params = {'InstanceId': instance_id}
                            
                            # Special handling for UseCase which also requires integration association
                            if config.get('requires_integration', False):
                                # Get integration associations for this instance first
                                integrations_response = client.list_integration_associations(InstanceId=instance_id)
                                integration_ids = [integration['IntegrationAssociationId'] 
                                                 for integration in integrations_response.get('IntegrationAssociationSummaryList', [])]
                                
                                instance_items = []
                                for integration_id in integration_ids:
                                    try:
                                        integration_params = {'InstanceId': instance_id, 'IntegrationAssociationId': integration_id}
                                        response = method(**integration_params)
                                        items = response.get(config['key'], [])
                                        # Add instance_id to each item for ARN construction
                                        for item in items:
                                            item['_instance_id'] = instance_id
                                        instance_items.extend(items)
                                    except Exception as integration_error:
                                        logger.warning(f"Error getting use cases for integration {integration_id}: {integration_error}")
                                        continue
                                return instance_items
                            else:
                                response = method(**instance_params)
                                items = response.get(config['key'], [])
                                # Add instance_id to each item for ARN construction
                                for item in items:
                                    item['_instance_id'] = instance_id
                                return items
                        
                        instance_items = retry_with_backoff(get_instance_resources, max_retries=3)
                        if instance_items is not None:
                            all_items.extend(instance_items)
                        else:
                            logger.warning(f"Failed to get {service_type} for instance {instance_id} after retries")
                            
                    except Exception as instance_error:
                        logger.warning(f"Error getting {service_type} for instance {instance_id}: {instance_error}")
                        continue
                        
                page_iterator = [{config['key']: all_items}]
                
            except Exception as instance_error:
                logger.warning(f"Error listing instances for {service_type}: {instance_error}")
                return f'{service}:{service_type}', "success", "", []
        else:
            # Handle Connect API calls with proper error handling and retry logic
            try:
                logger.info(f"Calling Connect {config['method']} in region {region}")
                
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
                logger.warning(f"Connect timeout in region {region}: {str(e)}")
                return f'{service}:{service_type}', "success", "", []
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                if error_code in ['UnauthorizedOperation', 'AccessDenied', 'InvalidAction']:
                    logger.warning(f"Connect not available in region {region}: {error_code}")
                    return f'{service}:{service_type}', "success", "", []
                elif error_code in ['TooManyRequestsException', 'Throttling', 'ThrottlingException']:
                    logger.warning(f"Connect rate limited in region {region}, but handled with retries")
                    return f'{service}:{service_type}', "success", "", []
                else:
                    logger.error(f"Connect API error in region {region}: {str(e)}")
                    return f'{service}:{service_type}', "error", str(e), []
            except Exception as e:
                logger.warning(f"Connect general error in region {region}: {str(e)}")
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
                    if config.get('requires_instance', False):
                        instance_id = item.get('_instance_id', '')
                        arn = config['arn_format'].format(
                            region=region,
                            account_id=account_id,
                            instance_id=instance_id,
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
                        if tags_response is not None:
                            tags_dict = tags_response.get('tags', {})
                            resource_tags = tags_dict
                        else:
                            logger.warning(f"Failed to get tags for Connect resource {resource_name} after retries")
                            
                    except (ConnectTimeoutError, ReadTimeoutError):
                        logger.warning(f"Timeout retrieving tags for Connect resource {resource_name}")
                        resource_tags = {}
                    except Exception as tag_error:
                        logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                        resource_tags = {}

                    # Get additional metadata based on resource type
                    additional_metadata = {}
                    if service_type == 'Instance':
                        additional_metadata = {
                            'ServiceRole': item.get('ServiceRole', ''),
                            'Status': item.get('InstanceStatus', ''),
                            'StatusReason': item.get('StatusReason', ''),
                            'InboundCallsEnabled': item.get('InboundCallsEnabled', False),
                            'OutboundCallsEnabled': item.get('OutboundCallsEnabled', False),
                            'InstanceAccessUrl': item.get('InstanceAccessUrl', '')
                        }
                    elif service_type == 'ContactFlow':
                        additional_metadata = {
                            'ContactFlowType': item.get('ContactFlowType', ''),
                            'ContactFlowState': item.get('ContactFlowState', ''),
                            'Description': item.get('Description', '')
                        }
                    elif service_type == 'Queue':
                        additional_metadata = {
                            'QueueType': item.get('QueueType', ''),
                            'Description': item.get('Description', '')
                        }
                    elif service_type == 'User':
                        additional_metadata = {
                            'Username': item.get('Username', ''),
                            'RoutingProfileId': item.get('RoutingProfileId', ''),
                            'HierarchyGroupId': item.get('HierarchyGroupId', ''),
                            'SecurityProfileIds': item.get('SecurityProfileIds', [])
                        }

                    # Combine original item with additional metadata
                    metadata = {**item, **additional_metadata}
                    # Remove internal fields
                    metadata.pop('_instance_id', None)

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
                    logger.warning(f"Error processing Connect item: {str(item_error)}")
                    continue

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} {service_type.lower()}s')

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in Connect discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources


def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    if tags_action == 2:        
        tag_keys = list(tags.keys()) if isinstance(tags, dict) else [tag['Key'] for tag in tags]

    # Create Connect client with timeout protection
    session = boto3.Session()
    client_config = Config(
        read_timeout=30,
        connect_timeout=15,
        retries={
            'max_attempts': 5,
            'mode': 'adaptive',
            'total_max_attempts': 10
        }
    )
    
    try:
        connect_client = session.client('connect', region_name=region, config=client_config)
    except Exception as e:
        logger.error(f"Failed to create Connect client: {str(e)}")
        return []

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Connect uses dictionary format
                if isinstance(tags, list):
                    connect_tags = {tag['Key']: tag['Value'] for tag in tags}
                else:
                    connect_tags = tags
                
                def tag_resource():
                    return connect_client.tag_resource(
                        resourceArn=resource.arn,
                        tags=connect_tags
                    )
                
                retry_with_backoff(tag_resource, max_retries=3)
                        
            elif tags_action == 2:
                # Remove tags
                def untag_resource():
                    return connect_client.untag_resource(
                        resourceArn=resource.arn,
                        tagKeys=tag_keys
                    )
                
                retry_with_backoff(untag_resource, max_retries=3)
                    
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

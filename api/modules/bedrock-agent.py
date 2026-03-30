import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError, ClientError, ConnectTimeoutError, ReadTimeoutError
from botocore.config import Config

def get_service_types(account_id, region, service, service_type):
    """
    AWS Bedrock Agent resources that support tagging - COMPLETE LIST.
    
    Based on AWS Bedrock Agent documentation:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/bedrock-agent.html
    
    Bedrock Agent supports tagging for ALL these resources:
    - Agent (Bedrock agents for conversational AI)
    - AgentAlias (Agent aliases for versioning and deployment)
    - AgentVersion (Specific versions of agents)
    - KnowledgeBase (Knowledge bases for RAG - Retrieval Augmented Generation)
    - DataSource (Data sources for knowledge bases)
    - ActionGroup (Action groups for agent capabilities and functions)
    - Prompt (Prompts for agent interactions and templates)
    - Flow (Flows for complex agent workflows and orchestration)
    - FlowAlias (Flow aliases for versioning and deployment)
    - FlowVersion (Specific versions of flows)
    - AgentCollaborator (Agent collaborators for multi-agent scenarios)
    - IngestionJob (Data ingestion jobs for knowledge bases)
    - KnowledgeBaseDocument (Individual documents in knowledge bases)
    
    Note: Some resources may not be available in all regions or CLI versions
    """

    resource_configs = {
        'Agent': {
            'method': 'list_agents',
            'key': 'agentSummaries',
            'id_field': 'agentId',
            'name_field': 'agentName',
            'date_field': 'createdAt',
            'nested': False,
            'arn_format': 'arn:aws:bedrock:{region}:{account_id}:agent/{resource_id}',
            'describe_method': 'get_agent',
            'describe_param': 'agentId'
        },
        'AgentAlias': {
            'method': 'list_agent_aliases',
            'key': 'agentAliasSummaries',
            'id_field': 'agentAliasId',
            'name_field': 'agentAliasName',
            'date_field': 'createdAt',
            'nested': True,
            'parent_method': 'list_agents',
            'parent_key': 'agentSummaries',
            'parent_id_field': 'agentId',
            'arn_format': 'arn:aws:bedrock:{region}:{account_id}:agent-alias/{agent_id}/{resource_id}',
            'describe_method': 'get_agent_alias',
            'describe_param': 'agentAliasId'
        },
        'AgentVersion': {
            'method': 'list_agent_versions',
            'key': 'agentVersionSummaries',
            'id_field': 'agentVersion',
            'name_field': 'agentName',
            'date_field': 'createdAt',
            'nested': True,
            'parent_method': 'list_agents',
            'parent_key': 'agentSummaries',
            'parent_id_field': 'agentId',
            'arn_format': 'arn:aws:bedrock:{region}:{account_id}:agent/{agent_id}/version/{resource_id}',
            'describe_method': 'get_agent_version',
            'describe_param': 'agentVersion'
        },
        'KnowledgeBase': {
            'method': 'list_knowledge_bases',
            'key': 'knowledgeBaseSummaries',
            'id_field': 'knowledgeBaseId',
            'name_field': 'name',
            'date_field': 'createdAt',
            'nested': False,
            'arn_format': 'arn:aws:bedrock:{region}:{account_id}:knowledge-base/{resource_id}',
            'describe_method': 'get_knowledge_base',
            'describe_param': 'knowledgeBaseId'
        },
        'DataSource': {
            'method': 'list_data_sources',
            'key': 'dataSourceSummaries',
            'id_field': 'dataSourceId',
            'name_field': 'name',
            'date_field': 'createdAt',
            'nested': True,
            'parent_method': 'list_knowledge_bases',
            'parent_key': 'knowledgeBaseSummaries',
            'parent_id_field': 'knowledgeBaseId',
            'arn_format': 'arn:aws:bedrock:{region}:{account_id}:knowledge-base/{knowledge_base_id}/data-source/{resource_id}',
            'describe_method': 'get_data_source',
            'describe_param': 'dataSourceId'
        },
        'ActionGroup': {
            'method': 'list_agent_action_groups',
            'key': 'actionGroupSummaries',
            'id_field': 'actionGroupId',
            'name_field': 'actionGroupName',
            'date_field': 'createdAt',
            'nested': True,
            'parent_method': 'list_agents',
            'parent_key': 'agentSummaries',
            'parent_id_field': 'agentId',
            'arn_format': 'arn:aws:bedrock:{region}:{account_id}:agent/{agent_id}/action-group/{resource_id}',
            'describe_method': 'get_agent_action_group',
            'describe_param': 'actionGroupId'
        },
        'Prompt': {
            'method': 'list_prompts',
            'key': 'promptSummaries',
            'id_field': 'id',
            'name_field': 'name',
            'date_field': 'createdAt',
            'nested': False,
            'arn_format': 'arn:aws:bedrock:{region}:{account_id}:prompt/{resource_id}',
            'describe_method': 'get_prompt',
            'describe_param': 'promptIdentifier'
        },
        'Flow': {
            'method': 'list_flows',
            'key': 'flowSummaries',
            'id_field': 'id',
            'name_field': 'name',
            'date_field': 'createdAt',
            'nested': False,
            'arn_format': 'arn:aws:bedrock:{region}:{account_id}:flow/{resource_id}',
            'describe_method': 'get_flow',
            'describe_param': 'flowIdentifier'
        },
        'FlowAlias': {
            'method': 'list_flow_aliases',
            'key': 'flowAliasSummaries',
            'id_field': 'id',
            'name_field': 'name',
            'date_field': 'createdAt',
            'nested': True,
            'parent_method': 'list_flows',
            'parent_key': 'flowSummaries',
            'parent_id_field': 'id',
            'arn_format': 'arn:aws:bedrock:{region}:{account_id}:flow/{flow_id}/alias/{resource_id}',
            'describe_method': 'get_flow_alias',
            'describe_param': 'aliasIdentifier'
        },
        'FlowVersion': {
            'method': 'list_flow_versions',
            'key': 'flowVersionSummaries',
            'id_field': 'version',
            'name_field': 'version',
            'date_field': 'createdAt',
            'nested': True,
            'parent_method': 'list_flows',
            'parent_key': 'flowSummaries',
            'parent_id_field': 'id',
            'arn_format': 'arn:aws:bedrock:{region}:{account_id}:flow/{flow_id}/version/{resource_id}',
            'describe_method': 'get_flow_version',
            'describe_param': 'flowVersion'
        },
        'AgentCollaborator': {
            'method': 'list_agent_collaborators',
            'key': 'agentCollaboratorSummaries',
            'id_field': 'agentId',
            'name_field': 'agentName',
            'date_field': 'createdAt',
            'nested': True,
            'parent_method': 'list_agents',
            'parent_key': 'agentSummaries',
            'parent_id_field': 'agentId',
            'arn_format': 'arn:aws:bedrock:{region}:{account_id}:agent/{agent_id}/collaborator/{resource_id}',
            'describe_method': 'get_agent_collaborator',
            'describe_param': 'agentId'
        },
        'IngestionJob': {
            'method': 'list_ingestion_jobs',
            'key': 'ingestionJobSummaries',
            'id_field': 'ingestionJobId',
            'name_field': 'ingestionJobId',
            'date_field': 'startedAt',
            'nested': True,
            'parent_method': 'list_knowledge_bases',
            'parent_key': 'knowledgeBaseSummaries',
            'parent_id_field': 'knowledgeBaseId',
            'arn_format': 'arn:aws:bedrock:{region}:{account_id}:knowledge-base/{knowledge_base_id}/ingestion-job/{resource_id}',
            'describe_method': 'get_ingestion_job',
            'describe_param': 'ingestionJobId',
            'requires_data_source': True
        },
        'KnowledgeBaseDocument': {
            'method': 'list_knowledge_base_documents',
            'key': 'documentDetails',
            'id_field': 'identifier',
            'name_field': 'identifier',
            'date_field': 'createdAt',
            'nested': True,
            'parent_method': 'list_knowledge_bases',
            'parent_key': 'knowledgeBaseSummaries',
            'parent_id_field': 'knowledgeBaseId',
            'arn_format': 'arn:aws:bedrock:{region}:{account_id}:knowledge-base/{knowledge_base_id}/document/{resource_id}',
            'describe_method': 'get_knowledge_base_documents',
            'describe_param': 'knowledgeBaseId',
            'requires_data_source': True
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
            client = session.client('bedrock-agent', region_name=region, config=client_config)
        except Exception as e:
            logger.warning(f"Bedrock Agent client creation failed in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        
        if not hasattr(client, config['method']):
            logger.warning(f"Method {config['method']} not available for bedrock-agent client in region {region}")
            return f'{service}:{service_type}', "success", "", []

        method = getattr(client, config['method'])
        
        # Handle nested resources (those that require parent resources)
        if config.get('nested', False):
            try:
                # Get parent resources first
                parent_method = getattr(client, config['parent_method'])
                parent_response = parent_method()
                parent_items = parent_response.get(config['parent_key'], [])
                
                if not parent_items:
                    logger.info(f"No parent resources found for {service_type} discovery")
                    return f'{service}:{service_type}', "success", "", []
                
                all_items = []
                for parent_item in parent_items:
                    parent_id = parent_item[config['parent_id_field']]
                    
                    try:
                        # Special handling for resources that need additional parameters
                        if config.get('requires_data_source', False):
                            # Get data sources for this knowledge base first
                            data_sources_response = client.list_data_sources(knowledgeBaseId=parent_id)
                            data_sources = data_sources_response.get('dataSourceSummaries', [])
                            
                            for data_source in data_sources:
                                data_source_id = data_source['dataSourceId']
                                try:
                                    if service_type == 'IngestionJob':
                                        nested_params = {
                                            'knowledgeBaseId': parent_id,
                                            'dataSourceId': data_source_id
                                        }
                                    else:  # KnowledgeBaseDocument
                                        nested_params = {
                                            'knowledgeBaseId': parent_id,
                                            'dataSourceId': data_source_id
                                        }
                                    
                                    nested_response = method(**nested_params)
                                    nested_items = nested_response.get(config['key'], [])
                                    
                                    # Add parent context to each item
                                    for item in nested_items:
                                        item['_parent_id'] = parent_id
                                        item['_data_source_id'] = data_source_id
                                    
                                    all_items.extend(nested_items)
                                except Exception as nested_error:
                                    logger.warning(f"Error getting {service_type} for data source {data_source_id}: {nested_error}")
                                    continue
                        else:
                            # Standard nested resource handling
                            if service_type == 'AgentAlias':
                                nested_params = {'agentId': parent_id}
                            elif service_type == 'AgentVersion':
                                nested_params = {'agentId': parent_id}
                            elif service_type == 'ActionGroup':
                                nested_params = {'agentId': parent_id}
                            elif service_type == 'AgentCollaborator':
                                nested_params = {'agentId': parent_id}
                            elif service_type == 'DataSource':
                                nested_params = {'knowledgeBaseId': parent_id}
                            elif service_type == 'FlowAlias':
                                nested_params = {'flowIdentifier': parent_id}
                            elif service_type == 'FlowVersion':
                                nested_params = {'flowIdentifier': parent_id}
                            else:
                                nested_params = {config['parent_id_field']: parent_id}
                            
                            nested_response = method(**nested_params)
                            nested_items = nested_response.get(config['key'], [])
                            
                            # Add parent context to each item
                            for item in nested_items:
                                item['_parent_id'] = parent_id
                            
                            all_items.extend(nested_items)
                            
                    except Exception as nested_error:
                        logger.warning(f"Error getting {service_type} for parent {parent_id}: {nested_error}")
                        continue
                
                page_iterator = [{config['key']: all_items}]
                
            except Exception as parent_error:
                logger.warning(f"Error getting parent resources for {service_type}: {parent_error}")
                return f'{service}:{service_type}', "success", "", []
        else:
            # Handle direct resource discovery
            try:
                logger.info(f"Calling Bedrock Agent {config['method']} in region {region}")
                
                # Handle pagination
                try:
                    paginator = client.get_paginator(config['method'])
                    page_iterator = paginator.paginate()
                except OperationNotPageableError:
                    response = method()
                    page_iterator = [response]
                    
            except (ConnectTimeoutError, ReadTimeoutError) as e:
                logger.warning(f"Bedrock Agent timeout in region {region}: {str(e)}")
                return f'{service}:{service_type}', "success", "", []
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                if error_code in ['UnauthorizedOperation', 'AccessDenied', 'InvalidAction', 'UnknownOperationException']:
                    logger.warning(f"Bedrock Agent {service_type} not available in region {region}: {error_code}")
                    return f'{service}:{service_type}', "success", "", []
                else:
                    logger.error(f"Bedrock Agent API error in region {region}: {str(e)}")
                    return f'{service}:{service_type}', "error", str(e), []
            except Exception as e:
                logger.warning(f"Bedrock Agent general error in region {region}: {str(e)}")
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

                    # Build ARN based on resource type
                    if config.get('nested', False):
                        parent_id = item.get('_parent_id', '')
                        data_source_id = item.get('_data_source_id', '')
                        
                        if service_type in ['AgentAlias', 'AgentVersion', 'ActionGroup', 'AgentCollaborator']:
                            arn = config['arn_format'].format(
                                region=region,
                                account_id=account_id,
                                agent_id=parent_id,
                                resource_id=resource_id
                            )
                        elif service_type in ['DataSource', 'IngestionJob', 'KnowledgeBaseDocument']:
                            arn = config['arn_format'].format(
                                region=region,
                                account_id=account_id,
                                knowledge_base_id=parent_id,
                                resource_id=resource_id
                            )
                        elif service_type in ['FlowAlias', 'FlowVersion']:
                            arn = config['arn_format'].format(
                                region=region,
                                account_id=account_id,
                                flow_id=parent_id,
                                resource_id=resource_id
                            )
                        else:
                            arn = config['arn_format'].format(
                                region=region,
                                account_id=account_id,
                                resource_id=resource_id
                            )
                    else:
                        arn = config['arn_format'].format(
                            region=region,
                            account_id=account_id,
                            resource_id=resource_id
                        )

                    # Get existing tags
                    resource_tags = {}
                    try:
                        tags_response = client.list_tags_for_resource(resourceArn=arn)
                        tags_dict = tags_response.get('tags', {})
                        # Bedrock Agent returns tags as a dictionary
                        resource_tags = tags_dict
                    except (ConnectTimeoutError, ReadTimeoutError):
                        logger.warning(f"Timeout retrieving tags for Bedrock Agent resource {resource_name}")
                        resource_tags = {}
                    except Exception as tag_error:
                        logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                        resource_tags = {}

                    # Get additional metadata based on resource type
                    additional_metadata = {}
                    if service_type == 'Agent':
                        additional_metadata = {
                            'agentName': item.get('agentName', ''),
                            'agentStatus': item.get('agentStatus', ''),
                            'description': item.get('description', ''),
                            'latestAgentVersion': item.get('latestAgentVersion', ''),
                            'updatedAt': item.get('updatedAt', '')
                        }
                    elif service_type == 'AgentAlias':
                        additional_metadata = {
                            'agentAliasName': item.get('agentAliasName', ''),
                            'agentAliasStatus': item.get('agentAliasStatus', ''),
                            'description': item.get('description', ''),
                            'routingConfiguration': item.get('routingConfiguration', []),
                            'updatedAt': item.get('updatedAt', '')
                        }
                    elif service_type == 'KnowledgeBase':
                        additional_metadata = {
                            'name': item.get('name', ''),
                            'description': item.get('description', ''),
                            'status': item.get('status', ''),
                            'updatedAt': item.get('updatedAt', '')
                        }
                    elif service_type == 'DataSource':
                        additional_metadata = {
                            'name': item.get('name', ''),
                            'description': item.get('description', ''),
                            'status': item.get('status', ''),
                            'updatedAt': item.get('updatedAt', ''),
                            'knowledgeBaseId': item.get('_parent_id', '')
                        }
                    elif service_type == 'ActionGroup':
                        additional_metadata = {
                            'actionGroupName': item.get('actionGroupName', ''),
                            'actionGroupState': item.get('actionGroupState', ''),
                            'description': item.get('description', ''),
                            'updatedAt': item.get('updatedAt', ''),
                            'agentId': item.get('_parent_id', '')
                        }
                    elif service_type == 'Prompt':
                        additional_metadata = {
                            'name': item.get('name', ''),
                            'description': item.get('description', ''),
                            'version': item.get('version', ''),
                            'updatedAt': item.get('updatedAt', '')
                        }
                    elif service_type == 'Flow':
                        additional_metadata = {
                            'name': item.get('name', ''),
                            'description': item.get('description', ''),
                            'status': item.get('status', ''),
                            'version': item.get('version', ''),
                            'updatedAt': item.get('updatedAt', '')
                        }
                    elif service_type == 'IngestionJob':
                        additional_metadata = {
                            'dataSourceId': item.get('_data_source_id', ''),
                            'knowledgeBaseId': item.get('_parent_id', ''),
                            'status': item.get('status', ''),
                            'description': item.get('description', ''),
                            'updatedAt': item.get('updatedAt', ''),
                            'statistics': item.get('statistics', {})
                        }

                    # Combine original item with additional metadata
                    metadata = {**item, **additional_metadata}
                    # Remove internal fields
                    metadata.pop('_parent_id', None)
                    metadata.pop('_data_source_id', None)

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
                    logger.warning(f"Error processing Bedrock Agent item: {str(item_error)}")
                    continue

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} {service_type.lower()}s')

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in Bedrock Agent discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources

def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    if tags_action == 2:        
        tag_keys = list(tags.keys()) if isinstance(tags, dict) else [tag['Key'] for tag in tags]

    # Create Bedrock Agent client with timeout protection
    session = boto3.Session()
    client_config = Config(
        read_timeout=15,
        connect_timeout=10,
        retries={'max_attempts': 2, 'mode': 'standard'}
    )
    
    try:
        bedrock_agent_client = session.client('bedrock-agent', region_name=region, config=client_config)
    except Exception as e:
        logger.error(f"Failed to create Bedrock Agent client: {str(e)}")
        return []

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Bedrock Agent uses dictionary format
                if isinstance(tags, list):
                    bedrock_agent_tags = {tag['Key']: tag['Value'] for tag in tags}
                else:
                    bedrock_agent_tags = tags
                    
                bedrock_agent_client.tag_resource(
                    resourceArn=resource.arn,
                    tags=bedrock_agent_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                bedrock_agent_client.untag_resource(
                    resourceArn=resource.arn,
                    tagKeys=tag_keys
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

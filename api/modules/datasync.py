import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError, ClientError, ConnectTimeoutError, ReadTimeoutError
from botocore.config import Config

def get_service_types(account_id, region, service, service_type):
    """
    AWS DataSync resources that support tagging.
    
    Based on AWS DataSync documentation:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/datasync.html
    
    DataSync supports tagging for:
    - Agent (DataSync agents for on-premises connectivity)
    - Task (Data transfer tasks)
    - Location (Data source and destination locations)
    - TaskExecution (Individual task execution runs)
    """

    resource_configs = {
        'Agent': {
            'method': 'list_agents',
            'key': 'Agents',
            'id_field': 'AgentArn',
            'name_field': 'Name',
            'date_field': None,
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'describe_method': 'describe_agent',
            'describe_param': 'AgentArn'
        },
        'Task': {
            'method': 'list_tasks',
            'key': 'Tasks',
            'id_field': 'TaskArn',
            'name_field': 'Name',
            'date_field': None,
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'describe_method': 'describe_task',
            'describe_param': 'TaskArn'
        },
        'Location': {
            'method': 'list_locations',
            'key': 'Locations',
            'id_field': 'LocationArn',
            'name_field': 'LocationUri',
            'date_field': None,
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'describe_method': None  # Multiple describe methods based on location type
        },
        'TaskExecution': {
            'method': 'list_task_executions',
            'key': 'TaskExecutions',
            'id_field': 'TaskExecutionArn',
            'name_field': 'TaskExecutionArn',
            'date_field': 'StartTime',
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'describe_method': 'describe_task_execution',
            'describe_param': 'TaskExecutionArn',
            'requires_task': True  # Requires task ARN parameter
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
            client = session.client('datasync', region_name=region, config=client_config)
        except Exception as e:
            logger.warning(f"DataSync client creation failed in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        
        if not hasattr(client, config['method']):
            logger.warning(f"Method {config['method']} not available for datasync client")
            return f'{service}:{service_type}', "success", "", []

        method = getattr(client, config['method'])
        params = {}
        
        # Special handling for TaskExecution which requires task ARNs
        if config.get('requires_task', False):
            # First get list of tasks
            try:
                tasks_response = client.list_tasks()
                task_arns = [task['TaskArn'] for task in tasks_response.get('Tasks', [])]
                if not task_arns:
                    logger.info(f"No tasks found for {service_type} discovery")
                    return f'{service}:{service_type}', "success", "", []
                
                # Get task executions for each task
                all_items = []
                for task_arn in task_arns:
                    try:
                        response = method(TaskArn=task_arn)
                        all_items.extend(response.get(config['key'], []))
                    except Exception as task_error:
                        logger.warning(f"Error getting task executions for task {task_arn}: {task_error}")
                        continue
                page_iterator = [{'TaskExecutions': all_items}]
            except Exception as task_error:
                logger.warning(f"Error listing tasks for {service_type}: {task_error}")
                return f'{service}:{service_type}', "success", "", []
        else:
            # Handle DataSync API calls with proper error handling
            try:
                logger.info(f"Calling DataSync {config['method']} in region {region}")
                
                # Handle pagination
                try:
                    paginator = client.get_paginator(config['method'])
                    page_iterator = paginator.paginate(**params)
                except OperationNotPageableError:
                    response = method(**params)
                    page_iterator = [response]
                    
            except (ConnectTimeoutError, ReadTimeoutError) as e:
                logger.warning(f"DataSync timeout in region {region}: {str(e)}")
                return f'{service}:{service_type}', "success", "", []
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                if error_code in ['UnauthorizedOperation', 'AccessDenied', 'InvalidAction']:
                    logger.warning(f"DataSync not available in region {region}: {error_code}")
                    return f'{service}:{service_type}', "success", "", []
                else:
                    logger.error(f"DataSync API error in region {region}: {str(e)}")
                    return f'{service}:{service_type}', "error", str(e), []
            except Exception as e:
                logger.warning(f"DataSync general error in region {region}: {str(e)}")
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

                    # ARN is provided directly in DataSync
                    arn = resource_id

                    # Get existing tags
                    resource_tags = {}
                    try:
                        tags_response = client.list_tags_for_resource(ResourceArn=arn)
                        tags_list = tags_response.get('Tags', [])
                        # Convert DataSync tag format to standard format
                        resource_tags = {tag.get('Key', ''): tag.get('Value', '') for tag in tags_list}
                    except (ConnectTimeoutError, ReadTimeoutError):
                        logger.warning(f"Timeout retrieving tags for DataSync resource {resource_name}")
                        resource_tags = {}
                    except Exception as tag_error:
                        logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                        resource_tags = {}

                    # Get additional metadata based on resource type
                    additional_metadata = {}
                    if service_type == 'Agent':
                        additional_metadata = {
                            'Name': item.get('Name', ''),
                            'Status': item.get('Status', ''),
                            'Platform': item.get('Platform', {}),
                            'EndpointType': item.get('EndpointType', ''),
                            'PrivateLinkConfig': item.get('PrivateLinkConfig', {}),
                            'CreationTime': item.get('CreationTime', ''),
                            'LastConnectionTime': item.get('LastConnectionTime', '')
                        }
                    elif service_type == 'Task':
                        additional_metadata = {
                            'Name': item.get('Name', ''),
                            'Status': item.get('Status', ''),
                            'SourceLocationArn': item.get('SourceLocationArn', ''),
                            'DestinationLocationArn': item.get('DestinationLocationArn', ''),
                            'CloudWatchLogGroupArn': item.get('CloudWatchLogGroupArn', ''),
                            'CurrentTaskExecutionArn': item.get('CurrentTaskExecutionArn', ''),
                            'ErrorCode': item.get('ErrorCode', ''),
                            'ErrorDetail': item.get('ErrorDetail', ''),
                            'CreationTime': item.get('CreationTime', ''),
                            'Schedule': item.get('Schedule', {}),
                            'Options': item.get('Options', {}),
                            'Excludes': item.get('Excludes', []),
                            'Includes': item.get('Includes', [])
                        }
                    elif service_type == 'Location':
                        additional_metadata = {
                            'LocationUri': item.get('LocationUri', ''),
                            'CreationTime': item.get('CreationTime', '')
                        }
                    elif service_type == 'TaskExecution':
                        additional_metadata = {
                            'TaskArn': item.get('TaskArn', ''),
                            'Status': item.get('Status', ''),
                            'StartTime': item.get('StartTime', ''),
                            'EstimatedFilesToTransfer': item.get('EstimatedFilesToTransfer', 0),
                            'EstimatedBytesToTransfer': item.get('EstimatedBytesToTransfer', 0),
                            'FilesTransferred': item.get('FilesTransferred', 0),
                            'BytesWritten': item.get('BytesWritten', 0),
                            'BytesTransferred': item.get('BytesTransferred', 0),
                            'Result': item.get('Result', {}),
                            'BytesCompressed': item.get('BytesCompressed', 0),
                            'EstimatedFilesToDelete': item.get('EstimatedFilesToDelete', 0),
                            'FilesDeleted': item.get('FilesDeleted', 0),
                            'FilesSkipped': item.get('FilesSkipped', 0),
                            'FilesVerified': item.get('FilesVerified', 0)
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
                    logger.warning(f"Error processing DataSync item: {str(item_error)}")
                    continue

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} {service_type.lower()}s')

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in DataSync discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources


def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    if tags_action == 2:        
        tag_keys = [item['Key'] for item in tags]

    # Create DataSync client with timeout protection
    session = boto3.Session()
    client_config = Config(
        read_timeout=15,
        connect_timeout=10,
        retries={'max_attempts': 2, 'mode': 'standard'}
    )
    
    try:
        datasync_client = session.client('datasync', region_name=region, config=client_config)
    except Exception as e:
        logger.error(f"Failed to create DataSync client: {str(e)}")
        return []

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to DataSync format (list of objects)
                datasync_tags = [{'Key': tag['Key'], 'Value': tag['Value']} for tag in tags]
                datasync_client.tag_resource(
                    ResourceArn=resource.arn,
                    Tags=datasync_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                datasync_client.untag_resource(
                    ResourceArn=resource.arn,
                    Keys=tag_keys
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

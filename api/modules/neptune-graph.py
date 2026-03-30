import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError, ClientError, ConnectTimeoutError, ReadTimeoutError
from botocore.config import Config

def get_service_types(account_id, region, service, service_type):
    """
    Amazon Neptune Analytics resources that support tagging.
    
    Based on AWS Neptune Analytics documentation:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/neptune-graph.html
    
    Neptune Analytics supports tagging for:
    - Graph (Neptune Analytics graphs for graph analytics workloads)
    - GraphSnapshot (Snapshots of Neptune Analytics graphs)
    - PrivateGraphEndpoint (Private endpoints for Neptune Analytics graphs)
    - ImportTask (Data import tasks for Neptune Analytics)
    - ExportTask (Data export tasks from Neptune Analytics)
    - Query (Query executions in Neptune Analytics)
    
    Neptune Analytics is a serverless graph analytics service that enables
    fast analytics on graph data using popular graph query languages.
    """

    resource_configs = {
        'Graph': {
            'method': 'list_graphs',
            'key': 'graphs',
            'id_field': 'id',
            'name_field': 'name',
            'date_field': 'createTime',
            'nested': False,
            'arn_format': 'arn:aws:neptune-graph:{region}:{account_id}:graph/{resource_id}',
            'describe_method': 'get_graph',
            'describe_param': 'graphIdentifier'
        },
        'GraphSnapshot': {
            'method': 'list_graph_snapshots',
            'key': 'graphSnapshots',
            'id_field': 'id',
            'name_field': 'name',
            'date_field': 'snapshotCreateTime',
            'nested': False,
            'arn_format': 'arn:aws:neptune-graph:{region}:{account_id}:snapshot/{resource_id}',
            'describe_method': 'get_graph_snapshot',
            'describe_param': 'snapshotIdentifier'
        },
        'PrivateGraphEndpoint': {
            'method': 'list_private_graph_endpoints',
            'key': 'privateGraphEndpoints',
            'id_field': 'privateGraphEndpointIdentifier',
            'name_field': 'privateGraphEndpointIdentifier',
            'date_field': 'createTime',
            'nested': False,
            'arn_format': 'arn:aws:neptune-graph:{region}:{account_id}:private-graph-endpoint/{resource_id}',
            'describe_method': 'get_private_graph_endpoint',
            'describe_param': 'privateGraphEndpointIdentifier',
            'requires_graph': True
        },
        'ImportTask': {
            'method': 'list_import_tasks',
            'key': 'tasks',
            'id_field': 'taskId',
            'name_field': 'taskId',
            'date_field': 'createTime',
            'nested': False,
            'arn_format': 'arn:aws:neptune-graph:{region}:{account_id}:import-task/{resource_id}',
            'describe_method': 'get_import_task',
            'describe_param': 'taskIdentifier'
        },
        'ExportTask': {
            'method': 'list_export_tasks',
            'key': 'tasks',
            'id_field': 'taskId',
            'name_field': 'taskId',
            'date_field': 'createTime',
            'nested': False,
            'arn_format': 'arn:aws:neptune-graph:{region}:{account_id}:export-task/{resource_id}',
            'describe_method': 'get_export_task',
            'describe_param': 'taskIdentifier'
        },
        'Query': {
            'method': 'list_queries',
            'key': 'queries',
            'id_field': 'id',
            'name_field': 'queryString',
            'date_field': 'createTime',
            'nested': False,
            'arn_format': 'arn:aws:neptune-graph:{region}:{account_id}:query/{resource_id}',
            'describe_method': 'get_query',
            'describe_param': 'queryId',
            'requires_graph': True
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
            client = session.client('neptune-graph', region_name=region, config=client_config)
        except Exception as e:
            logger.warning(f"Neptune Analytics client creation failed in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        
        if not hasattr(client, config['method']):
            logger.warning(f"Method {config['method']} not available for neptune-graph client")
            return f'{service}:{service_type}', "success", "", []

        method = getattr(client, config['method'])
        params = {}
        
        # Special handling for resources that require graph IDs
        if config.get('requires_graph', False):
            # First get list of graphs
            try:
                graphs_response = client.list_graphs()
                graph_ids = [graph['id'] for graph in graphs_response.get('graphs', [])]
                if not graph_ids:
                    logger.info(f"No graphs found for {service_type} discovery")
                    return f'{service}:{service_type}', "success", "", []
                
                # Get resources for each graph
                all_items = []
                for graph_id in graph_ids:
                    try:
                        graph_params = {'graphIdentifier': graph_id}
                        response = method(**graph_params)
                        all_items.extend(response.get(config['key'], []))
                    except Exception as graph_error:
                        logger.warning(f"Error getting {service_type} for graph {graph_id}: {graph_error}")
                        continue
                        
                page_iterator = [{config['key']: all_items}]
                
            except Exception as graph_error:
                logger.warning(f"Error listing graphs for {service_type}: {graph_error}")
                return f'{service}:{service_type}', "success", "", []
        else:
            # Handle Neptune Analytics API calls with proper error handling
            try:
                logger.info(f"Calling Neptune Analytics {config['method']} in region {region}")
                
                # Handle pagination
                try:
                    paginator = client.get_paginator(config['method'])
                    page_iterator = paginator.paginate(**params)
                except OperationNotPageableError:
                    response = method(**params)
                    page_iterator = [response]
                    
            except (ConnectTimeoutError, ReadTimeoutError) as e:
                logger.warning(f"Neptune Analytics timeout in region {region}: {str(e)}")
                return f'{service}:{service_type}', "success", "", []
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                if error_code in ['UnauthorizedOperation', 'AccessDenied', 'InvalidAction']:
                    logger.warning(f"Neptune Analytics not available in region {region}: {error_code}")
                    return f'{service}:{service_type}', "success", "", []
                else:
                    logger.error(f"Neptune Analytics API error in region {region}: {str(e)}")
                    return f'{service}:{service_type}', "error", str(e), []
            except Exception as e:
                logger.warning(f"Neptune Analytics general error in region {region}: {str(e)}")
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

                    # Get existing tags
                    resource_tags = {}
                    try:
                        tags_response = client.list_tags_for_resource(resourceArn=arn)
                        tags_dict = tags_response.get('tags', {})
                        # Neptune Analytics returns tags as a dictionary
                        resource_tags = tags_dict
                    except (ConnectTimeoutError, ReadTimeoutError):
                        logger.warning(f"Timeout retrieving tags for Neptune Analytics resource {resource_name}")
                        resource_tags = {}
                    except Exception as tag_error:
                        logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                        resource_tags = {}

                    # Get additional metadata based on resource type
                    additional_metadata = {}
                    if service_type == 'Graph':
                        additional_metadata = {
                            'status': item.get('status', ''),
                            'statusReason': item.get('statusReason', ''),
                            'endpoint': item.get('endpoint', ''),
                            'replicaCount': item.get('replicaCount', 0),
                            'kmsKeyIdentifier': item.get('kmsKeyIdentifier', ''),
                            'sourceSnapshotId': item.get('sourceSnapshotId', ''),
                            'deletionProtection': item.get('deletionProtection', False),
                            'buildNumber': item.get('buildNumber', ''),
                            'provisionedMemory': item.get('provisionedMemory', 0)
                        }
                    elif service_type == 'GraphSnapshot':
                        additional_metadata = {
                            'sourceGraphId': item.get('sourceGraphId', ''),
                            'status': item.get('status', ''),
                            'kmsKeyIdentifier': item.get('kmsKeyIdentifier', ''),
                            'snapshotType': item.get('snapshotType', ''),
                            'statusReason': item.get('statusReason', '')
                        }
                    elif service_type == 'PrivateGraphEndpoint':
                        additional_metadata = {
                            'graphIdentifier': item.get('graphIdentifier', ''),
                            'vpcId': item.get('vpcId', ''),
                            'subnetIds': item.get('subnetIds', []),
                            'status': item.get('status', ''),
                            'vpcEndpointId': item.get('vpcEndpointId', '')
                        }
                    elif service_type == 'ImportTask':
                        additional_metadata = {
                            'graphId': item.get('graphId', ''),
                            'source': item.get('source', ''),
                            'format': item.get('format', ''),
                            'status': item.get('status', ''),
                            'roleArn': item.get('roleArn', ''),
                            'importOptions': item.get('importOptions', {}),
                            'importedGraphSummary': item.get('importedGraphSummary', {})
                        }
                    elif service_type == 'ExportTask':
                        additional_metadata = {
                            'graphId': item.get('graphId', ''),
                            'destination': item.get('destination', ''),
                            'format': item.get('format', ''),
                            'status': item.get('status', ''),
                            'roleArn': item.get('roleArn', ''),
                            'exportTaskDetails': item.get('exportTaskDetails', {})
                        }
                    elif service_type == 'Query':
                        additional_metadata = {
                            'graphIdentifier': item.get('graphIdentifier', ''),
                            'state': item.get('state', ''),
                            'elapsed': item.get('elapsed', 0),
                            'queryString': item.get('queryString', ''),
                            'waited': item.get('waited', 0)
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
                    logger.warning(f"Error processing Neptune Analytics item: {str(item_error)}")
                    continue

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} {service_type.lower()}s')

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in Neptune Analytics discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources


def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    if tags_action == 2:        
        tag_keys = list(tags.keys()) if isinstance(tags, dict) else [tag['Key'] for tag in tags]

    # Create Neptune Analytics client with timeout protection
    session = boto3.Session()
    client_config = Config(
        read_timeout=15,
        connect_timeout=10,
        retries={'max_attempts': 2, 'mode': 'standard'}
    )
    
    try:
        neptune_graph_client = session.client('neptune-graph', region_name=region, config=client_config)
    except Exception as e:
        logger.error(f"Failed to create Neptune Analytics client: {str(e)}")
        return []

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Neptune Analytics uses dictionary format
                if isinstance(tags, list):
                    neptune_graph_tags = {tag['Key']: tag['Value'] for tag in tags}
                else:
                    neptune_graph_tags = tags
                    
                neptune_graph_client.tag_resource(
                    resourceArn=resource.arn,
                    tags=neptune_graph_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                neptune_graph_client.untag_resource(
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

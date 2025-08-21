import boto3
import json
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError, ClientError, ConnectTimeoutError, ReadTimeoutError
from botocore.config import Config

def get_service_types(account_id, region, service, service_type):
    """
    Amazon Neptune resources that support tagging.
    
    Neptune uses the RDS API client and supports tagging for:
    - Cluster (Neptune DB clusters)
    - Instance (Neptune DB instances)
    - ClusterSnapshot (Neptune cluster snapshots)
    - ClusterParameterGroup (Neptune cluster parameter groups)
    - ParameterGroup (Neptune DB parameter groups)
    - SubnetGroup (Neptune DB subnet groups)
    - EventSubscription (Neptune event subscriptions)
    - GlobalCluster (Neptune global clusters)
    - ClusterEndpoint (Neptune cluster endpoints)
    """
    
    resource_configs = {
        'Cluster': {
            'method': 'describe_db_clusters',
            'key': 'DBClusters',
            'id_field': 'DBClusterIdentifier',
            'name_field': 'DBClusterIdentifier',
            'date_field': 'ClusterCreateTime',
            'nested': False,
            'filter': {'Name': 'engine', 'Values': ['neptune']},
            'arn_format': 'arn:aws:rds:{region}:{account_id}:cluster:{resource_id}',
            'arn_field': 'DBClusterArn'
        },
        'Instance': {
            'method': 'describe_db_instances',
            'key': 'DBInstances',
            'id_field': 'DBInstanceIdentifier',
            'name_field': 'DBInstanceIdentifier',
            'date_field': 'InstanceCreateTime',
            'nested': False,
            'filter': {'Name': 'engine', 'Values': ['neptune']},
            'arn_format': 'arn:aws:rds:{region}:{account_id}:db:{resource_id}',
            'arn_field': 'DBInstanceArn'
        },
        'ClusterSnapshot': {
            'method': 'describe_db_cluster_snapshots',
            'key': 'DBClusterSnapshots',
            'id_field': 'DBClusterSnapshotIdentifier',
            'name_field': 'DBClusterSnapshotIdentifier',
            'date_field': 'SnapshotCreateTime',
            'nested': False,
            'filter': {'Name': 'engine', 'Values': ['neptune']},
            'arn_format': 'arn:aws:rds:{region}:{account_id}:cluster-snapshot:{resource_id}',
            'arn_field': 'DBClusterSnapshotArn'
        },
        'ClusterParameterGroup': {
            'method': 'describe_db_cluster_parameter_groups',
            'key': 'DBClusterParameterGroups',
            'id_field': 'DBClusterParameterGroupName',
            'name_field': 'DBClusterParameterGroupName',
            'date_field': None,
            'nested': False,
            'filter': {'Name': 'engine', 'Values': ['neptune']},
            'arn_format': 'arn:aws:rds:{region}:{account_id}:cluster-pg:{resource_id}',
            'arn_field': 'DBClusterParameterGroupArn'
        },
        'ParameterGroup': {
            'method': 'describe_db_parameter_groups',
            'key': 'DBParameterGroups',
            'id_field': 'DBParameterGroupName',
            'name_field': 'DBParameterGroupName',
            'date_field': None,
            'nested': False,
            'filter': {'Name': 'engine', 'Values': ['neptune']},
            'arn_format': 'arn:aws:rds:{region}:{account_id}:pg:{resource_id}',
            'arn_field': 'DBParameterGroupArn'
        },
        'SubnetGroup': {
            'method': 'describe_db_subnet_groups',
            'key': 'DBSubnetGroups',
            'id_field': 'DBSubnetGroupName',
            'name_field': 'DBSubnetGroupName',
            'date_field': None,
            'nested': False,
            # No filter needed - subnet groups are not engine-specific
            'arn_format': 'arn:aws:rds:{region}:{account_id}:subgrp:{resource_id}',
            'arn_field': 'DBSubnetGroupArn'
        },
        'EventSubscription': {
            'method': 'describe_event_subscriptions',
            'key': 'EventSubscriptionsList',
            'id_field': 'CustSubscriptionId',
            'name_field': 'CustSubscriptionId',
            'date_field': 'SubscriptionCreationTime',
            'nested': False,
            # No filter needed - event subscriptions are not engine-specific
            'arn_format': 'arn:aws:rds:{region}:{account_id}:es:{resource_id}',
            'arn_field': 'EventSubscriptionArn'
        },
        'GlobalCluster': {
            'method': 'describe_global_clusters',
            'key': 'GlobalClusters',
            'id_field': 'GlobalClusterIdentifier',
            'name_field': 'GlobalClusterIdentifier',
            'date_field': None,
            'nested': False,
            # No filter parameter supported by describe_global_clusters
            'arn_format': 'arn:aws:rds::{account_id}:global-cluster:{resource_id}',
            'arn_field': 'GlobalClusterArn',
            'filter_results': True,  # Filter results after retrieval
            'engine_filter': 'neptune'
        },
        'ClusterEndpoint': {
            'method': 'describe_db_cluster_endpoints',
            'key': 'DBClusterEndpoints',
            'id_field': 'DBClusterEndpointIdentifier',
            'name_field': 'DBClusterEndpointIdentifier',
            'date_field': None,
            'nested': False,
            # No filter needed - cluster endpoints are not engine-specific in the API
            'arn_format': 'arn:aws:rds:{region}:{account_id}:cluster-endpoint:{resource_id}',
            'arn_field': 'DBClusterEndpointArn'
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
        
        # Neptune uses the RDS client
        try:
            client = session.client('neptune', region_name=region, config=client_config)
        except Exception as e:
            logger.warning(f"Neptune client creation failed in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []

        if not hasattr(client, config['method']):
            logger.warning(f"Method {config['method']} not available for neptune client")
            return f'{service}:{service_type}', "success", "", []

        method = getattr(client, config['method'])
        params = {}
        
        # Add Neptune-specific filter if specified (not for GlobalCluster)
        if 'filter' in config:
            params['Filters'] = [config['filter']]

        try:
            logger.info(f"Calling Neptune {config['method']} in region {region}")
            
            # Handle pagination
            try:
                paginator = client.get_paginator(config['method'])
                response_iterator = paginator.paginate(**params)
            except OperationNotPageableError:
                response_iterator = [method(**params)]
                
        except (ConnectTimeoutError, ReadTimeoutError) as e:
            logger.warning(f"Neptune timeout in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code in ['UnauthorizedOperation', 'AccessDenied', 'InvalidAction']:
                logger.warning(f"Neptune not available in region {region}: {error_code}")
                return f'{service}:{service_type}', "success", "", []
            else:
                logger.error(f"Neptune API error in region {region}: {str(e)}")
                return f'{service}:{service_type}', "error", str(e), []
        except Exception as e:
            logger.warning(f"Neptune general error in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []

        for page in response_iterator:
            items = page.get(config['key'], [])
            
            # Filter results after retrieval for GlobalCluster
            if config.get('filter_results', False):
                engine_filter = config.get('engine_filter', '')
                if engine_filter:
                    items = [item for item in items if item.get('Engine', '').lower() == engine_filter.lower()]

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

                    # Get ARN - prefer direct ARN field, fallback to constructed ARN
                    if config.get('arn_field') and config['arn_field'] in item:
                        arn = item[config['arn_field']]
                    else:
                        arn = config['arn_format'].format(
                            region=region,
                            account_id=account_id,
                            resource_id=resource_id
                        )

                    # Get existing tags
                    resource_tags = {}
                    
                    # First try to get tags from the item itself (TagList)
                    if 'TagList' in item and item['TagList']:
                        resource_tags = {tag.get('Key', ''): tag.get('Value', '') for tag in item.get('TagList', [])}
                    else:
                        # Fetch tags separately using list_tags_for_resource
                        try:
                            tag_response = client.list_tags_for_resource(ResourceName=arn)
                            resource_tags = {tag.get('Key', ''): tag.get('Value', '') for tag in tag_response.get('TagList', [])}
                        except (ConnectTimeoutError, ReadTimeoutError):
                            logger.warning(f"Timeout retrieving tags for Neptune resource {resource_name}")
                            resource_tags = {}
                        except Exception as tag_error:
                            logger.warning(f"Error fetching tags for Neptune {service_type} {resource_id}: {str(tag_error)}")
                            resource_tags = {}

                    # Get additional metadata based on resource type
                    additional_metadata = {}
                    if service_type == 'Cluster':
                        additional_metadata = {
                            'Engine': item.get('Engine', ''),
                            'EngineVersion': item.get('EngineVersion', ''),
                            'Status': item.get('Status', ''),
                            'Endpoint': item.get('Endpoint', ''),
                            'Port': item.get('Port', 0),
                            'MasterUsername': item.get('MasterUsername', ''),
                            'DatabaseName': item.get('DatabaseName', ''),
                            'BackupRetentionPeriod': item.get('BackupRetentionPeriod', 0),
                            'PreferredBackupWindow': item.get('PreferredBackupWindow', ''),
                            'PreferredMaintenanceWindow': item.get('PreferredMaintenanceWindow', ''),
                            'MultiAZ': item.get('MultiAZ', False),
                            'StorageEncrypted': item.get('StorageEncrypted', False),
                            'KmsKeyId': item.get('KmsKeyId', ''),
                            'DbClusterResourceId': item.get('DbClusterResourceId', ''),
                            'DeletionProtection': item.get('DeletionProtection', False)
                        }
                    elif service_type == 'Instance':
                        additional_metadata = {
                            'Engine': item.get('Engine', ''),
                            'EngineVersion': item.get('EngineVersion', ''),
                            'DBInstanceClass': item.get('DBInstanceClass', ''),
                            'DBInstanceStatus': item.get('DBInstanceStatus', ''),
                            'Endpoint': item.get('Endpoint', {}),
                            'Port': item.get('DbInstancePort', 0),
                            'AvailabilityZone': item.get('AvailabilityZone', ''),
                            'DBSubnetGroup': item.get('DBSubnetGroup', {}),
                            'MultiAZ': item.get('MultiAZ', False),
                            'PubliclyAccessible': item.get('PubliclyAccessible', False),
                            'StorageEncrypted': item.get('StorageEncrypted', False),
                            'KmsKeyId': item.get('KmsKeyId', ''),
                            'DbiResourceId': item.get('DbiResourceId', ''),
                            'DeletionProtection': item.get('DeletionProtection', False)
                        }
                    elif service_type == 'SubnetGroup':
                        additional_metadata = {
                            'VpcId': item.get('VpcId', ''),
                            'SubnetGroupStatus': item.get('SubnetGroupStatus', ''),
                            'Subnets': item.get('Subnets', [])
                        }
                    elif service_type == 'GlobalCluster':
                        additional_metadata = {
                            'Engine': item.get('Engine', ''),
                            'EngineVersion': item.get('EngineVersion', ''),
                            'Status': item.get('Status', ''),
                            'StorageEncrypted': item.get('StorageEncrypted', False),
                            'DeletionProtection': item.get('DeletionProtection', False),
                            'GlobalClusterMembers': item.get('GlobalClusterMembers', [])
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
                    logger.warning(f"Error processing Neptune item: {str(item_error)}")
                    continue

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} {service_type.lower()}s')

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in Neptune discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources

def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    # Create Neptune client with timeout protection
    session = boto3.Session()
    client_config = Config(
        read_timeout=15,
        connect_timeout=10,
        retries={'max_attempts': 2, 'mode': 'standard'}
    )
    
    try:
        neptune_client = session.client('neptune', region_name=region, config=client_config)
    except Exception as e:
        logger.error(f"Failed to create Neptune client: {str(e)}")
        return []

    for resource in resources:
        try:
            if tags_action == 1:  # Add tags
                neptune_client.add_tags_to_resource(
                    ResourceName=resource.arn,
                    Tags=[{'Key': item['Key'], 'Value': item['Value']} for item in tags]
                )
            elif tags_action == 2:  # Remove tags
                neptune_client.remove_tags_from_resource(
                    ResourceName=resource.arn,
                    TagKeys=[item['Key'] for item in tags]
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

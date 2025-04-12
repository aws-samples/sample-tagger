import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError
from typing import List, Dict, Tuple

def get_service_types(account_id, region, service, service_type):

    resource_configs = {
            'ReplicationGroup': {
                'method': 'describe_replication_groups',
                'key': 'ReplicationGroups',
                'id_field': 'ReplicationGroupId',
                'date_field': None,  # ReplicationGroups don't have a creation date in this API response
                'nested': False,
                'arn_format': 'arn:aws:elasticache:{region}:{account_id}:replicationgroup:{resource_id}'
            },
            'Snapshot': {
                'method': 'describe_snapshots',
                'key': 'Snapshots',
                'id_field': 'SnapshotName',
                'date_field': 'NodeSnapshotCreateTime',
                'nested': False,
                'arn_format': 'arn:aws:elasticache:{region}:{account_id}:snapshot:{resource_id}'
            }
        }
        
    return resource_configs


def discovery(self, session, account_id, region, service, service_type, logger):    
    
    status = "success"
    error_message = ""
    resources = []
    processed_clusters = set()  # To track clusters we've already processed

    try:
        service_types_list = get_service_types(account_id, region, service, service_type)        
        if service_type not in service_types_list:
            raise ValueError(f"Unsupported service type: {service_type}")

        config = service_types_list[service_type]        
        client = session.client(service, region_name=region)

        method = getattr(client, config['method'])
        params = {}

        try:
            paginator = client.get_paginator(config['method'])
            response_iterator = paginator.paginate(**params)
        except OperationNotPageableError:
            response_iterator = [method(**params)]

        for page in response_iterator:
            items = page[config['key']]

            for item in items:
                resource_id = item[config['id_field']]
                
                # For Cluster types, only process once per cluster
                if service_type == 'Cluster':
                    # Extract the base cluster id (without node suffix)
                    base_cluster_id = resource_id.split('-')[0] if '-' in resource_id else resource_id
                    
                    # Skip if we've already processed this cluster
                    if base_cluster_id in processed_clusters:
                        continue
                    processed_clusters.add(base_cluster_id)
                    
                    # For multi-node clusters, use the base ID
                    resource_id = base_cluster_id
                
                # For ElastiCache, we need to get the ARN and tags separately
                if service_type in ['Cluster', 'ReplicationGroup', 'Snapshot']:
                    arn = config['arn_format'].format(
                        region=region,
                        account_id=account_id,
                        resource_id=resource_id
                    )
                    
                    # Get tags for the resource
                    try:
                        tags_response = client.list_tags_for_resource(ResourceName=arn)
                        resource_tags = {tag['Key']: tag['Value'] for tag in tags_response.get('TagList', [])}
                    except Exception as e:
                        logger.warning(f"Could not retrieve tags for {resource_id}: {str(e)}")
                        resource_tags = {}
                else:
                    resource_tags = {}
                    arn = config['arn_format'].format(
                        region=region,
                        account_id=account_id,
                        resource_id=resource_id
                    )
                
                name_tag = resource_tags.get('Name', resource_id)
                creation_date = item.get(config['date_field']) if config['date_field'] else ''

                # For clusters, get additional information about the cluster including all nodes
                if service_type == 'Cluster':
                    # Get all nodes that belong to this cluster
                    try:
                        cluster_nodes = []
                        cluster_response = client.describe_cache_clusters(
                            CacheClusterId=resource_id,
                            ShowCacheNodeInfo=True
                        )
                        if cluster_response.get('CacheClusters'):
                            cluster_data = cluster_response['CacheClusters'][0]
                            item = cluster_data  # Replace with complete cluster data
                            if 'CacheNodes' in cluster_data:
                                for node in cluster_data['CacheNodes']:
                                    cluster_nodes.append({
                                        'CacheNodeId': node.get('CacheNodeId'),
                                        'CacheNodeStatus': node.get('CacheNodeStatus'),
                                        'Endpoint': node.get('Endpoint')
                                    })
                            item['ClusterNodes'] = cluster_nodes
                    except Exception as e:
                        logger.warning(f"Could not retrieve detailed info for cluster {resource_id}: {str(e)}")

                resources.append({
                    "seq": 0,
                    "account_id": account_id,
                    "region": region,
                    "service": service,
                    "resource_type": service_type,
                    "resource_id": resource_id,
                    "name": name_tag,
                    "creation_date": creation_date,
                    "tags": resource_tags,
                    "tags_number": len(resource_tags),
                    "metadata": item,
                    "arn": arn
                })

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources


def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)
    
    # Format for ElastiCache tags
    elasticache_tags = [{'Key': tag['Key'], 'Value': tag['Value']} for tag in tags] if tags_action == 1 else \
                       [{'Key': tag['Key']} for tag in tags] 

    for resource in resources:            
        try:
            # ElastiCache uses different methods for tagging
            if tags_action == 1:
                client.add_tags_to_resource(
                    ResourceName=resource.arn,
                    Tags=elasticache_tags
                )
            elif tags_action == 2:
                client.remove_tags_from_resource(
                    ResourceName=resource.arn,
                    TagKeys=[tag['Key'] for tag in tags]
                )
                
            results.append({
                'account_id': account_id,
                'region': region,
                'service': service,
                'identifier': resource.identifier,
                'arn': resource.arn,
                'status': 'success',
                'error' : ""
            })
            
        except Exception as e:
            logger.error(f"Error processing tagging for {service} in {account_id}/{region}:{resource.identifier} # {str(e)}")
            
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
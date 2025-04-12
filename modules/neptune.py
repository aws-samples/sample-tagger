import boto3
import json
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    resource_configs = {
        'Cluster': {
            'method': 'describe_db_clusters',
            'key': 'DBClusters',
            'id_field': 'DBClusterIdentifier',
            'date_field': 'ClusterCreateTime',
            'nested': False,
            'filter': {'Name': 'engine', 'Values': ['neptune']},
            'arn_format': 'arn:aws:rds:{region}:{account_id}:cluster:{resource_id}'
        },
        'Instance': {
            'method': 'describe_db_instances',
            'key': 'DBInstances',
            'id_field': 'DBInstanceIdentifier',
            'date_field': 'InstanceCreateTime',
            'nested': False,
            'filter': {'Name': 'engine', 'Values': ['neptune']},
            'arn_format': 'arn:aws:rds:{region}:{account_id}:db:{resource_id}'
        },
        'Snapshot': {
            'method': 'describe_db_cluster_snapshots',
            'key': 'DBClusterSnapshots',
            'id_field': 'DBClusterSnapshotIdentifier',
            'date_field': 'SnapshotCreateTime',
            'nested': False,
            'filter': {'Name': 'engine', 'Values': ['neptune']},
            'arn_format': 'arn:aws:rds:{region}:{account_id}:cluster-snapshot:{resource_id}'
        }
    }
    
    return resource_configs

def discovery(self, session, account_id, region, service, service_type, logger):
    status = "success"
    error_message = ""
    resources = []

    try:
        # Note: Neptune resources are managed through the RDS API client
        service_types_list = get_service_types(account_id, region, service, service_type)
        if service_type not in service_types_list:
            raise ValueError(f"Unsupported service type: {service_type}")

        config = service_types_list[service_type]
        # Neptune uses the RDS client
        client = session.client('rds', region_name=region)

        method = getattr(client, config['method'])
        params = {}
        
        # Add Neptune-specific filter
        if 'filter' in config:
            params['Filters'] = [config['filter']]

        try:
            paginator = client.get_paginator(config['method'])
            response_iterator = paginator.paginate(**params)
        except OperationNotPageableError:
            response_iterator = [method(**params)]

        for page in response_iterator:
            items = page[config['key']]

            for item in items:
                resource_id = item[config['id_field']]
                
                # Neptune/RDS uses a different tag structure
                resource_tags = {}
                if 'TagList' in item and item['TagList']:
                    resource_tags = {tag.get('Key', ''): tag.get('Value', '') for tag in item.get('TagList', [])}
                # For Neptune, we might need to fetch tags separately if not included in the describe call
                elif hasattr(client, 'list_tags_for_resource'):
                    try:
                        arn = item.get('DBClusterArn') or item.get('DBInstanceArn') or item.get('DBClusterSnapshotArn') or \
                              config['arn_format'].format(region=region, account_id=account_id, resource_id=resource_id)
                        tag_response = client.list_tags_for_resource(ResourceName=arn)
                        resource_tags = {tag.get('Key', ''): tag.get('Value', '') for tag in tag_response.get('TagList', [])}
                    except Exception as tag_error:
                        logger.warning(f"Error fetching tags for Neptune {service_type} {resource_id}: {str(tag_error)}")
                
                name = resource_id  # Neptune typically uses the identifier as the name
                creation_date = item.get(config['date_field']) if config['date_field'] else ''

                arn = item.get('DBClusterArn') or item.get('DBInstanceArn') or item.get('DBClusterSnapshotArn') or \
                      config['arn_format'].format(region=region, account_id=account_id, resource_id=resource_id)

                resources.append({
                    "seq": 0,
                    "account_id": account_id,
                    "region": region,
                    "service": service,
                    "resource_type": service_type,
                    "resource_id": resource_id,
                    "name": name,
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
    logger.info(f'Discovery # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    for resource in resources:
        try:
            if tags_action == 1:  # Add tags
                client.add_tags_to_resource(
                    ResourceName=resource.arn,
                    Tags=[{'Key': item['Key'], 'Value': item['Value']} for item in tags]
                )
            elif tags_action == 2:  # Remove tags
                client.remove_tags_from_resource(
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
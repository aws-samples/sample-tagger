import json
import boto3
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
            'arn_format': 'arn:aws:rds:{region}:{account_id}:cluster:{resource_id}'
        },
        'Instance': {
            'method': 'describe_db_instances',
            'key': 'DBInstances',
            'id_field': 'DBInstanceIdentifier',
            'date_field': 'InstanceCreateTime',
            'nested': False,
            'arn_format': 'arn:aws:rds:{region}:{account_id}:db:{resource_id}'
        },
        'Snapshot': {
            'method': 'describe_db_cluster_snapshots',
            'key': 'DBClusterSnapshots',
            'id_field': 'DBClusterSnapshotIdentifier',
            'date_field': 'SnapshotCreateTime',
            'nested': False,
            'arn_format': 'arn:aws:rds:{region}:{account_id}:cluster-snapshot:{resource_id}'
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
        client = session.client('docdb', region_name=region)  # DocumentDB has its own client

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
                # Filter DocumentDB resources - engine will be 'docdb'
                if item.get('Engine') != 'docdb':
                    continue
                    
                resource_id = item[config['id_field']]
                
                # Get the appropriate ARN field based on resource type
                if service_type == 'Cluster':
                    resource_arn = item.get('DBClusterArn')
                elif service_type == 'Instance':
                    resource_arn = item.get('DBInstanceArn')
                elif service_type == 'Snapshot':
                    resource_arn = item.get('DBClusterSnapshotArn')
                else:
                    resource_arn = None
                
                # Handle TagList or Tags depending on which is available
                if 'TagList' in item:
                    resource_tags = {tag['Key']: tag['Value'] for tag in item.get('TagList', [])}
                else:
                    # We might need to call list_tags_for_resource for some resources
                    try:
                        if resource_arn:
                            tags_response = client.list_tags_for_resource(ResourceName=resource_arn)
                            resource_tags = {tag['Key']: tag['Value'] for tag in tags_response.get('TagList', [])}
                        else:
                            resource_tags = {}
                    except Exception as tag_err:
                        logger.warning(f"Could not fetch tags for {resource_id}: {str(tag_err)}")
                        resource_tags = {}
                
                name_tag = resource_tags.get('Name', resource_id)
                creation_date = item.get(config['date_field']) if config['date_field'] else ''

                # If ARN is not provided by the API, construct it
                if not resource_arn:
                    resource_arn = config['arn_format'].format(
                        region=region,
                        account_id=account_id,
                        resource_id=resource_id
                    )

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
                    "arn": resource_arn
                })

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources

class DocumentDBResource:
    def __init__(self, arn):
        self.identifier = arn

def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    
    logger.info(f'DocumentDB Tagging # Account: {account_id}, Region: {region}, Service: {service}')
    
    results = []    
    tags = parse_tags(tags_string)
    
    # DocumentDB resources are tagged by their ARN, not resource ID
    docdb_resources = []
    for resource in resources:
        if isinstance(resource, dict) and 'arn' in resource:
            docdb_resources.append(DocumentDBResource(resource['arn']))
        elif hasattr(resource, 'arn'):
            docdb_resources.append(DocumentDBResource(resource.arn))
        else:
            logger.warning(f"Resource without ARN: {resource}")
    
    # DocumentDB uses its own client for tagging
    docdb_client = client if client else boto3.client('docdb', region_name=region)

    for resource in docdb_resources:
        try:
            if tags_action == 1:  # Add tags
                docdb_client.add_tags_to_resource(
                    ResourceName=resource.identifier,
                    Tags=tags
                )
            elif tags_action == 2:  # Remove tags
                tag_keys = [tag['Key'] for tag in tags]
                docdb_client.remove_tags_from_resource(
                    ResourceName=resource.identifier,
                    TagKeys=tag_keys
                )
                           
            results.append({
                'account_id': account_id,
                'region': region,
                'service': service,
                'identifier': resource.identifier,
                'status': 'success'
            })
            
        except Exception as e:
            logger.error(f"Error processing tagging for DocumentDB in {account_id}/{region}:{resource.identifier} # {str(e)}")
            
            results.append({
                'account_id': account_id,
                'region': region,
                'service': service,
                'identifier': resource.identifier,
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
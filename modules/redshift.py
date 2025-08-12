import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    """
    AWS Redshift resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/redshift/client/create_tags.html
    
    Redshift supports tagging for:
    - Cluster (Redshift clusters for data warehousing)
    - Snapshot (Cluster snapshots for backup and restore)
    - SubnetGroup (Subnet groups for VPC configuration)
    - ParameterGroup (Parameter groups for cluster configuration)
    - ScheduledAction (Scheduled actions for automation)
    """

    resource_configs = {
        'Cluster': {
            'method': 'describe_clusters',
            'key': 'Clusters',
            'id_field': 'ClusterIdentifier',
            'name_field': 'ClusterIdentifier',
            'date_field': 'ClusterCreateTime',
            'nested': False,
            'arn_format': 'arn:aws:redshift:{region}:{account_id}:cluster:{name}'
        },
        'Snapshot': {
            'method': 'describe_cluster_snapshots',
            'key': 'Snapshots',
            'id_field': 'SnapshotIdentifier',
            'name_field': 'SnapshotIdentifier',
            'date_field': 'SnapshotCreateTime',
            'nested': False,
            'arn_format': 'arn:aws:redshift:{region}:{account_id}:snapshot:{cluster_name}/{name}'
        },
        'SubnetGroup': {
            'method': 'describe_cluster_subnet_groups',
            'key': 'ClusterSubnetGroups',
            'id_field': 'ClusterSubnetGroupName',
            'name_field': 'ClusterSubnetGroupName',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:redshift:{region}:{account_id}:subnetgroup:{name}'
        },
        'ParameterGroup': {
            'method': 'describe_cluster_parameter_groups',
            'key': 'ParameterGroups',
            'id_field': 'ParameterGroupName',
            'name_field': 'ParameterGroupName',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:redshift:{region}:{account_id}:parametergroup:{name}'
        },
        'ScheduledAction': {
            'method': 'describe_scheduled_actions',
            'key': 'ScheduledActions',
            'id_field': 'ScheduledActionName',
            'name_field': 'ScheduledActionName',
            'date_field': 'NextInvocations',  # Special handling needed
            'nested': False,
            'arn_format': 'arn:aws:redshift:{region}:{account_id}:scheduledaction:{name}'
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
        
        # Redshift is regional
        client = session.client('redshift', region_name=region)
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for redshift client")

        method = getattr(client, config['method'])
        params = {}

        # Add specific filters for certain resource types
        if service_type == 'Snapshot':
            # Only get snapshots owned by the account (not AWS managed)
            params['OwnerAccount'] = account_id

        # Handle pagination
        try:
            paginator = client.get_paginator(config['method'])
            page_iterator = paginator.paginate(**params)
        except OperationNotPageableError:
            response = method(**params)
            page_iterator = [response]

        # Process each page of results
        for page in page_iterator:
            items = page.get(config['key'], [])
            if not items:
                continue

            for item in items:
                resource_id = item[config['id_field']]
                resource_name = item.get(config['name_field'], resource_id) if config['name_field'] else resource_id

                # Get creation date
                creation_date = None
                if config['date_field'] and config['date_field'] in item:
                    creation_date = item[config['date_field']]
                    if hasattr(creation_date, 'isoformat'):
                        creation_date = creation_date.isoformat()
                    elif service_type == 'ScheduledAction' and isinstance(creation_date, list):
                        # NextInvocations is a list, get the first one
                        if creation_date:
                            creation_date = creation_date[0].isoformat() if hasattr(creation_date[0], 'isoformat') else str(creation_date[0])

                # Build ARN
                if config['arn_format']:
                    if service_type == 'Snapshot':
                        # Snapshots need cluster name in ARN
                        cluster_name = item.get('ClusterIdentifier', 'unknown')
                        arn = config['arn_format'].format(region=region, account_id=account_id, cluster_name=cluster_name, name=resource_name)
                    else:
                        arn = config['arn_format'].format(region=region, account_id=account_id, name=resource_name)
                else:
                    arn = f"arn:aws:redshift:{region}:{account_id}:{service_type.lower()}:{resource_id}"

                # Get additional metadata based on resource type
                additional_metadata = {}
                if service_type == 'Cluster':
                    additional_metadata = {
                        'NodeType': item.get('NodeType', ''),
                        'NumberOfNodes': item.get('NumberOfNodes', 0),
                        'ClusterStatus': item.get('ClusterStatus', ''),
                        'MasterUsername': item.get('MasterUsername', ''),
                        'DBName': item.get('DBName', ''),
                        'Endpoint': item.get('Endpoint', {}),
                        'ClusterVersion': item.get('ClusterVersion', ''),
                        'PubliclyAccessible': item.get('PubliclyAccessible', False),
                        'Encrypted': item.get('Encrypted', False)
                    }
                elif service_type == 'Snapshot':
                    additional_metadata = {
                        'ClusterIdentifier': item.get('ClusterIdentifier', ''),
                        'SnapshotType': item.get('SnapshotType', ''),
                        'Status': item.get('Status', ''),
                        'Port': item.get('Port', 0),
                        'AvailabilityZone': item.get('AvailabilityZone', ''),
                        'MasterUsername': item.get('MasterUsername', ''),
                        'DBName': item.get('DBName', ''),
                        'Encrypted': item.get('Encrypted', False)
                    }
                elif service_type == 'SubnetGroup':
                    additional_metadata = {
                        'Description': item.get('Description', ''),
                        'VpcId': item.get('VpcId', ''),
                        'SubnetGroupStatus': item.get('SubnetGroupStatus', ''),
                        'Subnets': item.get('Subnets', [])
                    }
                elif service_type == 'ParameterGroup':
                    additional_metadata = {
                        'ParameterGroupFamily': item.get('ParameterGroupFamily', ''),
                        'Description': item.get('Description', '')
                    }
                elif service_type == 'ScheduledAction':
                    additional_metadata = {
                        'TargetAction': item.get('TargetAction', {}),
                        'Schedule': item.get('Schedule', ''),
                        'IamRole': item.get('IamRole', ''),
                        'Description': item.get('Description', ''),
                        'State': item.get('State', ''),
                        'NextInvocations': item.get('NextInvocations', [])
                    }

                # Get existing tags
                resource_tags = {}
                try:
                    tags_response = client.describe_tags(ResourceName=arn)
                    tags_list = tags_response.get('TaggedResources', [])
                    if tags_list:
                        # Get tags from the first (and should be only) resource
                        resource_tags_list = tags_list[0].get('Tags', [])
                        resource_tags = {tag['Key']: tag['Value'] for tag in resource_tags_list}
                except Exception as tag_error:
                    logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                    resource_tags = {}

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

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} {service_type.lower()}s')

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources


####----| Tagging method
def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    if tags_action == 2:        
        tag_keys = [item['Key'] for item in tags]

    # Create Redshift client
    session = boto3.Session()
    redshift_client = session.client('redshift', region_name=region)

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to Redshift format (list of objects)
                redshift_tags = [{'Key': tag['Key'], 'Value': tag['Value']} for tag in tags]
                redshift_client.create_tags(
                    ResourceName=resource.arn,
                    Tags=redshift_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                redshift_client.delete_tags(
                    ResourceName=resource.arn,
                    TagKeys=tag_keys
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

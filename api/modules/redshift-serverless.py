import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    """
    AWS Redshift Serverless resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/redshift-serverless/client/tag_resource.html
    
    Redshift Serverless supports tagging for:
    - Workgroup (Serverless workgroups for compute resources)
    - Namespace (Serverless namespaces for data organization)
    - Snapshot (Serverless snapshots for backup and restore)
    - RecoveryPoint (Recovery points for point-in-time recovery)
    """

    resource_configs = {
        'Workgroup': {
            'method': 'list_workgroups',
            'key': 'workgroups',
            'id_field': 'workgroupName',
            'name_field': 'workgroupName',
            'date_field': 'creationDate',
            'nested': False,
            'arn_format': 'arn:aws:redshift-serverless:{region}:{account_id}:workgroup/{name}'
        },
        'Namespace': {
            'method': 'list_namespaces',
            'key': 'namespaces',
            'id_field': 'namespaceName',
            'name_field': 'namespaceName',
            'date_field': 'creationDate',
            'nested': False,
            'arn_format': 'arn:aws:redshift-serverless:{region}:{account_id}:namespace/{name}'
        },
        'Snapshot': {
            'method': 'list_snapshots',
            'key': 'snapshots',
            'id_field': 'snapshotName',
            'name_field': 'snapshotName',
            'date_field': 'snapshotCreateTime',
            'nested': False,
            'arn_format': 'arn:aws:redshift-serverless:{region}:{account_id}:snapshot/{name}'
        },
        'RecoveryPoint': {
            'method': 'list_recovery_points',
            'key': 'recoveryPoints',
            'id_field': 'recoveryPointId',
            'name_field': 'recoveryPointId',
            'date_field': 'recoveryPointCreateTime',
            'nested': False,
            'arn_format': 'arn:aws:redshift-serverless:{region}:{account_id}:recoverypoint/{name}'
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
        
        # Redshift Serverless is regional
        client = session.client('redshift-serverless', region_name=region)
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for redshift-serverless client")

        method = getattr(client, config['method'])
        params = {}

        # Add specific filters for certain resource types
        if service_type == 'Snapshot':
            # Only get snapshots owned by the account
            params['ownerAccount'] = account_id

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

                # Build ARN
                if config['arn_format']:
                    arn = config['arn_format'].format(region=region, account_id=account_id, name=resource_name)
                else:
                    arn = f"arn:aws:redshift-serverless:{region}:{account_id}:{service_type.lower()}:{resource_id}"

                # Get additional metadata based on resource type
                additional_metadata = {}
                if service_type == 'Workgroup':
                    additional_metadata = {
                        'status': item.get('status', ''),
                        'endpoint': item.get('endpoint', {}),
                        'port': item.get('port', 0),
                        'publiclyAccessible': item.get('publiclyAccessible', False),
                        'enhancedVpcRouting': item.get('enhancedVpcRouting', False),
                        'baseCapacity': item.get('baseCapacity', 0),
                        'configParameters': item.get('configParameters', []),
                        'securityGroupIds': item.get('securityGroupIds', []),
                        'subnetIds': item.get('subnetIds', [])
                    }
                elif service_type == 'Namespace':
                    additional_metadata = {
                        'status': item.get('status', ''),
                        'dbName': item.get('dbName', ''),
                        'defaultIamRoleArn': item.get('defaultIamRoleArn', ''),
                        'iamRoles': item.get('iamRoles', []),
                        'kmsKeyId': item.get('kmsKeyId', ''),
                        'logExports': item.get('logExports', []),
                        'adminUsername': item.get('adminUsername', '')
                    }
                elif service_type == 'Snapshot':
                    additional_metadata = {
                        'status': item.get('status', ''),
                        'namespaceName': item.get('namespaceName', ''),
                        'snapshotRetentionPeriod': item.get('snapshotRetentionPeriod', 0),
                        'adminUsername': item.get('adminUsername', ''),
                        'kmsKeyId': item.get('kmsKeyId', ''),
                        'ownerAccount': item.get('ownerAccount', ''),
                        'totalBackupSizeInMegaBytes': item.get('totalBackupSizeInMegaBytes', 0),
                        'actualIncrementalBackupSizeInMegaBytes': item.get('actualIncrementalBackupSizeInMegaBytes', 0)
                    }
                elif service_type == 'RecoveryPoint':
                    additional_metadata = {
                        'namespaceName': item.get('namespaceName', ''),
                        'workgroupName': item.get('workgroupName', ''),
                        'totalSizeInMegaBytes': item.get('totalSizeInMegaBytes', 0)
                    }

                # Get existing tags
                resource_tags = {}
                try:
                    tags_response = client.list_tags_for_resource(resourceArn=arn)
                    tags_list = tags_response.get('tags', [])
                    resource_tags = {tag['key']: tag['value'] for tag in tags_list}
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

    # Create Redshift Serverless client
    session = boto3.Session()
    redshift_serverless_client = session.client('redshift-serverless', region_name=region)

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to Redshift Serverless format (list of objects)
                serverless_tags = [{'key': tag['Key'], 'value': tag['Value']} for tag in tags]
                redshift_serverless_client.tag_resource(
                    resourceArn=resource.arn,
                    tags=serverless_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                redshift_serverless_client.untag_resource(
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
    """Parse tags from string format to list of dictionaries"""
    tags = []
    if tags_string:
        for tag_pair in tags_string.split(','):
            if ':' in tag_pair:
                key, value = tag_pair.split(':', 1)
                tags.append({'Key': key.strip(), 'Value': value.strip()})
    return tags

import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    """
    AWS Elastic Disaster Recovery (DRS) resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/drs/client/tag_resource.html
    
    DRS supports tagging for:
    - SourceServer (Source servers being protected by DRS)
    - ReplicationConfigurationTemplate (Templates for replication configuration)
    - LaunchConfigurationTemplate (Templates for launch configuration)
    
    Note: DRS is a regional service for disaster recovery to AWS
    """

    resource_configs = {
        'SourceServer': {
            'method': 'describe_source_servers',
            'key': 'items',
            'id_field': 'arn',
            'name_field': None,  # Will use sourceServerID as name
            'date_field': None,  # Not available in list response
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'ReplicationConfigurationTemplate': {
            'method': 'describe_replication_configuration_templates',
            'key': 'items',
            'id_field': 'arn',
            'name_field': None,  # Will use replicationConfigurationTemplateID as name
            'date_field': None,  # Not available in list response
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'LaunchConfigurationTemplate': {
            'method': 'describe_launch_configuration_templates',
            'key': 'items',
            'id_field': 'arn',
            'name_field': None,  # Will use launchConfigurationTemplateID as name
            'date_field': None,  # Not available in list response
            'nested': False,
            'arn_format': None  # ARN is provided directly
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
        
        # DRS is regional
        client = session.client('drs', region_name=region)
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for drs client")

        method = getattr(client, config['method'])
        params = {}

        # Handle pagination
        try:
            paginator = client.get_paginator(config['method'])
            page_iterator = paginator.paginate(**params)
        except OperationNotPageableError:
            response = method(**params)
            page_iterator = [response]

        # Process each page of results
        for page in page_iterator:
            items = page[config['key']]

            for item in items:
                resource_id = item[config['id_field']]
                
                # Handle resource name based on type
                if service_type == 'SourceServer':
                    resource_name = item.get('sourceServerID', resource_id)
                elif service_type == 'ReplicationConfigurationTemplate':
                    resource_name = item.get('replicationConfigurationTemplateID', resource_id)
                elif service_type == 'LaunchConfigurationTemplate':
                    resource_name = item.get('launchConfigurationTemplateID', resource_id)
                else:
                    resource_name = resource_id

                # Get creation date (not available in DRS list responses)
                creation_date = None

                # Build ARN - DRS provides ARN directly
                arn = resource_id

                # Get additional metadata based on resource type
                additional_metadata = {}
                if service_type == 'SourceServer':
                    additional_metadata = {
                        'sourceServerID': item.get('sourceServerID', ''),
                        'agentVersion': item.get('agentVersion', ''),
                        'dataReplicationState': item.get('dataReplicationInfo', {}).get('dataReplicationState', ''),
                        'lastLaunchResult': item.get('lastLaunchResult', ''),
                        'replicationDirection': item.get('replicationDirection', ''),
                        'recommendedInstanceType': item.get('sourceProperties', {}).get('recommendedInstanceType', ''),
                        'os': item.get('sourceProperties', {}).get('os', {}).get('fullString', ''),
                        'hostname': item.get('sourceProperties', {}).get('identificationHints', {}).get('hostname', ''),
                        'fqdn': item.get('sourceProperties', {}).get('identificationHints', {}).get('fqdn', ''),
                        'awsInstanceID': item.get('sourceProperties', {}).get('identificationHints', {}).get('awsInstanceID', ''),
                        'stagingAvailabilityZone': item.get('dataReplicationInfo', {}).get('stagingAvailabilityZone', ''),
                        'originRegion': item.get('sourceCloudProperties', {}).get('originRegion', ''),
                        'originAccountID': item.get('sourceCloudProperties', {}).get('originAccountID', ''),
                        'reversedDirectionSourceServerArn': item.get('reversedDirectionSourceServerArn', ''),
                        'supportsNitroInstances': item.get('sourceProperties', {}).get('supportsNitroInstances', False),
                        'addedToServiceDateTime': item.get('lifeCycle', {}).get('addedToServiceDateTime', '').isoformat() if hasattr(item.get('lifeCycle', {}).get('addedToServiceDateTime', ''), 'isoformat') else item.get('lifeCycle', {}).get('addedToServiceDateTime', '')
                    }
                elif service_type == 'ReplicationConfigurationTemplate':
                    additional_metadata = {
                        'replicationConfigurationTemplateID': item.get('replicationConfigurationTemplateID', ''),
                        'associateDefaultSecurityGroup': item.get('associateDefaultSecurityGroup', False),
                        'bandwidthThrottling': item.get('bandwidthThrottling', ''),
                        'createPublicIP': item.get('createPublicIP', False),
                        'dataPlaneRouting': item.get('dataPlaneRouting', ''),
                        'defaultLargeStagingDiskType': item.get('defaultLargeStagingDiskType', ''),
                        'ebsEncryption': item.get('ebsEncryption', ''),
                        'replicationServerInstanceType': item.get('replicationServerInstanceType', ''),
                        'stagingAreaSubnetId': item.get('stagingAreaSubnetId', ''),
                        'useDedicatedReplicationServer': item.get('useDedicatedReplicationServer', False)
                    }
                elif service_type == 'LaunchConfigurationTemplate':
                    additional_metadata = {
                        'launchConfigurationTemplateID': item.get('launchConfigurationTemplateID', ''),
                        'copyPrivateIp': item.get('copyPrivateIp', False),
                        'copyTags': item.get('copyTags', False),
                        'exportBucketArn': item.get('exportBucketArn', ''),
                        'launchDisposition': item.get('launchDisposition', ''),
                        'licensing': item.get('licensing', {}),
                        'targetInstanceTypeRightSizingMethod': item.get('targetInstanceTypeRightSizingMethod', '')
                    }

                # Get existing tags - DRS stores tags directly in the resource
                resource_tags = {}
                try:
                    # For DRS, tags are usually stored directly in the item
                    if 'tags' in item and isinstance(item['tags'], dict):
                        resource_tags = item['tags']
                    else:
                        # Fallback to API call if needed
                        tags_response = client.list_tags_for_resource(resourceArn=arn)
                        tags_dict = tags_response.get('tags', {})
                        resource_tags = tags_dict
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
        tag_keys = list(tags.keys()) if isinstance(tags, dict) else [tag['Key'] for tag in tags]

    # Create DRS client
    session = boto3.Session()
    drs_client = session.client('drs', region_name=region)

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to DRS format (dictionary)
                if isinstance(tags, list):
                    drs_tags = {tag['Key']: tag['Value'] for tag in tags}
                else:
                    drs_tags = tags
                    
                drs_client.tag_resource(
                    resourceArn=resource.arn,
                    tags=drs_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                drs_client.untag_resource(
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

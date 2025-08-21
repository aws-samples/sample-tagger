import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    """
    AWS Application Migration Service (MGN) resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/mgn/client/tag_resource.html
    
    MGN supports tagging for:
    - SourceServer (Source servers being migrated)
    - Application (Application groupings for migration)
    - Wave (Migration waves for coordinated migrations)
    - Connector (MGN connectors for vCenter integration)
    
    Note: MGN is a regional service for application migration to AWS
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
        'Application': {
            'method': 'list_applications',
            'key': 'items',
            'id_field': 'arn',
            'name_field': 'name',
            'date_field': 'creationDateTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'Wave': {
            'method': 'list_waves',
            'key': 'items',
            'id_field': 'arn',
            'name_field': 'name',
            'date_field': 'creationDateTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'Connector': {
            'method': 'list_connectors',
            'key': 'items',
            'id_field': 'arn',
            'name_field': 'name',
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
        
        # MGN is regional
        client = session.client('mgn', region_name=region)
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for mgn client")

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
                else:
                    resource_name = item.get(config['name_field'], resource_id) if config['name_field'] else resource_id

                # Get creation date
                creation_date = None
                if config['date_field'] and config['date_field'] in item:
                    creation_date = item[config['date_field']]
                    if hasattr(creation_date, 'isoformat'):
                        creation_date = creation_date.isoformat()

                # Build ARN - MGN provides ARN directly
                arn = resource_id

                # Get additional metadata based on resource type
                additional_metadata = {}
                if service_type == 'SourceServer':
                    additional_metadata = {
                        'sourceServerID': item.get('sourceServerID', ''),
                        'isArchived': item.get('isArchived', False),
                        'replicationType': item.get('replicationType', ''),
                        'dataReplicationState': item.get('dataReplicationInfo', {}).get('dataReplicationState', ''),
                        'lifeCycleState': item.get('lifeCycle', {}).get('state', ''),
                        'recommendedInstanceType': item.get('sourceProperties', {}).get('recommendedInstanceType', ''),
                        'os': item.get('sourceProperties', {}).get('os', {}).get('fullString', ''),
                        'hostname': item.get('sourceProperties', {}).get('identificationHints', {}).get('hostname', ''),
                        'fqdn': item.get('sourceProperties', {}).get('identificationHints', {}).get('fqdn', ''),
                        'awsInstanceID': item.get('sourceProperties', {}).get('identificationHints', {}).get('awsInstanceID', ''),
                        'vcenterClientID': item.get('vcenterClientID', ''),
                        'lastSeenByServiceDateTime': item.get('lifeCycle', {}).get('lastSeenByServiceDateTime', '').isoformat() if hasattr(item.get('lifeCycle', {}).get('lastSeenByServiceDateTime', ''), 'isoformat') else item.get('lifeCycle', {}).get('lastSeenByServiceDateTime', '')
                    }
                elif service_type == 'Application':
                    additional_metadata = {
                        'applicationID': item.get('applicationID', ''),
                        'description': item.get('description', ''),
                        'isArchived': item.get('isArchived', False),
                        'waveID': item.get('waveID', ''),
                        'lastModifiedDateTime': item.get('lastModifiedDateTime', '').isoformat() if hasattr(item.get('lastModifiedDateTime', ''), 'isoformat') else item.get('lastModifiedDateTime', '')
                    }
                elif service_type == 'Wave':
                    additional_metadata = {
                        'waveID': item.get('waveID', ''),
                        'description': item.get('description', ''),
                        'isArchived': item.get('isArchived', False),
                        'status': item.get('status', ''),
                        'lastModifiedDateTime': item.get('lastModifiedDateTime', '').isoformat() if hasattr(item.get('lastModifiedDateTime', ''), 'isoformat') else item.get('lastModifiedDateTime', '')
                    }
                elif service_type == 'Connector':
                    additional_metadata = {
                        'connectorID': item.get('connectorID', ''),
                        'ssmInstanceID': item.get('ssmInstanceID', ''),
                        'ssmCommandID': item.get('ssmCommandID', ''),
                        'capabilityArn': item.get('capabilityArn', '')
                    }

                # Get existing tags - MGN stores tags directly in the resource
                resource_tags = {}
                try:
                    # For MGN, tags are usually stored directly in the item
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

    # Create MGN client
    session = boto3.Session()
    mgn_client = session.client('mgn', region_name=region)

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to MGN format (dictionary)
                if isinstance(tags, list):
                    mgn_tags = {tag['Key']: tag['Value'] for tag in tags}
                else:
                    mgn_tags = tags
                    
                mgn_client.tag_resource(
                    resourceArn=resource.arn,
                    tags=mgn_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                mgn_client.untag_resource(
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

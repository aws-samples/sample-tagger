import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    """
    AWS SSM resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ssm/client/add_tags_to_resource.html
    
    SSM supports tagging for:
    - Parameter (SSM Parameters for configuration management)
    - Document (SSM Documents for automation)
    - MaintenanceWindow (Maintenance windows for scheduled tasks)
    - PatchBaseline (Patch baselines for patch management)
    """

    resource_configs = {
        'Parameter': {
            'method': 'describe_parameters',
            'key': 'Parameters',
            'id_field': 'Name',
            'name_field': 'Name',
            'date_field': 'LastModifiedDate',
            'nested': False,
            'arn_format': 'arn:aws:ssm:{region}:{account_id}:parameter/{name}'
        },
        'Document': {
            'method': 'list_documents',
            'key': 'DocumentIdentifiers',
            'id_field': 'Name',
            'name_field': 'Name',
            'date_field': 'CreatedDate',
            'nested': False,
            'arn_format': 'arn:aws:ssm:{region}:{account_id}:document/{name}'
        },
        'MaintenanceWindow': {
            'method': 'describe_maintenance_windows',
            'key': 'WindowIdentities',
            'id_field': 'WindowId',
            'name_field': 'Name',
            'date_field': 'CreatedDate',
            'nested': False,
            'arn_format': 'arn:aws:ssm:{region}:{account_id}:maintenancewindow/{id}'
        },
        'PatchBaseline': {
            'method': 'describe_patch_baselines',
            'key': 'BaselineIdentities',
            'id_field': 'BaselineId',
            'name_field': 'BaselineName',
            'date_field': 'CreatedDate',
            'nested': False,
            'arn_format': 'arn:aws:ssm:{region}:{account_id}:patchbaseline/{id}'
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
        
        # SSM is regional
        client = session.client('ssm', region_name=region)
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for ssm client")

        method = getattr(client, config['method'])
        params = {}

        # Add filters for specific resource types
        if service_type == 'Document':
            # Only get documents owned by the account (not AWS managed)
            params['Filters'] = [{'Key': 'Owner', 'Values': ['Self']}]

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
                resource_name = item.get(config['name_field'], resource_id) if config['name_field'] else resource_id

                # Get creation date
                creation_date = None
                if config['date_field'] and config['date_field'] in item:
                    creation_date = item[config['date_field']]
                    if hasattr(creation_date, 'isoformat'):
                        creation_date = creation_date.isoformat()

                # Build ARN
                if config['arn_format']:
                    if service_type in ['MaintenanceWindow', 'PatchBaseline']:
                        arn = config['arn_format'].format(region=region, account_id=account_id, id=resource_id)
                    else:
                        # For Parameter and Document, use name
                        name_for_arn = resource_name
                        if service_type == 'Parameter' and not resource_name.startswith('/'):
                            name_for_arn = '/' + resource_name
                        arn = config['arn_format'].format(region=region, account_id=account_id, name=name_for_arn)
                else:
                    arn = f"arn:aws:ssm:{region}:{account_id}:{service_type.lower()}:{resource_id}"

                # Get additional metadata for specific resource types
                additional_metadata = {}
                if service_type == 'Parameter':
                    additional_metadata = {
                        'Type': item.get('Type', 'String'),
                        'Tier': item.get('Tier', 'Standard'),
                        'Version': item.get('Version', 1),
                        'DataType': item.get('DataType', 'text')
                    }
                elif service_type == 'Document':
                    additional_metadata = {
                        'DocumentType': item.get('DocumentType', 'Command'),
                        'DocumentFormat': item.get('DocumentFormat', 'YAML'),
                        'DocumentVersion': item.get('DocumentVersion', '1'),
                        'PlatformTypes': item.get('PlatformTypes', [])
                    }
                elif service_type == 'MaintenanceWindow':
                    additional_metadata = {
                        'Enabled': item.get('Enabled', False),
                        'Duration': item.get('Duration', 0),
                        'Cutoff': item.get('Cutoff', 0),
                        'Schedule': item.get('Schedule', ''),
                        'NextExecutionTime': item.get('NextExecutionTime', '')
                    }
                elif service_type == 'PatchBaseline':
                    additional_metadata = {
                        'OperatingSystem': item.get('OperatingSystem', 'WINDOWS'),
                        'BaselineDescription': item.get('BaselineDescription', '')
                    }

                # Get existing tags
                resource_tags = {}
                try:
                    # SSM uses different resource types for tagging
                    resource_type_mapping = {
                        'Parameter': 'Parameter',
                        'Document': 'Document',
                        'MaintenanceWindow': 'MaintenanceWindow',
                        'PatchBaseline': 'PatchBaseline'
                    }
                    
                    tags_response = client.list_tags_for_resource(
                        ResourceType=resource_type_mapping[service_type],
                        ResourceId=resource_id
                    )
                    tags_list = tags_response.get('TagList', [])
                    # Convert list of tag objects to dict
                    resource_tags = {tag['Key']: tag['Value'] for tag in tags_list}
                except Exception as tag_error:
                    logger.warning(f"Could not retrieve tags for {resource_id}: {tag_error}")
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

    # Create SSM client
    session = boto3.Session()
    ssm_client = session.client('ssm', region_name=region)

    # Resource type mapping for SSM tagging
    resource_type_mapping = {
        'Parameter': 'Parameter',
        'Document': 'Document',
        'MaintenanceWindow': 'MaintenanceWindow',
        'PatchBaseline': 'PatchBaseline'
    }

    for resource in resources:            
        try:
            resource_type_for_tagging = resource_type_mapping.get(resource.resource_type)
            if not resource_type_for_tagging:
                raise ValueError(f"Unsupported resource type for tagging: {resource.resource_type}")

            if tags_action == 1:
                # Add tags - Convert to SSM format (list of objects)
                ssm_tags = [{'Key': tag['Key'], 'Value': tag['Value']} for tag in tags]
                ssm_client.add_tags_to_resource(
                    ResourceType=resource_type_for_tagging,
                    ResourceId=resource.identifier,
                    Tags=ssm_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                ssm_client.remove_tags_from_resource(
                    ResourceType=resource_type_for_tagging,
                    ResourceId=resource.identifier,
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

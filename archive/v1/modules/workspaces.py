import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    resource_configs = {
        'Workspace': {
            'method': 'describe_workspaces',
            'key': 'Workspaces',
            'id_field': 'WorkspaceId',
            'name_field': None,  # WorkSpaces doesn't have a direct name field
            'date_field': None,  # No direct creation date in main response
            'nested': False,
            'arn_format': 'arn:aws:workspaces:{region}:{account_id}:workspace/{resource_id}'
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
        client = session.client('workspaces', region_name=region)
        method = getattr(client, config['method'])
        
        try:
            # List all WorkSpaces - note some regions may not have WorkSpaces
            paginator = client.get_paginator(config['method'])
            response_iterator = paginator.paginate()
        except OperationNotPageableError:
            response_iterator = [method()]

        for page in response_iterator:
            workspaces = page[config['key']]

            for workspace in workspaces:
                resource_id = workspace[config['id_field']]
                
                # Construct the ARN for the workspace
                arn = config['arn_format'].format(
                    region=region, 
                    account_id=account_id,
                    resource_id=resource_id
                )
                
                # Get tags for the workspace
                resource_tags = {}
                try:
                    tags_response = client.describe_tags(ResourceId=resource_id)
                    # Convert the tag list to a dict for consistency
                    for tag in tags_response.get('TagList', []):
                        if 'Key' in tag and 'Value' in tag:
                            resource_tags[tag['Key']] = tag['Value']
                except Exception as tag_error:
                    logger.warning(f"Could not get tags for WorkSpace {resource_id}: {str(tag_error)}")
                
                # Try to get a useful name (username or computed name)
                name_tag = resource_tags.get('Name', '')
                
                # If no Name tag, use UserName or DirectoryId + ComputerName
                if not name_tag:
                    user_name = workspace.get('UserName', '')
                    if user_name:
                        name_tag = user_name
                    else:
                        directory_id = workspace.get('DirectoryId', '')
                        computer_name = workspace.get('ComputerName', '')
                        if directory_id and computer_name:
                            name_tag = f"{directory_id}/{computer_name}"
                        else:
                            name_tag = resource_id
                
                # Get additional details - we'll try to get creation time and bundle details
                creation_date = ''
                bundle_details = {}
                try:
                    bundle_id = workspace.get('BundleId', '')
                    if bundle_id:
                        detail_response = client.describe_workspace_bundles(
                            BundleIds=[bundle_id]
                        )
                        if detail_response.get('Bundles') and len(detail_response.get('Bundles')) > 0:
                            # Some bundles have CreationTime
                            bundle = detail_response['Bundles'][0]
                            bundle_details = bundle
                            if 'CreationTime' in bundle:
                                creation_date = bundle['CreationTime']
                except Exception as detail_error:
                    logger.warning(f"Could not get bundle details for WorkSpace {resource_id}: {str(detail_error)}")
                
                # Get directory details
                directory_details = {}
                try:
                    directory_id = workspace.get('DirectoryId', '')
                    if directory_id:
                        dir_response = client.describe_workspace_directories(
                            DirectoryIds=[directory_id]
                        )
                        if dir_response.get('Directories') and len(dir_response.get('Directories')) > 0:
                            directory_details = dir_response['Directories'][0]
                except Exception as dir_error:
                    logger.warning(f"Could not get directory details for WorkSpace {resource_id}: {str(dir_error)}")
                
                # Include all workspace information in metadata
                # This includes the original workspace object + additional details we fetched
                metadata = workspace.copy()  # Start with all fields from describe_workspaces
                
                # Add additional details we fetched
                metadata.update({
                    'BundleDetails': bundle_details,
                    'DirectoryDetails': directory_details,
                    'TagDetails': tags_response if 'tags_response' in locals() else {}
                })

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
                    "metadata": metadata,
                    "arn": arn
                })

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources

def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    logger.info(f'Tagging # Account: {account_id}, Region: {region}, Service: {service}')
    
    results = []
    tags = parse_tags_for_workspaces(tags_string)  # Special format for WorkSpaces
    
    for resource in resources:
        try:
            resource_id = resource.identifier
            
            if tags_action == 1:  # Add tags
                client.create_tags(
                    ResourceId=resource_id,  # WorkSpaces uses ResourceId, not ARN
                    Tags=tags
                )
            elif tags_action == 2:  # Remove tags
                # For delete, we need the keys
                tag_keys = [tag['Key'] for tag in tags]
                client.delete_tags(
                    ResourceId=resource_id,
                    TagKeys=tag_keys
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
    """Standard parse_tags function (returns list of Key-Value dicts)"""
    tags = []
    for tag_pair in tags_string.split(','):
        key, value = tag_pair.split(':')
        tags.append({
            'Key': key.strip(),
            'Value': value.strip()
        })
    return tags

def parse_tags_for_workspaces(tags_string: str) -> List[Dict[str, str]]:
    """WorkSpaces-specific parse_tags function"""
    # WorkSpaces uses the same tag format as most services, so we can reuse the standard function
    return parse_tags(tags_string)
import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError, ClientError, ConnectTimeoutError, ReadTimeoutError
from botocore.config import Config

def get_service_types(account_id, region, service, service_type):
    """
    AWS Storage Gateway resources that support tagging.
    
    Based on AWS Storage Gateway documentation:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/storagegateway.html
    
    Storage Gateway supports tagging for:
    - Gateway (Storage Gateway appliances - File, Volume, Tape gateways)
    - Volume (iSCSI volumes - both cached and stored)
    - FileShare (NFS and SMB file shares)
    - Tape (Virtual Tape Library tapes)
    - TapePool (Custom tape pools)
    - FileSystemAssociation (FSx file system associations)
    """

    resource_configs = {
        'Gateway': {
            'method': 'list_gateways',
            'key': 'Gateways',
            'id_field': 'GatewayARN',
            'name_field': 'GatewayName',
            'date_field': None,
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'describe_method': 'describe_gateway_information',
            'describe_param': 'GatewayARN'
        },
        'Volume': {
            'method': 'list_volumes',
            'key': 'VolumeInfos',
            'id_field': 'VolumeARN',
            'name_field': 'VolumeId',
            'date_field': None,
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'describe_method': None  # Use describe_cached_iscsi_volumes or describe_stored_iscsi_volumes
        },
        'FileShare': {
            'method': 'list_file_shares',
            'key': 'FileShareInfoList',
            'id_field': 'FileShareARN',
            'name_field': 'FileShareId',
            'date_field': None,
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'describe_method': None  # Use describe_nfs_file_shares or describe_smb_file_shares
        },
        'Tape': {
            'method': 'describe_tapes',
            'key': 'Tapes',
            'id_field': 'TapeARN',
            'name_field': 'TapeBarcode',
            'date_field': 'TapeCreatedDate',
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'requires_gateway': True
        },
        'TapePool': {
            'method': 'list_tape_pools',
            'key': 'PoolInfos',
            'id_field': 'PoolARN',
            'name_field': 'PoolName',
            'date_field': None,
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'FileSystemAssociation': {
            'method': 'describe_file_system_associations',
            'key': 'FileSystemAssociationInfoList',
            'id_field': 'FileSystemAssociationARN',
            'name_field': 'FileSystemAssociationId',
            'date_field': None,
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'requires_gateway': True
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
        
        try:
            client = session.client('storagegateway', region_name=region, config=client_config)
        except Exception as e:
            logger.warning(f"Storage Gateway client creation failed in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        
        if not hasattr(client, config['method']):
            logger.warning(f"Method {config['method']} not available for storagegateway client")
            return f'{service}:{service_type}', "success", "", []

        method = getattr(client, config['method'])
        params = {}
        
        # Special handling for resources that require gateway ARNs
        if config.get('requires_gateway', False):
            # First get list of gateways
            try:
                gateways_response = client.list_gateways()
                gateway_arns = [gw['GatewayARN'] for gw in gateways_response.get('Gateways', [])]
                if not gateway_arns:
                    logger.info(f"No gateways found for {service_type} discovery")
                    return f'{service}:{service_type}', "success", "", []
                
                if service_type == 'Tape':
                    # For tapes, we need to call describe_tapes for each gateway
                    all_items = []
                    for gateway_arn in gateway_arns:
                        try:
                            response = method(GatewayARN=gateway_arn)
                            all_items.extend(response.get(config['key'], []))
                        except Exception as gw_error:
                            logger.warning(f"Error getting tapes for gateway {gateway_arn}: {gw_error}")
                            continue
                    page_iterator = [{'Tapes': all_items}]
                elif service_type == 'FileSystemAssociation':
                    # For file system associations, we need gateway ARNs as parameter
                    all_items = []
                    for gateway_arn in gateway_arns:
                        try:
                            response = method(FileSystemAssociationARNList=[])  # Get all associations
                            all_items.extend(response.get(config['key'], []))
                        except Exception as gw_error:
                            logger.warning(f"Error getting file system associations: {gw_error}")
                            continue
                    page_iterator = [{'FileSystemAssociationInfoList': all_items}]
            except Exception as gateway_error:
                logger.warning(f"Error listing gateways for {service_type}: {gateway_error}")
                return f'{service}:{service_type}', "success", "", []
        else:
            # Handle Storage Gateway API calls with proper error handling
            try:
                logger.info(f"Calling Storage Gateway {config['method']} in region {region}")
                
                # Handle pagination
                try:
                    paginator = client.get_paginator(config['method'])
                    page_iterator = paginator.paginate(**params)
                except OperationNotPageableError:
                    response = method(**params)
                    page_iterator = [response]
                    
            except (ConnectTimeoutError, ReadTimeoutError) as e:
                logger.warning(f"Storage Gateway timeout in region {region}: {str(e)}")
                return f'{service}:{service_type}', "success", "", []
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                if error_code in ['UnauthorizedOperation', 'AccessDenied', 'InvalidAction']:
                    logger.warning(f"Storage Gateway not available in region {region}: {error_code}")
                    return f'{service}:{service_type}', "success", "", []
                else:
                    logger.error(f"Storage Gateway API error in region {region}: {str(e)}")
                    return f'{service}:{service_type}', "error", str(e), []
            except Exception as e:
                logger.warning(f"Storage Gateway general error in region {region}: {str(e)}")
                return f'{service}:{service_type}', "success", "", []

        # Process results
        for page in page_iterator:
            items = page.get(config['key'], [])

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

                    # ARN is provided directly in Storage Gateway
                    arn = resource_id

                    # Get existing tags
                    resource_tags = {}
                    try:
                        tags_response = client.list_tags_for_resource(ResourceARN=arn)
                        tags_list = tags_response.get('Tags', [])
                        # Convert Storage Gateway tag format to standard format
                        resource_tags = {tag.get('Key', ''): tag.get('Value', '') for tag in tags_list}
                    except (ConnectTimeoutError, ReadTimeoutError):
                        logger.warning(f"Timeout retrieving tags for Storage Gateway resource {resource_name}")
                        resource_tags = {}
                    except Exception as tag_error:
                        logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                        resource_tags = {}

                    # Get additional metadata based on resource type
                    additional_metadata = {}
                    if service_type == 'Gateway':
                        additional_metadata = {
                            'GatewayId': item.get('GatewayId', ''),
                            'GatewayType': item.get('GatewayType', ''),
                            'GatewayOperationalState': item.get('GatewayOperationalState', ''),
                            'Ec2InstanceId': item.get('Ec2InstanceId', ''),
                            'Ec2InstanceRegion': item.get('Ec2InstanceRegion', ''),
                            'HostEnvironment': item.get('HostEnvironment', ''),
                            'HostEnvironmentId': item.get('HostEnvironmentId', '')
                        }
                    elif service_type == 'Volume':
                        additional_metadata = {
                            'VolumeId': item.get('VolumeId', ''),
                            'VolumeType': item.get('VolumeType', ''),
                            'VolumeSizeInBytes': item.get('VolumeSizeInBytes', 0),
                            'VolumeAttachmentStatus': item.get('VolumeAttachmentStatus', ''),
                            'GatewayARN': item.get('GatewayARN', ''),
                            'GatewayId': item.get('GatewayId', '')
                        }
                    elif service_type == 'FileShare':
                        additional_metadata = {
                            'FileShareId': item.get('FileShareId', ''),
                            'FileShareType': item.get('FileShareType', ''),
                            'FileShareStatus': item.get('FileShareStatus', ''),
                            'GatewayARN': item.get('GatewayARN', '')
                        }
                    elif service_type == 'Tape':
                        additional_metadata = {
                            'TapeBarcode': item.get('TapeBarcode', ''),
                            'TapeSizeInBytes': item.get('TapeSizeInBytes', 0),
                            'TapeStatus': item.get('TapeStatus', ''),
                            'VTLDevice': item.get('VTLDevice', ''),
                            'Progress': item.get('Progress', 0.0),
                            'TapeUsedInBytes': item.get('TapeUsedInBytes', 0),
                            'KMSKey': item.get('KMSKey', ''),
                            'PoolId': item.get('PoolId', ''),
                            'Worm': item.get('Worm', False),
                            'RetentionStartDate': item.get('RetentionStartDate', ''),
                            'PoolEntryDate': item.get('PoolEntryDate', '')
                        }
                    elif service_type == 'TapePool':
                        additional_metadata = {
                            'PoolName': item.get('PoolName', ''),
                            'StorageClass': item.get('StorageClass', ''),
                            'RetentionLockType': item.get('RetentionLockType', ''),
                            'RetentionLockTimeInDays': item.get('RetentionLockTimeInDays', 0),
                            'PoolStatus': item.get('PoolStatus', '')
                        }
                    elif service_type == 'FileSystemAssociation':
                        additional_metadata = {
                            'FileSystemAssociationId': item.get('FileSystemAssociationId', ''),
                            'LocationARN': item.get('LocationARN', ''),
                            'FileSystemAssociationStatus': item.get('FileSystemAssociationStatus', ''),
                            'AuditDestinationARN': item.get('AuditDestinationARN', ''),
                            'GatewayARN': item.get('GatewayARN', ''),
                            'CacheAttributes': item.get('CacheAttributes', {}),
                            'EndpointNetworkConfiguration': item.get('EndpointNetworkConfiguration', {}),
                            'FileSystemAssociationStatusDetails': item.get('FileSystemAssociationStatusDetails', [])
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
                    logger.warning(f"Error processing Storage Gateway item: {str(item_error)}")
                    continue

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} {service_type.lower()}s')

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in Storage Gateway discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources


def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    if tags_action == 2:        
        tag_keys = [item['Key'] for item in tags]

    # Create Storage Gateway client with timeout protection
    session = boto3.Session()
    client_config = Config(
        read_timeout=15,
        connect_timeout=10,
        retries={'max_attempts': 2, 'mode': 'standard'}
    )
    
    try:
        storagegateway_client = session.client('storagegateway', region_name=region, config=client_config)
    except Exception as e:
        logger.error(f"Failed to create Storage Gateway client: {str(e)}")
        return []

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to Storage Gateway format (list of objects)
                storagegateway_tags = [{'Key': tag['Key'], 'Value': tag['Value']} for tag in tags]
                storagegateway_client.add_tags_to_resource(
                    ResourceARN=resource.arn,
                    Tags=storagegateway_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                storagegateway_client.remove_tags_from_resource(
                    ResourceARN=resource.arn,
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

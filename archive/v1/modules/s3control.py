import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError, ClientError, ConnectTimeoutError, ReadTimeoutError
from botocore.config import Config

def get_service_types(account_id, region, service, service_type):
    """
    AWS S3 Control resources that support tagging.
    
    S3 Control supports tagging for:
    - AccessPoint (S3 Access Points)
    - MultiRegionAccessPoint (Multi-Region Access Points)
    - Job (S3 Batch Operations jobs)
    - StorageLensConfiguration (S3 Storage Lens configurations)
    - StorageLensGroup (S3 Storage Lens groups)
    - AccessGrant (S3 Access Grants)
    - AccessGrantsInstance (S3 Access Grants instances)
    - AccessGrantsLocation (S3 Access Grants locations)
    """

    resource_configs = {
        'AccessPoint': {
            'method': 'list_access_points',
            'key': 'AccessPointList',
            'id_field': 'Name',
            'name_field': 'Name',
            'date_field': 'CreationDate',
            'nested': False,
            'arn_format': 'arn:aws:s3:{region}:{account_id}:accesspoint/{resource_id}',
            'requires_account_id': True
        },
        'MultiRegionAccessPoint': {
            'method': 'list_multi_region_access_points',
            'key': 'AccessPoints',
            'id_field': 'Name',
            'name_field': 'Name',
            'date_field': 'CreatedAt',
            'nested': False,
            'arn_format': 'arn:aws:s3::{account_id}:accesspoint/{resource_id}',
            'requires_account_id': True,
            'supported_regions': ['us-west-2']  # Only available in specific regions
        },
        'Job': {
            'method': 'list_jobs',
            'key': 'Jobs',
            'id_field': 'JobId',
            'name_field': 'JobId',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': 'arn:aws:s3:{region}:{account_id}:job/{resource_id}',
            'requires_account_id': True
        },
        'StorageLensConfiguration': {
            'method': 'list_storage_lens_configurations',
            'key': 'StorageLensConfigurationList',
            'id_field': 'Id',
            'name_field': 'Id',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:s3:{region}:{account_id}:storage-lens/{resource_id}',
            'requires_account_id': True
        },
        'StorageLensGroup': {
            'method': 'list_storage_lens_groups',
            'key': 'StorageLensGroupList',
            'id_field': 'Name',
            'name_field': 'Name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:s3:{region}:{account_id}:storage-lens-group/{resource_id}',
            'requires_account_id': True
        },
        'AccessGrant': {
            'method': 'list_access_grants',
            'key': 'AccessGrantsList',
            'id_field': 'AccessGrantId',
            'name_field': 'AccessGrantId',
            'date_field': 'CreatedAt',
            'nested': False,
            'arn_format': 'arn:aws:s3:{region}:{account_id}:access-grant/{resource_id}',
            'requires_account_id': True,
            'requires_instance': True  # Requires Access Grants Instance
        },
        'AccessGrantsInstance': {
            'method': 'list_access_grants_instances',
            'key': 'AccessGrantsInstancesList',
            'id_field': 'AccessGrantsInstanceArn',
            'name_field': 'AccessGrantsInstanceId',
            'date_field': 'CreatedAt',
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'requires_account_id': True
        },
        'AccessGrantsLocation': {
            'method': 'list_access_grants_locations',
            'key': 'AccessGrantsLocationsList',
            'id_field': 'AccessGrantsLocationId',
            'name_field': 'AccessGrantsLocationId',
            'date_field': 'CreatedAt',
            'nested': False,
            'arn_format': 'arn:aws:s3:{region}:{account_id}:access-grants-location/{resource_id}',
            'requires_account_id': True,
            'requires_instance': True  # Requires Access Grants Instance
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
        
        # Check if this resource type is supported in this region
        if 'supported_regions' in config and region not in config['supported_regions']:
            logger.info(f"S3 Control {service_type} not supported in region {region}")
            return f'{service}:{service_type}', "success", "", []
        
        # Configure client with timeouts
        client_config = Config(
            read_timeout=15,
            connect_timeout=10,
            retries={'max_attempts': 2, 'mode': 'standard'}
        )
        
        try:
            client = session.client('s3control', region_name=region, config=client_config)
        except Exception as e:
            logger.warning(f"S3 Control client creation failed in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        
        if not hasattr(client, config['method']):
            logger.warning(f"Method {config['method']} not available for s3control client")
            return f'{service}:{service_type}', "success", "", []

        method = getattr(client, config['method'])
        params = {}
        
        # Add account ID parameter if required
        if config.get('requires_account_id', False):
            params['AccountId'] = account_id

        # Handle S3 Control API calls with proper error handling
        try:
            logger.info(f"Calling S3 Control {config['method']} in region {region}")
            
            # Handle pagination
            try:
                paginator = client.get_paginator(config['method'])
                page_iterator = paginator.paginate(**params)
            except OperationNotPageableError:
                response = method(**params)
                page_iterator = [response]
                
        except (ConnectTimeoutError, ReadTimeoutError) as e:
            logger.warning(f"S3 Control timeout in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code in ['UnauthorizedOperation', 'AccessDenied', 'InvalidAction', 'PermanentRedirect']:
                logger.warning(f"S3 Control {service_type} not available in region {region}: {error_code}")
                return f'{service}:{service_type}', "success", "", []
            elif error_code in ['AccessGrantsInstanceNotExistsError', 'NoSuchAccessGrantsInstance']:
                logger.info(f"S3 Control {service_type} requires Access Grants Instance which doesn't exist")
                return f'{service}:{service_type}', "success", "", []
            elif error_code in ['NoSuchConfiguration', 'ConfigurationNotFound']:
                logger.info(f"S3 Control {service_type} configuration not found")
                return f'{service}:{service_type}', "success", "", []
            else:
                logger.error(f"S3 Control API error in region {region}: {str(e)}")
                return f'{service}:{service_type}', "error", str(e), []
        except Exception as e:
            logger.warning(f"S3 Control general error in region {region}: {str(e)}")
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

                    # Build ARN
                    if config['arn_format']:
                        arn = config['arn_format'].format(
                            region=region,
                            account_id=account_id,
                            resource_id=resource_id
                        )
                    else:
                        arn = resource_id  # ARN is provided directly

                    # Get existing tags based on resource type
                    resource_tags = {}
                    try:
                        if service_type == 'Job':
                            tags_response = client.get_job_tagging(AccountId=account_id, JobId=resource_id)
                            tags_list = tags_response.get('Tags', [])
                            resource_tags = {tag.get('Key', ''): tag.get('Value', '') for tag in tags_list}
                        elif service_type == 'StorageLensConfiguration':
                            tags_response = client.get_storage_lens_configuration_tagging(
                                ConfigId=resource_id, AccountId=account_id
                            )
                            tags_list = tags_response.get('Tags', [])
                            resource_tags = {tag.get('Key', ''): tag.get('Value', '') for tag in tags_list}
                        elif service_type == 'AccessPoint':
                            # Access Points may have tags in the response or need separate call
                            if 'Tags' in item:
                                resource_tags = {tag.get('Key', ''): tag.get('Value', '') for tag in item.get('Tags', [])}
                            else:
                                resource_tags = {}
                        else:
                            # For other resource types, check if tags are included in the list response
                            if 'Tags' in item:
                                tags_list = item.get('Tags', [])
                                resource_tags = {tag.get('Key', ''): tag.get('Value', '') for tag in tags_list}
                            else:
                                resource_tags = {}
                            
                    except (ConnectTimeoutError, ReadTimeoutError):
                        logger.warning(f"Timeout retrieving tags for S3 Control resource {resource_name}")
                        resource_tags = {}
                    except ClientError as tag_error:
                        tag_error_code = tag_error.response.get('Error', {}).get('Code', 'Unknown')
                        if tag_error_code in ['NoSuchTagSet', 'NoSuchConfiguration']:
                            logger.info(f"No tags found for S3 Control resource {resource_name}")
                            resource_tags = {}
                        else:
                            logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                            resource_tags = {}
                    except Exception as tag_error:
                        logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                        resource_tags = {}

                    # Get additional metadata based on resource type
                    additional_metadata = {}
                    if service_type == 'AccessPoint':
                        additional_metadata = {
                            'Bucket': item.get('Bucket', ''),
                            'VpcConfiguration': item.get('VpcConfiguration', {}),
                            'AccessPointArn': item.get('AccessPointArn', ''),
                            'Alias': item.get('Alias', ''),
                            'BucketAccountId': item.get('BucketAccountId', '')
                        }
                    elif service_type == 'Job':
                        additional_metadata = {
                            'Operation': item.get('Operation', ''),
                            'Priority': item.get('Priority', 0),
                            'Status': item.get('Status', ''),
                            'ProgressSummary': item.get('ProgressSummary', {}),
                            'StatusUpdateReason': item.get('StatusUpdateReason', ''),
                            'FailureReasons': item.get('FailureReasons', []),
                            'Report': item.get('Report', {}),
                            'CreationTime': item.get('CreationTime', ''),
                            'TerminationDate': item.get('TerminationDate', ''),
                            'RoleArn': item.get('RoleArn', ''),
                            'SuspendedDate': item.get('SuspendedDate', ''),
                            'SuspendedCause': item.get('SuspendedCause', '')
                        }
                    elif service_type == 'StorageLensConfiguration':
                        additional_metadata = {
                            'StorageLensArn': item.get('StorageLensArn', ''),
                            'HomeRegion': item.get('HomeRegion', ''),
                            'IsEnabled': item.get('IsEnabled', False)
                        }
                    elif service_type == 'MultiRegionAccessPoint':
                        additional_metadata = {
                            'Alias': item.get('Alias', ''),
                            'Status': item.get('Status', ''),
                            'PublicAccessBlock': item.get('PublicAccessBlock', {}),
                            'Regions': item.get('Regions', [])
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
                    logger.warning(f"Error processing S3 Control item: {str(item_error)}")
                    continue

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} {service_type.lower()}s')

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in S3 Control discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources


def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    if tags_action == 2:        
        tag_keys = [item['Key'] for item in tags]

    # Create S3 Control client with timeout protection
    session = boto3.Session()
    client_config = Config(
        read_timeout=15,
        connect_timeout=10,
        retries={'max_attempts': 2, 'mode': 'standard'}
    )
    
    try:
        s3control_client = session.client('s3control', region_name=region, config=client_config)
    except Exception as e:
        logger.error(f"Failed to create S3 Control client: {str(e)}")
        return []

    for resource in resources:            
        try:
            resource_type = resource.resource_type
            resource_id = resource.identifier
            
            if tags_action == 1:
                # Add tags - Different methods for different resource types
                s3control_tags = [{'Key': tag['Key'], 'Value': tag['Value']} for tag in tags]
                
                if resource_type == 'Job':
                    s3control_client.put_job_tagging(
                        AccountId=account_id,
                        JobId=resource_id,
                        Tags=s3control_tags
                    )
                elif resource_type == 'StorageLensConfiguration':
                    s3control_client.put_storage_lens_configuration_tagging(
                        ConfigId=resource_id,
                        AccountId=account_id,
                        Tags=s3control_tags
                    )
                elif resource_type == 'AccessPoint':
                    s3control_client.put_access_point_tagging(
                        AccountId=account_id,
                        Name=resource_id,
                        Tagging={'TagSet': s3control_tags}
                    )
                # Note: Other resource types may need different tagging methods
                        
            elif tags_action == 2:
                # Remove tags
                if resource_type == 'Job':
                    s3control_client.delete_job_tagging(
                        AccountId=account_id,
                        JobId=resource_id
                    )
                elif resource_type == 'StorageLensConfiguration':
                    s3control_client.delete_storage_lens_configuration_tagging(
                        ConfigId=resource_id,
                        AccountId=account_id
                    )
                elif resource_type == 'AccessPoint':
                    s3control_client.delete_access_point_tagging(
                        AccountId=account_id,
                        Name=resource_id
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

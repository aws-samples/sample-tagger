import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError, ClientError, ConnectTimeoutError, ReadTimeoutError
from botocore.config import Config

def get_service_types(account_id, region, service, service_type):
    """
    AWS CloudHSMv2 resources that support tagging.
    
    CloudHSMv2 supports tagging for:
    - Cluster (CloudHSM clusters)
    - Backup (CloudHSM backups)
    """

    resource_configs = {
        'Cluster': {
            'method': 'describe_clusters',
            'key': 'Clusters',
            'id_field': 'ClusterId',
            'name_field': 'ClusterId',
            'date_field': 'CreateTimestamp',
            'nested': False,
            'arn_format': 'arn:aws:cloudhsmv2:{region}:{account_id}:cluster/{resource_id}'
        },
        'Backup': {
            'method': 'describe_backups',
            'key': 'Backups',
            'id_field': 'BackupId',
            'name_field': 'BackupId',
            'date_field': 'CreateTimestamp',
            'nested': False,
            'arn_format': 'arn:aws:cloudhsmv2:{region}:{account_id}:backup/{resource_id}'
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
            client = session.client('cloudhsmv2', region_name=region, config=client_config)
        except Exception as e:
            logger.warning(f"CloudHSMv2 client creation failed in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        
        if not hasattr(client, config['method']):
            logger.warning(f"Method {config['method']} not available for cloudhsmv2 client")
            return f'{service}:{service_type}', "success", "", []

        method = getattr(client, config['method'])
        params = {}

        # Handle CloudHSMv2 API calls with proper error handling
        try:
            logger.info(f"Calling CloudHSMv2 {config['method']} in region {region}")
            
            # Handle pagination
            try:
                paginator = client.get_paginator(config['method'])
                page_iterator = paginator.paginate(**params)
            except OperationNotPageableError:
                response = method(**params)
                page_iterator = [response]
                
        except (ConnectTimeoutError, ReadTimeoutError) as e:
            logger.warning(f"CloudHSMv2 timeout in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code in ['UnauthorizedOperation', 'AccessDenied', 'InvalidAction']:
                logger.warning(f"CloudHSMv2 not available in region {region}: {error_code}")
                return f'{service}:{service_type}', "success", "", []
            else:
                logger.error(f"CloudHSMv2 API error in region {region}: {str(e)}")
                return f'{service}:{service_type}', "error", str(e), []
        except Exception as e:
            logger.warning(f"CloudHSMv2 general error in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []

        # Process results
        for page in page_iterator:
            items = page.get(config['key'], [])

            for item in items:
                try:
                    resource_id = item[config['id_field']]
                    resource_name = item.get(config['name_field'], resource_id)

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
                        arn = resource_id

                    # Get existing tags
                    resource_tags = {}
                    try:
                        tags_response = client.list_tags(ResourceId=arn)
                        tags_list = tags_response.get('TagList', [])
                        resource_tags = {tag.get('Key', ''): tag.get('Value', '') for tag in tags_list}
                    except (ConnectTimeoutError, ReadTimeoutError):
                        logger.warning(f"Timeout retrieving tags for CloudHSMv2 resource {resource_name}")
                        resource_tags = {}
                    except Exception as tag_error:
                        logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                        resource_tags = {}

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
                        "metadata": item,
                        "arn": arn
                    })
                except Exception as item_error:
                    logger.warning(f"Error processing CloudHSMv2 item: {str(item_error)}")
                    continue

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} {service_type.lower()}s')

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in CloudHSMv2 discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources


def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    if tags_action == 2:        
        tag_keys = [item['Key'] for item in tags]

    # Create CloudHSMv2 client with timeout protection
    session = boto3.Session()
    client_config = Config(
        read_timeout=15,
        connect_timeout=10,
        retries={'max_attempts': 2, 'mode': 'standard'}
    )
    
    try:
        cloudhsmv2_client = session.client('cloudhsmv2', region_name=region, config=client_config)
    except Exception as e:
        logger.error(f"Failed to create CloudHSMv2 client: {str(e)}")
        return []

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags
                cloudhsmv2_tags = [{'Key': tag['Key'], 'Value': tag['Value']} for tag in tags]
                cloudhsmv2_client.tag_resource(
                    ResourceId=resource.arn,
                    TagList=cloudhsmv2_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                cloudhsmv2_client.untag_resource(
                    ResourceId=resource.arn,
                    TagKeyList=tag_keys
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

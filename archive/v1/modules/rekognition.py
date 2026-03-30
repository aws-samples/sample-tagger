import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError, ClientError, ConnectTimeoutError, ReadTimeoutError
from botocore.config import Config

def get_service_types(account_id, region, service, service_type):
    """
    Amazon Rekognition resources that support tagging.
    
    Rekognition supports tagging for:
    - Collection (Face collections for face recognition)
    - Project (Custom Labels projects for custom model training)
    - StreamProcessor (Stream processors for real-time analysis)
    """

    resource_configs = {
        'Collection': {
            'method': 'list_collections',
            'key': 'CollectionIds',
            'id_field': None,  # Collections are returned as simple strings
            'name_field': None,
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:rekognition:{region}:{account_id}:collection/{resource_id}'
        },
        'Project': {
            'method': 'describe_projects',
            'key': 'ProjectDescriptions',
            'id_field': 'ProjectArn',
            'name_field': 'ProjectName',
            'date_field': 'CreationTimestamp',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'StreamProcessor': {
            'method': 'list_stream_processors',
            'key': 'StreamProcessors',
            'id_field': 'StreamProcessorArn',
            'name_field': 'Name',
            'date_field': None,
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
        
        # Configure client with timeouts
        client_config = Config(
            read_timeout=15,
            connect_timeout=10,
            retries={'max_attempts': 2, 'mode': 'standard'}
        )
        
        try:
            client = session.client('rekognition', region_name=region, config=client_config)
        except Exception as e:
            logger.warning(f"Rekognition client creation failed in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        
        if not hasattr(client, config['method']):
            logger.warning(f"Method {config['method']} not available for rekognition client")
            return f'{service}:{service_type}', "success", "", []

        method = getattr(client, config['method'])
        params = {}

        # Handle Rekognition API calls with proper error handling
        try:
            logger.info(f"Calling Rekognition {config['method']} in region {region}")
            
            # Handle pagination
            try:
                paginator = client.get_paginator(config['method'])
                page_iterator = paginator.paginate(**params)
            except OperationNotPageableError:
                response = method(**params)
                page_iterator = [response]
                
        except (ConnectTimeoutError, ReadTimeoutError) as e:
            logger.warning(f"Rekognition timeout in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code in ['UnauthorizedOperation', 'AccessDenied', 'InvalidAction']:
                logger.warning(f"Rekognition not available in region {region}: {error_code}")
                return f'{service}:{service_type}', "success", "", []
            else:
                logger.error(f"Rekognition API error in region {region}: {str(e)}")
                return f'{service}:{service_type}', "error", str(e), []
        except Exception as e:
            logger.warning(f"Rekognition general error in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []

        # Process results
        for page in page_iterator:
            if service_type == 'Collection':
                # Collections are returned as simple strings
                items = page.get(config['key'], [])
                for collection_id in items:
                    try:
                        resource_id = collection_id
                        resource_name = collection_id

                        # Build ARN
                        arn = config['arn_format'].format(
                            region=region,
                            account_id=account_id,
                            resource_id=resource_id
                        )

                        # Get collection details
                        try:
                            collection_details = client.describe_collection(CollectionId=collection_id)
                            creation_date = collection_details.get('CreationTimestamp')
                            if hasattr(creation_date, 'isoformat'):
                                creation_date = creation_date.isoformat()
                            metadata = collection_details
                        except Exception as detail_error:
                            logger.warning(f"Could not get details for collection {collection_id}: {detail_error}")
                            creation_date = None
                            metadata = {'CollectionId': collection_id}

                        # Get existing tags
                        resource_tags = {}
                        try:
                            tags_response = client.list_tags_for_resource(ResourceArn=arn)
                            tags_dict = tags_response.get('Tags', {})
                            resource_tags = tags_dict
                        except (ConnectTimeoutError, ReadTimeoutError):
                            logger.warning(f"Timeout retrieving tags for Rekognition collection {resource_name}")
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
                            "metadata": metadata,
                            "arn": arn
                        })
                    except Exception as item_error:
                        logger.warning(f"Error processing Rekognition collection {collection_id}: {str(item_error)}")
                        continue
            else:
                # Projects and StreamProcessors are returned as objects
                items = page.get(config['key'], [])
                for item in items:
                    try:
                        if config['id_field']:
                            resource_id = item[config['id_field']]
                        else:
                            resource_id = item
                            
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
                            arn = resource_id

                        # Get existing tags
                        resource_tags = {}
                        try:
                            tags_response = client.list_tags_for_resource(ResourceArn=arn)
                            tags_dict = tags_response.get('Tags', {})
                            resource_tags = tags_dict
                        except (ConnectTimeoutError, ReadTimeoutError):
                            logger.warning(f"Timeout retrieving tags for Rekognition resource {resource_name}")
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
                        logger.warning(f"Error processing Rekognition item: {str(item_error)}")
                        continue

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} {service_type.lower()}s')

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in Rekognition discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources


def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    if tags_action == 2:        
        tag_keys = list(tags.keys()) if isinstance(tags, dict) else [tag['Key'] for tag in tags]

    # Create Rekognition client with timeout protection
    session = boto3.Session()
    client_config = Config(
        read_timeout=15,
        connect_timeout=10,
        retries={'max_attempts': 2, 'mode': 'standard'}
    )
    
    try:
        rekognition_client = session.client('rekognition', region_name=region, config=client_config)
    except Exception as e:
        logger.error(f"Failed to create Rekognition client: {str(e)}")
        return []

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to Rekognition format (dictionary)
                if isinstance(tags, list):
                    rekognition_tags = {tag['Key']: tag['Value'] for tag in tags}
                else:
                    rekognition_tags = tags
                    
                rekognition_client.tag_resource(
                    ResourceArn=resource.arn,
                    Tags=rekognition_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                rekognition_client.untag_resource(
                    ResourceArn=resource.arn,
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
    """Parse tags from string format to dictionary"""
    tags = {}
    if tags_string:
        for tag_pair in tags_string.split(','):
            if ':' in tag_pair:
                key, value = tag_pair.split(':', 1)
                tags[key.strip()] = value.strip()
    return tags

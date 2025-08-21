import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError, ClientError, ConnectTimeoutError, ReadTimeoutError
from botocore.config import Config

def get_service_types(account_id, region, service, service_type):
    """
    AWS App Runner resources that support tagging.
    
    App Runner supports tagging for:
    - Service (App Runner services)
    - AutoScalingConfiguration (Auto scaling configurations)
    - ObservabilityConfiguration (Observability configurations)
    - VpcConnector (VPC connectors)
    - Connection (Source code connections)
    - VpcIngressConnection (VPC ingress connections)
    """

    resource_configs = {
        'Service': {
            'method': 'list_services',
            'key': 'ServiceSummaryList',
            'id_field': 'ServiceArn',
            'name_field': 'ServiceName',
            'date_field': 'CreatedAt',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'AutoScalingConfiguration': {
            'method': 'list_auto_scaling_configurations',
            'key': 'AutoScalingConfigurationSummaryList',
            'id_field': 'AutoScalingConfigurationArn',
            'name_field': 'AutoScalingConfigurationName',
            'date_field': 'CreatedAt',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'ObservabilityConfiguration': {
            'method': 'list_observability_configurations',
            'key': 'ObservabilityConfigurationSummaryList',
            'id_field': 'ObservabilityConfigurationArn',
            'name_field': 'ObservabilityConfigurationName',
            'date_field': 'CreatedAt',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'VpcConnector': {
            'method': 'list_vpc_connectors',
            'key': 'VpcConnectors',
            'id_field': 'VpcConnectorArn',
            'name_field': 'VpcConnectorName',
            'date_field': 'CreatedAt',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'Connection': {
            'method': 'list_connections',
            'key': 'ConnectionSummaryList',
            'id_field': 'ConnectionArn',
            'name_field': 'ConnectionName',
            'date_field': 'CreatedAt',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'VpcIngressConnection': {
            'method': 'list_vpc_ingress_connections',
            'key': 'VpcIngressConnectionSummaryList',
            'id_field': 'VpcIngressConnectionArn',
            'name_field': 'ServiceArn',  # Uses service ARN as name
            'date_field': 'CreatedAt',
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
            client = session.client('apprunner', region_name=region, config=client_config)
        except Exception as e:
            logger.warning(f"App Runner client creation failed in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        
        if not hasattr(client, config['method']):
            logger.warning(f"Method {config['method']} not available for apprunner client")
            return f'{service}:{service_type}', "success", "", []

        method = getattr(client, config['method'])
        params = {}

        # Handle App Runner API calls with proper error handling
        try:
            logger.info(f"Calling App Runner {config['method']} in region {region}")
            
            # Handle pagination
            try:
                paginator = client.get_paginator(config['method'])
                page_iterator = paginator.paginate(**params)
            except OperationNotPageableError:
                response = method(**params)
                page_iterator = [response]
                
        except (ConnectTimeoutError, ReadTimeoutError) as e:
            logger.warning(f"App Runner timeout in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code in ['UnauthorizedOperation', 'AccessDenied', 'InvalidAction']:
                logger.warning(f"App Runner not available in region {region}: {error_code}")
                return f'{service}:{service_type}', "success", "", []
            else:
                logger.error(f"App Runner API error in region {region}: {str(e)}")
                return f'{service}:{service_type}', "error", str(e), []
        except Exception as e:
            logger.warning(f"App Runner general error in region {region}: {str(e)}")
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

                    # Build ARN - App Runner provides ARN directly
                    arn = resource_id

                    # Get additional metadata based on resource type
                    additional_metadata = {}
                    if service_type == 'Service':
                        additional_metadata = {
                            'ServiceId': item.get('ServiceId', ''),
                            'ServiceUrl': item.get('ServiceUrl', ''),
                            'Status': item.get('Status', ''),
                            'UpdatedAt': item.get('UpdatedAt', '').isoformat() if hasattr(item.get('UpdatedAt', ''), 'isoformat') else item.get('UpdatedAt', '')
                        }
                    elif service_type == 'AutoScalingConfiguration':
                        additional_metadata = {
                            'AutoScalingConfigurationRevision': item.get('AutoScalingConfigurationRevision', 0),
                            'Status': item.get('Status', ''),
                            'HasAssociatedService': item.get('HasAssociatedService', False),
                            'IsDefault': item.get('IsDefault', False)
                        }
                    elif service_type == 'ObservabilityConfiguration':
                        additional_metadata = {
                            'ObservabilityConfigurationRevision': item.get('ObservabilityConfigurationRevision', 0),
                            'Status': item.get('Status', '')
                        }
                    elif service_type == 'VpcConnector':
                        additional_metadata = {
                            'Status': item.get('Status', ''),
                            'Subnets': item.get('Subnets', []),
                            'SecurityGroups': item.get('SecurityGroups', [])
                        }
                    elif service_type == 'Connection':
                        additional_metadata = {
                            'ProviderType': item.get('ProviderType', ''),
                            'Status': item.get('Status', '')
                        }
                    elif service_type == 'VpcIngressConnection':
                        additional_metadata = {
                            'Status': item.get('Status', ''),
                            'DomainName': item.get('DomainName', '')
                        }

                    # Get existing tags
                    resource_tags = {}
                    try:
                        tags_response = client.list_tags_for_resource(ResourceArn=arn)
                        tags_list = tags_response.get('Tags', [])
                        # Convert App Runner tag format to standard format
                        resource_tags = {tag.get('Key', ''): tag.get('Value', '') for tag in tags_list}
                    except (ConnectTimeoutError, ReadTimeoutError):
                        logger.warning(f"Timeout retrieving tags for App Runner resource {resource_name}")
                        resource_tags = {}
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
                except Exception as item_error:
                    logger.warning(f"Error processing App Runner item: {str(item_error)}")
                    continue

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} {service_type.lower()}s')

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in App Runner discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources


def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    if tags_action == 2:        
        tag_keys = [item['Key'] for item in tags]

    # Create App Runner client with timeout protection
    session = boto3.Session()
    client_config = Config(
        read_timeout=15,
        connect_timeout=10,
        retries={'max_attempts': 2, 'mode': 'standard'}
    )
    
    try:
        apprunner_client = session.client('apprunner', region_name=region, config=client_config)
    except Exception as e:
        logger.error(f"Failed to create App Runner client: {str(e)}")
        return []

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to App Runner format (list of objects)
                apprunner_tags = [{'Key': tag['Key'], 'Value': tag['Value']} for tag in tags]
                apprunner_client.tag_resource(
                    ResourceArn=resource.arn,
                    Tags=apprunner_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                apprunner_client.untag_resource(
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
    """Parse tags from string format to list of dictionaries"""
    tags = []
    if tags_string:
        for tag_pair in tags_string.split(','):
            if ':' in tag_pair:
                key, value = tag_pair.split(':', 1)
                tags.append({'Key': key.strip(), 'Value': value.strip()})
    return tags

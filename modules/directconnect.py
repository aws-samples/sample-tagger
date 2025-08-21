import json
import boto3
import time
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError, ClientError, ConnectTimeoutError, ReadTimeoutError
from botocore.config import Config

def get_service_types(account_id, region, service, service_type):
    """
    AWS Direct Connect resources that support tagging.
    
    Based on AWS Direct Connect documentation:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/directconnect.html
    
    Direct Connect supports tagging for:
    - Connection (Direct Connect connections)
    - Interconnect (Direct Connect interconnects - requires partner account)
    - LAG (Link Aggregation Groups)
    - VirtualInterface (Virtual interfaces - private, public, transit)
    - DirectConnectGateway (Direct Connect gateways)
    - DirectConnectGatewayAssociation (Gateway associations)
    - DirectConnectGatewayAssociationProposal (Gateway association proposals)
    """

    resource_configs = {
        'Connection': {
            'method': 'describe_connections',
            'key': 'connections',
            'id_field': 'connectionId',
            'name_field': 'connectionName',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:directconnect:{region}:{account_id}:dxcon/{resource_id}',
            'resource_type': 'dxcon'
        },
        'Interconnect': {
            'method': 'describe_interconnects',
            'key': 'interconnects',
            'id_field': 'interconnectId',
            'name_field': 'interconnectName',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:directconnect:{region}:{account_id}:dxcon/{resource_id}',
            'resource_type': 'dxcon',
            'partner_only': True  # Only available for Direct Connect partners
        },
        'LAG': {
            'method': 'describe_lags',
            'key': 'lags',
            'id_field': 'lagId',
            'name_field': 'lagName',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:directconnect:{region}:{account_id}:dxlag/{resource_id}',
            'resource_type': 'dxlag'
        },
        'VirtualInterface': {
            'method': 'describe_virtual_interfaces',
            'key': 'virtualInterfaces',
            'id_field': 'virtualInterfaceId',
            'name_field': 'virtualInterfaceName',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:directconnect:{region}:{account_id}:dxvif/{resource_id}',
            'resource_type': 'dxvif'
        },
        'DirectConnectGateway': {
            'method': 'describe_direct_connect_gateways',
            'key': 'directConnectGateways',
            'id_field': 'directConnectGatewayId',
            'name_field': 'name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:directconnect::{account_id}:dx-gateway/{resource_id}',
            'resource_type': 'dx-gateway'
        },
        'DirectConnectGatewayAssociation': {
            'method': 'describe_direct_connect_gateway_associations',
            'key': 'directConnectGatewayAssociations',
            'id_field': 'associationId',
            'name_field': 'associationId',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:directconnect::{account_id}:dx-gateway-association/{resource_id}',
            'resource_type': 'dx-gateway-association',
            'requires_gateway': True  # Requires gateway ID to list
        },
        'DirectConnectGatewayAssociationProposal': {
            'method': 'describe_direct_connect_gateway_association_proposals',
            'key': 'directConnectGatewayAssociationProposals',
            'id_field': 'proposalId',
            'name_field': 'proposalId',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:directconnect::{account_id}:dx-gateway-association-proposal/{resource_id}',
            'resource_type': 'dx-gateway-association-proposal',
            'requires_gateway': True  # Requires gateway ID to list
        }
    }
    
    return resource_configs


def retry_with_backoff(func, max_retries=5, base_delay=1, max_delay=60):
    """
    Retry function with exponential backoff for handling rate limiting
    """
    for attempt in range(max_retries):
        try:
            return func()
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code in ['TooManyRequestsException', 'Throttling', 'ThrottlingException']:
                if attempt < max_retries - 1:
                    delay = min(base_delay * (2 ** attempt), max_delay)
                    time.sleep(delay)
                    continue
            raise
        except Exception as e:
            raise
    return None


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
            retries={'max_attempts': 3, 'mode': 'standard'}
        )
        
        try:
            client = session.client('directconnect', region_name=region, config=client_config)
        except Exception as e:
            logger.warning(f"Direct Connect client creation failed in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        
        if not hasattr(client, config['method']):
            logger.warning(f"Method {config['method']} not available for directconnect client")
            return f'{service}:{service_type}', "success", "", []

        method = getattr(client, config['method'])
        params = {}
        
        # Special handling for resources that require gateway IDs
        if config.get('requires_gateway', False):
            # First get list of Direct Connect gateways
            try:
                def get_gateways():
                    return client.describe_direct_connect_gateways()
                
                gw_response = retry_with_backoff(get_gateways, max_retries=3)
                if not gw_response:
                    logger.info(f"No Direct Connect gateways found for {service_type} discovery")
                    return f'{service}:{service_type}', "success", "", []
                    
                gateway_ids = [gw['directConnectGatewayId'] for gw in gw_response.get('directConnectGateways', [])]
                if not gateway_ids:
                    logger.info(f"No Direct Connect gateways found for {service_type} discovery")
                    return f'{service}:{service_type}', "success", "", []
                
                # Get resources for each gateway
                all_items = []
                for gateway_id in gateway_ids:
                    try:
                        def get_gateway_resources():
                            gw_params = {'directConnectGatewayId': gateway_id}
                            response = method(**gw_params)
                            items = response.get(config['key'], [])
                            return items
                        
                        gw_items = retry_with_backoff(get_gateway_resources, max_retries=3)
                        if gw_items is not None:
                            all_items.extend(gw_items)
                        else:
                            logger.warning(f"Failed to get {service_type} for gateway {gateway_id}")
                            
                    except ClientError as gw_error:
                        error_code = gw_error.response.get('Error', {}).get('Code', 'Unknown')
                        if error_code in ['DirectConnectClientException']:
                            logger.info(f"No {service_type} found for gateway {gateway_id}")
                            continue
                        else:
                            logger.warning(f"Error getting {service_type} for gateway {gateway_id}: {gw_error}")
                            continue
                    except Exception as gw_error:
                        logger.warning(f"Error getting {service_type} for gateway {gateway_id}: {gw_error}")
                        continue
                        
                page_iterator = [{config['key']: all_items}]
                
            except Exception as gw_error:
                logger.warning(f"Error listing gateways for {service_type}: {gw_error}")
                return f'{service}:{service_type}', "success", "", []
        else:
            # Handle Direct Connect API calls with proper error handling and retry logic
            try:
                logger.info(f"Calling Direct Connect {config['method']} in region {region}")
                
                def get_resources():
                    # Handle pagination
                    try:
                        paginator = client.get_paginator(config['method'])
                        pages = []
                        for page in paginator.paginate(**params):
                            pages.append(page)
                        return pages
                    except OperationNotPageableError:
                        response = method(**params)
                        return [response]
                
                page_iterator = retry_with_backoff(get_resources, max_retries=5)
                if page_iterator is None:
                    logger.warning(f"Failed to get {service_type} after retries")
                    return f'{service}:{service_type}', "success", "", []
                    
            except (ConnectTimeoutError, ReadTimeoutError) as e:
                logger.warning(f"Direct Connect timeout in region {region}: {str(e)}")
                return f'{service}:{service_type}', "success", "", []
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                if error_code in ['UnauthorizedOperation', 'AccessDenied', 'InvalidAction']:
                    logger.warning(f"Direct Connect not available in region {region}: {error_code}")
                    return f'{service}:{service_type}', "success", "", []
                elif error_code in ['DirectConnectClientException']:
                    # Handle specific Direct Connect errors
                    error_message = str(e)
                    if 'not an authorized Direct Connect partner' in error_message:
                        logger.info(f"Account not authorized for Direct Connect {service_type} in {region}")
                        return f'{service}:{service_type}', "success", "", []
                    elif 'must be set' in error_message:
                        logger.info(f"Direct Connect {service_type} requires additional parameters")
                        return f'{service}:{service_type}', "success", "", []
                    else:
                        logger.warning(f"Direct Connect client error for {service_type}: {error_message}")
                        return f'{service}:{service_type}', "success", "", []
                elif error_code in ['ResourceNotFoundException', 'InvalidParameterException']:
                    logger.info(f"Direct Connect {service_type} not found in region {region}")
                    return f'{service}:{service_type}', "success", "", []
                else:
                    logger.error(f"Direct Connect API error in region {region}: {str(e)}")
                    return f'{service}:{service_type}', "error", str(e), []
            except Exception as e:
                logger.warning(f"Direct Connect general error in region {region}: {str(e)}")
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
                    arn = config['arn_format'].format(
                        region=region,
                        account_id=account_id,
                        resource_id=resource_id
                    )

                    # Get existing tags with retry logic
                    resource_tags = {}
                    try:
                        def get_tags():
                            return client.describe_tags(resourceArns=[arn])
                        
                        tags_response = retry_with_backoff(get_tags, max_retries=3)
                        if tags_response:
                            # Direct Connect returns tags in resourceTags array
                            resource_tag_sets = tags_response.get('resourceTags', [])
                            if resource_tag_sets:
                                # Find tags for this specific resource
                                for resource_tag_set in resource_tag_sets:
                                    if resource_tag_set.get('resourceArn') == arn:
                                        tags_list = resource_tag_set.get('tags', [])
                                        resource_tags = {tag.get('key', ''): tag.get('value', '') for tag in tags_list}
                                        break
                        else:
                            logger.warning(f"Failed to get tags for Direct Connect resource {resource_name}")
                            resource_tags = {}
                            
                    except (ConnectTimeoutError, ReadTimeoutError):
                        logger.warning(f"Timeout retrieving tags for Direct Connect resource {resource_name}")
                        resource_tags = {}
                    except ClientError as tag_error:
                        tag_error_code = tag_error.response.get('Error', {}).get('Code', 'Unknown')
                        if tag_error_code in ['ResourceNotFoundException', 'AccessDenied', 'DirectConnectClientException']:
                            logger.info(f"No tags found for Direct Connect resource {resource_name}")
                            resource_tags = {}
                        else:
                            logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                            resource_tags = {}
                    except Exception as tag_error:
                        logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                        resource_tags = {}

                    # Get additional metadata based on resource type
                    additional_metadata = {}
                    if service_type == 'Connection':
                        additional_metadata = {
                            'connectionState': item.get('connectionState', ''),
                            'bandwidth': item.get('bandwidth', ''),
                            'location': item.get('location', ''),
                            'lagId': item.get('lagId', ''),
                            'partnerName': item.get('partnerName', ''),
                            'providerName': item.get('providerName', ''),
                            'region': item.get('region', ''),
                            'vlan': item.get('vlan', 0),
                            'ownerAccount': item.get('ownerAccount', ''),
                            'hasLogicalRedundancy': item.get('hasLogicalRedundancy', ''),
                            'jumboFrameCapable': item.get('jumboFrameCapable', False),
                            'macSecCapable': item.get('macSecCapable', False)
                        }
                    elif service_type == 'VirtualInterface':
                        additional_metadata = {
                            'virtualInterfaceState': item.get('virtualInterfaceState', ''),
                            'virtualInterfaceType': item.get('virtualInterfaceType', ''),
                            'connectionId': item.get('connectionId', ''),
                            'vlan': item.get('vlan', 0),
                            'location': item.get('location', ''),
                            'bgpPeers': item.get('bgpPeers', []),
                            'region': item.get('region', ''),
                            'directConnectGatewayId': item.get('directConnectGatewayId', ''),
                            'routeFilterPrefixes': item.get('routeFilterPrefixes', []),
                            'customerAddress': item.get('customerAddress', ''),
                            'amazonAddress': item.get('amazonAddress', ''),
                            'addressFamily': item.get('addressFamily', ''),
                            'virtualGatewayId': item.get('virtualGatewayId', ''),
                            'customerRouterConfig': item.get('customerRouterConfig', ''),
                            'mtu': item.get('mtu', 0),
                            'jumboFrameCapable': item.get('jumboFrameCapable', False),
                            'siteLinkEnabled': item.get('siteLinkEnabled', False)
                        }
                    elif service_type == 'DirectConnectGateway':
                        additional_metadata = {
                            'directConnectGatewayState': item.get('directConnectGatewayState', ''),
                            'stateChangeError': item.get('stateChangeError', ''),
                            'amazonSideAsn': item.get('amazonSideAsn', 0),
                            'ownerAccount': item.get('ownerAccount', '')
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
                    logger.warning(f"Error processing Direct Connect item: {str(item_error)}")
                    continue

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} {service_type.lower()}s')

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in Direct Connect discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources


def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    # Create Direct Connect client with timeout protection
    session = boto3.Session()
    client_config = Config(
        read_timeout=15,
        connect_timeout=10,
        retries={'max_attempts': 3, 'mode': 'standard'}
    )
    
    try:
        dx_client = session.client('directconnect', region_name=region, config=client_config)
    except Exception as e:
        logger.error(f"Failed to create Direct Connect client: {str(e)}")
        return []

    for resource in resources:
        try:
            def tag_resource():
                if tags_action == 1:  # Add tags
                    # Convert tags to Direct Connect format (list of key-value objects)
                    tags_list = [{'key': tag['Key'], 'value': tag['Value']} for tag in tags]
                    dx_client.tag_resource(
                        resourceArn=resource.arn,
                        tags=tags_list
                    )
                elif tags_action == 2:  # Remove tags
                    dx_client.untag_resource(
                        resourceArn=resource.arn,
                        tagKeys=[tag['Key'] for tag in tags]
                    )
            
            # Use retry logic for tagging operations
            retry_with_backoff(tag_resource, max_retries=3)
                
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
            logger.error(f"Error processing batch for {service} in {account_id}/{region}:{resource.identifier} # {str(e)}")
            
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
    tags = []
    for tag_pair in tags_string.split(','):
        key, value = tag_pair.split(':')
        tags.append({
            'Key': key.strip(),
            'Value': value.strip()
        })
    return tags

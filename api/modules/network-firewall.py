import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    """
    AWS Network Firewall resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/network-firewall/client/tag_resource.html
    
    Network Firewall supports tagging for:
    - Firewall (Network Firewall instances)
    - FirewallPolicy (Firewall policies that define behavior)
    - RuleGroup (Rule groups for stateful and stateless rules)
    - TLSInspectionConfiguration (TLS inspection configurations)
    
    Note: Network Firewall is a regional service for VPC-level network protection
    """

    resource_configs = {
        'Firewall': {
            'method': 'list_firewalls',
            'key': 'Firewalls',
            'id_field': 'FirewallArn',
            'name_field': 'FirewallName',
            'date_field': None,  # Not available in list response
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'FirewallPolicy': {
            'method': 'list_firewall_policies',
            'key': 'FirewallPolicies',
            'id_field': 'Arn',
            'name_field': 'Name',
            'date_field': None,  # Not available in list response
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'RuleGroup': {
            'method': 'list_rule_groups',
            'key': 'RuleGroups',
            'id_field': 'Arn',
            'name_field': 'Name',
            'date_field': None,  # Not available in list response
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'TLSInspectionConfiguration': {
            'method': 'list_tls_inspection_configurations',
            'key': 'TLSInspectionConfigurations',
            'id_field': 'Arn',
            'name_field': 'Name',
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
        
        # Network Firewall is regional
        client = session.client('network-firewall', region_name=region)
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for network-firewall client")

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
                resource_name = item.get(config['name_field'], resource_id) if config['name_field'] else resource_id

                # Get creation date (not available in Network Firewall list responses)
                creation_date = None

                # Build ARN - Network Firewall provides ARN directly
                arn = resource_id

                # Get additional metadata based on resource type
                additional_metadata = {}
                if service_type == 'Firewall':
                    additional_metadata = {
                        'FirewallId': item.get('FirewallId', ''),
                        'VpcId': item.get('VpcId', ''),
                        'SubnetMappings': item.get('SubnetMappings', []),
                        'FirewallPolicyArn': item.get('FirewallPolicyArn', ''),
                        'DeleteProtection': item.get('DeleteProtection', False),
                        'SubnetChangeProtection': item.get('SubnetChangeProtection', False),
                        'FirewallPolicyChangeProtection': item.get('FirewallPolicyChangeProtection', False)
                    }
                elif service_type == 'FirewallPolicy':
                    additional_metadata = {
                        'Description': item.get('Description', ''),
                        'Type': item.get('Type', '')
                    }
                elif service_type == 'RuleGroup':
                    additional_metadata = {
                        'Type': item.get('Type', ''),  # STATELESS or STATEFUL
                        'Capacity': item.get('Capacity', ''),
                        'Description': item.get('Description', '')
                    }
                elif service_type == 'TLSInspectionConfiguration':
                    additional_metadata = {
                        'Description': item.get('Description', ''),
                        'LastModifiedTime': item.get('LastModifiedTime', '').isoformat() if hasattr(item.get('LastModifiedTime', ''), 'isoformat') else item.get('LastModifiedTime', '')
                    }

                # Get existing tags
                resource_tags = {}
                try:
                    tags_response = client.list_tags_for_resource(ResourceArn=arn)
                    tags_list = tags_response.get('Tags', [])
                    # Convert Network Firewall tag format to standard format
                    resource_tags = {tag.get('Key', ''): tag.get('Value', '') for tag in tags_list}
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
        tag_keys = [item['Key'] for item in tags]

    # Create Network Firewall client
    session = boto3.Session()
    network_firewall_client = session.client('network-firewall', region_name=region)

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to Network Firewall format (list of objects)
                network_firewall_tags = [{'Key': tag['Key'], 'Value': tag['Value']} for tag in tags]
                network_firewall_client.tag_resource(
                    ResourceArn=resource.arn,
                    Tags=network_firewall_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                network_firewall_client.untag_resource(
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

import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def _is_aws_managed_resource(resource_id: str, service_type: str) -> bool:
    """
    Determine if a resource is AWS-managed and cannot be tagged.
    Returns True if the resource should be skipped during discovery.
    """
    
    # Convert to lowercase for case-insensitive matching
    resource_id_lower = resource_id.lower()
    
    # Common AWS-managed resource patterns
    aws_managed_patterns = [
        'autodefined',      # AWS auto-defined resources
        'aws-managed',      # Explicitly AWS managed
        'default',          # Default AWS resources
        'system',           # System resources
    ]
    
    # Check for common AWS-managed patterns
    for pattern in aws_managed_patterns:
        if pattern in resource_id_lower:
            return True
    
    # Service-specific AWS-managed resource patterns
    if service_type == 'ResolverRule':
        # Most resolver rules starting with 'rslvr-autodefined' are AWS-managed
        if resource_id_lower.startswith('rslvr-autodefined'):
            return True
    
    elif service_type == 'FirewallDomainList':
        # Most firewall domain lists are AWS-managed shared resources
        # These typically start with 'rslvr-fdl-' and are shared
        if resource_id_lower.startswith('rslvr-fdl-'):
            return True
    
    elif service_type == 'FirewallRuleGroup':
        # AWS-managed firewall rule groups
        if resource_id_lower.startswith('rslvr-frg-') and 'aws' in resource_id_lower:
            return True
    
    elif service_type == 'FirewallRuleGroupAssociation':
        # AWS-managed firewall rule group associations
        if 'autodefined' in resource_id_lower or 'aws-managed' in resource_id_lower:
            return True
    
    # If none of the patterns match, assume it's user-created and can be tagged
    return False


def get_service_types(account_id, region, service, service_type):
    """
    Route53 Resolver resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/route53resolver/client/tag_resource.html
    """

    resource_configs = {
        'ResolverEndpoint': {
            'method': 'list_resolver_endpoints',
            'key': 'ResolverEndpoints',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': 'arn:aws:route53resolver:{region}:{account_id}:resolver-endpoint/{resource_id}'
        },
        'ResolverRule': {
            'method': 'list_resolver_rules',
            'key': 'ResolverRules',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': 'arn:aws:route53resolver:{region}:{account_id}:resolver-rule/{resource_id}'
        },
        'ResolverQueryLogConfig': {
            'method': 'list_resolver_query_log_configs',
            'key': 'ResolverQueryLogConfigs',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': 'arn:aws:route53resolver:{region}:{account_id}:resolver-query-log-config/{resource_id}'
        },
        'FirewallDomainList': {
            'method': 'list_firewall_domain_lists',
            'key': 'FirewallDomainLists',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': 'arn:aws:route53resolver:{region}:{account_id}:firewall-domain-list/{resource_id}'
        },
        'FirewallRuleGroup': {
            'method': 'list_firewall_rule_groups',
            'key': 'FirewallRuleGroups',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': 'arn:aws:route53resolver:{region}:{account_id}:firewall-rule-group/{resource_id}'
        },
        'FirewallRuleGroupAssociation': {
            'method': 'list_firewall_rule_group_associations',
            'key': 'FirewallRuleGroupAssociations',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': 'arn:aws:route53resolver:{region}:{account_id}:firewall-rule-group-association/{resource_id}'
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
        
        # Route53 Resolver is regional
        client = session.client('route53resolver', region_name=region)
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for route53resolver client")

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

                # Filter out AWS-managed/shared resources that cannot be tagged
                if _is_aws_managed_resource(resource_id, service_type):
                    logger.debug(f"Skipping AWS-managed resource: {resource_id}")
                    continue

                # Get resource name
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

                # Get existing tags
                resource_tags = {}
                try:
                    tags_response = client.list_tags_for_resource(ResourceArn=arn)
                    resource_tags = {tag['Key']: tag['Value'] for tag in tags_response.get('Tags', [])}
                except Exception as tag_error:
                    logger.warning(f"Could not retrieve tags for {resource_id}: {tag_error}")
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

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} user-created resources (AWS-managed resources filtered out)')

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

    # Create Route53 Resolver client
    session = boto3.Session()
    resolver_client = session.client('route53resolver', region_name=region)

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags
                resolver_client.tag_resource(
                    ResourceArn=resource.arn,
                    Tags=tags
                )
            elif tags_action == 2:
                # Remove tags
                resolver_client.untag_resource(
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

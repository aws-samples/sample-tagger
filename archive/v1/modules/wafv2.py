import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    """
    AWS WAFv2 resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/wafv2/client/tag_resource.html
    
    WAFv2 supports tagging for:
    - WebACL (Web Access Control Lists - both REGIONAL and CLOUDFRONT scopes)
    - RuleGroup (Rule Groups - both REGIONAL and CLOUDFRONT scopes)
    - IPSet (IP Sets - both REGIONAL and CLOUDFRONT scopes)
    - RegexPatternSet (Regular Expression Pattern Sets - both REGIONAL and CLOUDFRONT scopes)
    - ManagedRuleSet (Managed Rule Sets - CLOUDFRONT scope only)
    
    Note: WAFv2 is the latest version of AWS WAF with improved performance and features
    Resources can have REGIONAL scope (ALB, API Gateway, App Runner) or CLOUDFRONT scope (global)
    """

    resource_configs = {
        'WebACL': {
            'method': 'list_web_acls',
            'key': 'WebACLs',
            'id_field': 'ARN',
            'name_field': 'Name',
            'date_field': None,  # Not available in list response
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'scopes': ['REGIONAL', 'CLOUDFRONT']
        },
        'RuleGroup': {
            'method': 'list_rule_groups',
            'key': 'RuleGroups',
            'id_field': 'ARN',
            'name_field': 'Name',
            'date_field': None,  # Not available in list response
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'scopes': ['REGIONAL', 'CLOUDFRONT']
        },
        'IPSet': {
            'method': 'list_ip_sets',
            'key': 'IPSets',
            'id_field': 'ARN',
            'name_field': 'Name',
            'date_field': None,  # Not available in list response
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'scopes': ['REGIONAL', 'CLOUDFRONT']
        },
        'RegexPatternSet': {
            'method': 'list_regex_pattern_sets',
            'key': 'RegexPatternSets',
            'id_field': 'ARN',
            'name_field': 'Name',
            'date_field': None,  # Not available in list response
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'scopes': ['REGIONAL', 'CLOUDFRONT']
        },
        'ManagedRuleSet': {
            'method': 'list_managed_rule_sets',
            'key': 'ManagedRuleSets',
            'id_field': 'ARN',
            'name_field': 'Name',
            'date_field': None,  # Not available in list response
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'scopes': ['CLOUDFRONT']  # Only CLOUDFRONT scope for managed rule sets
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
        
        # WAFv2 supports both regional and global (CloudFront) resources
        client = session.client('wafv2', region_name=region)
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for wafv2 client")

        method = getattr(client, config['method'])
        
        # WAFv2 requires Scope parameter - check both REGIONAL and CLOUDFRONT scopes
        scopes_to_check = config.get('scopes', ['REGIONAL'])
        
        for scope in scopes_to_check:
            try:
                params = {'Scope': scope}

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

                        # Get creation date (not available in WAFv2 list responses)
                        creation_date = None

                        # Build ARN - WAFv2 provides ARN directly
                        arn = resource_id

                        # Get additional metadata based on resource type
                        additional_metadata = {
                            'Scope': scope,
                            'Id': item.get('Id', ''),
                            'Description': item.get('Description', ''),
                            'LockToken': item.get('LockToken', '')
                        }

                        if service_type == 'WebACL':
                            additional_metadata.update({
                                'WebACLId': item.get('Id', ''),
                                'DefaultAction': item.get('DefaultAction', '')
                            })
                        elif service_type == 'RuleGroup':
                            additional_metadata.update({
                                'RuleGroupId': item.get('Id', ''),
                                'Capacity': item.get('Capacity', '')
                            })
                        elif service_type == 'IPSet':
                            additional_metadata.update({
                                'IPSetId': item.get('Id', ''),
                                'IPAddressVersion': item.get('IPAddressVersion', '')
                            })
                        elif service_type == 'RegexPatternSet':
                            additional_metadata.update({
                                'RegexPatternSetId': item.get('Id', '')
                            })
                        elif service_type == 'ManagedRuleSet':
                            additional_metadata.update({
                                'ManagedRuleSetId': item.get('Id', ''),
                                'LabelNamespace': item.get('LabelNamespace', '')
                            })

                        # Get existing tags
                        resource_tags = {}
                        try:
                            tags_response = client.list_tags_for_resource(ResourceARN=arn)
                            tags_list = tags_response.get('TagInfoForResource', {}).get('TagList', [])
                            # Convert WAFv2 tag format to standard format
                            resource_tags = {tag.get('Key', ''): tag.get('Value', '') for tag in tags_list}
                        except Exception as tag_error:
                            logger.warning(f"Could not retrieve tags for {resource_name} in scope {scope}: {tag_error}")
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

            except Exception as scope_error:
                logger.warning(f"Error processing scope {scope} for {service_type}: {scope_error}")
                continue

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

    # Create WAFv2 client
    session = boto3.Session()
    wafv2_client = session.client('wafv2', region_name=region)

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to WAFv2 format (list of objects)
                wafv2_tags = [{'Key': tag['Key'], 'Value': tag['Value']} for tag in tags]
                wafv2_client.tag_resource(
                    ResourceARN=resource.arn,
                    Tags=wafv2_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                wafv2_client.untag_resource(
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

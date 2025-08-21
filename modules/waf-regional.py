import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    """
    AWS WAF Regional resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/waf-regional/client/tag_resource.html
    
    WAF Regional supports tagging for:
    - WebACL (Regional Web Access Control Lists)
    - Rule (Regional WAF Rules)
    - RuleGroup (Regional Rule Groups)
    - ByteMatchSet (Regional Byte match sets)
    - IPSet (Regional IP sets)
    - GeoMatchSet (Regional Geographic match sets)
    - RegexMatchSet (Regional Regular expression match sets)
    - RegexPatternSet (Regional Regular expression pattern sets)
    - SizeConstraintSet (Regional Size constraint sets)
    - SqlInjectionMatchSet (Regional SQL injection match sets)
    - XssMatchSet (Regional Cross-site scripting match sets)
    - RateBasedRule (Regional Rate-based rules)
    
    Note: WAF Regional is for regional resources (ALB, API Gateway) vs WAF Classic for CloudFront
    """

    resource_configs = {
        'WebACL': {
            'method': 'list_web_acls',
            'key': 'WebACLs',
            'id_field': 'WebACLId',
            'name_field': 'Name',
            'date_field': None,  # Not available in list response
            'nested': False,
            'arn_format': 'arn:aws:waf-regional:{region}:{account_id}:webacl/{resource_id}'
        },
        'Rule': {
            'method': 'list_rules',
            'key': 'Rules',
            'id_field': 'RuleId',
            'name_field': 'Name',
            'date_field': None,  # Not available in list response
            'nested': False,
            'arn_format': 'arn:aws:waf-regional:{region}:{account_id}:rule/{resource_id}'
        },
        'RuleGroup': {
            'method': 'list_rule_groups',
            'key': 'RuleGroups',
            'id_field': 'RuleGroupId',
            'name_field': 'Name',
            'date_field': None,  # Not available in list response
            'nested': False,
            'arn_format': 'arn:aws:waf-regional:{region}:{account_id}:rulegroup/{resource_id}'
        },
        'ByteMatchSet': {
            'method': 'list_byte_match_sets',
            'key': 'ByteMatchSets',
            'id_field': 'ByteMatchSetId',
            'name_field': 'Name',
            'date_field': None,  # Not available in list response
            'nested': False,
            'arn_format': 'arn:aws:waf-regional:{region}:{account_id}:bytematchset/{resource_id}'
        },
        'IPSet': {
            'method': 'list_ip_sets',
            'key': 'IPSets',
            'id_field': 'IPSetId',
            'name_field': 'Name',
            'date_field': None,  # Not available in list response
            'nested': False,
            'arn_format': 'arn:aws:waf-regional:{region}:{account_id}:ipset/{resource_id}'
        },
        'GeoMatchSet': {
            'method': 'list_geo_match_sets',
            'key': 'GeoMatchSets',
            'id_field': 'GeoMatchSetId',
            'name_field': 'Name',
            'date_field': None,  # Not available in list response
            'nested': False,
            'arn_format': 'arn:aws:waf-regional:{region}:{account_id}:geomatchset/{resource_id}'
        },
        'RegexMatchSet': {
            'method': 'list_regex_match_sets',
            'key': 'RegexMatchSets',
            'id_field': 'RegexMatchSetId',
            'name_field': 'Name',
            'date_field': None,  # Not available in list response
            'nested': False,
            'arn_format': 'arn:aws:waf-regional:{region}:{account_id}:regexmatchset/{resource_id}'
        },
        'RegexPatternSet': {
            'method': 'list_regex_pattern_sets',
            'key': 'RegexPatternSets',
            'id_field': 'RegexPatternSetId',
            'name_field': 'Name',
            'date_field': None,  # Not available in list response
            'nested': False,
            'arn_format': 'arn:aws:waf-regional:{region}:{account_id}:regexpatternset/{resource_id}'
        },
        'SizeConstraintSet': {
            'method': 'list_size_constraint_sets',
            'key': 'SizeConstraintSets',
            'id_field': 'SizeConstraintSetId',
            'name_field': 'Name',
            'date_field': None,  # Not available in list response
            'nested': False,
            'arn_format': 'arn:aws:waf-regional:{region}:{account_id}:sizeconstraintset/{resource_id}'
        },
        'SqlInjectionMatchSet': {
            'method': 'list_sql_injection_match_sets',
            'key': 'SqlInjectionMatchSets',
            'id_field': 'SqlInjectionMatchSetId',
            'name_field': 'Name',
            'date_field': None,  # Not available in list response
            'nested': False,
            'arn_format': 'arn:aws:waf-regional:{region}:{account_id}:sqlinjectionmatchset/{resource_id}'
        },
        'XssMatchSet': {
            'method': 'list_xss_match_sets',
            'key': 'XssMatchSets',
            'id_field': 'XssMatchSetId',
            'name_field': 'Name',
            'date_field': None,  # Not available in list response
            'nested': False,
            'arn_format': 'arn:aws:waf-regional:{region}:{account_id}:xssmatchset/{resource_id}'
        },
        'RateBasedRule': {
            'method': 'list_rate_based_rules',
            'key': 'Rules',
            'id_field': 'RuleId',
            'name_field': 'Name',
            'date_field': None,  # Not available in list response
            'nested': False,
            'arn_format': 'arn:aws:waf-regional:{region}:{account_id}:ratebasedrule/{resource_id}'
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
        
        # WAF Regional is region-specific
        client = session.client('waf-regional', region_name=region)
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for waf-regional client")

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

                # Get creation date (not available in WAF Regional list responses)
                creation_date = None

                # Build ARN - WAF Regional uses region-specific ARN format
                if config['arn_format']:
                    arn = config['arn_format'].format(
                        region=region,
                        account_id=account_id,
                        resource_id=resource_id
                    )
                else:
                    arn = resource_id

                # Get additional metadata based on resource type
                additional_metadata = {}
                if service_type == 'WebACL':
                    additional_metadata = {
                        'WebACLId': resource_id,
                        'DefaultAction': item.get('DefaultAction', '')
                    }
                elif service_type in ['Rule', 'RateBasedRule']:
                    additional_metadata = {
                        'RuleId': resource_id,
                        'MetricName': item.get('MetricName', '')
                    }
                elif service_type == 'RuleGroup':
                    additional_metadata = {
                        'RuleGroupId': resource_id,
                        'MetricName': item.get('MetricName', '')
                    }
                else:
                    # For match sets and other resources
                    additional_metadata = {
                        f'{service_type}Id': resource_id
                    }

                # Get existing tags
                resource_tags = {}
                try:
                    tags_response = client.list_tags_for_resource(ResourceARN=arn)
                    tags_list = tags_response.get('TagInfoForResource', {}).get('TagList', [])
                    # Convert WAF Regional tag format to standard format
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

    # Create WAF Regional client
    session = boto3.Session()
    waf_regional_client = session.client('waf-regional', region_name=region)

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to WAF Regional format (list of objects)
                waf_regional_tags = [{'Key': tag['Key'], 'Value': tag['Value']} for tag in tags]
                waf_regional_client.tag_resource(
                    ResourceARN=resource.arn,
                    Tags=waf_regional_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                waf_regional_client.untag_resource(
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

import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    resource_configs = {
        'ApplicationLoadBalancer': {
            'method': 'describe_load_balancers',
            'key': 'LoadBalancers',
            'id_field': 'LoadBalancerArn',
            'name_field': 'LoadBalancerName',
            'date_field': 'CreatedTime',
            'nested': False,
            'type': 'application'
        },
        'NetworkLoadBalancer': {
            'method': 'describe_load_balancers',
            'key': 'LoadBalancers',
            'id_field': 'LoadBalancerArn',
            'name_field': 'LoadBalancerName',
            'date_field': 'CreatedTime',
            'nested': False,
            'type': 'network'
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
        # Use the elbv2 client for ALB and NLB
        client = session.client('elbv2', region_name=region)
        method = getattr(client, config['method'])
        
        try:
            paginator = client.get_paginator(config['method'])
            response_iterator = paginator.paginate()
        except OperationNotPageableError:
            response_iterator = [method()]

        for page in response_iterator:
            items = page[config['key']]

            for item in items:
                # Filter by load balancer type (application or network)
                if 'Type' in item and item['Type'].lower() != config['type']:
                    continue
                
                # For ALB/NLB, the ARN is the ID, but we extract a more readable ID
                arn = item[config['id_field']]
                # Extract load balancer ID from ARN (format: arn:aws:elasticloadbalancing:region:account:loadbalancer/app/name/id)
                resource_id = arn.split('/')[-1]
                name_tag = item[config['name_field']]
                
                # Get tags for the load balancer
                resource_tags = {}
                try:
                    tags_response = client.describe_tags(ResourceArns=[arn])
                    for tag_desc in tags_response.get('TagDescriptions', []):
                        if tag_desc['ResourceArn'] == arn:
                            resource_tags = {tag['Key']: tag['Value'] for tag in tag_desc.get('Tags', [])}
                except Exception as tag_error:
                    logger.warning(f"Could not get tags for {service_type} {name_tag}: {str(tag_error)}")
                
                # Get creation date
                creation_date = item.get(config['date_field']) if config['date_field'] in item else ''

                resources.append({
                    "seq": 0,
                    "account_id": account_id,
                    "region": region,
                    "service": service,
                    "resource_type": service_type,
                    "resource_id": resource_id,
                    "name": name_tag,
                    "creation_date": creation_date,
                    "tags": resource_tags,
                    "tags_number": len(resource_tags),
                    "metadata": item,
                    "arn": arn
                })

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources

def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    logger.info(f'Tagging # Account: {account_id}, Region: {region}, Service: {service}')
    
    results = []
    tags = parse_tags(tags_string)
    
    for resource in resources:
        try:
            resource_id = resource.identifier
            resource_arn = resource.arn
            
            if tags_action == 1:  # Add tags
                client.add_tags(
                    ResourceArns=[resource_arn],
                    Tags=tags
                )
            elif tags_action == 2:  # Remove tags
                # For delete, we just need the keys
                tag_keys = [item['Key'] for item in tags]
                client.remove_tags(
                    ResourceArns=[resource_arn],
                    TagKeys=tag_keys
                )
                    
            results.append({
                'account_id': account_id,
                'region': region,
                'service': service,
                'identifier': resource.identifier,
                'arn': resource.arn,
                'status': 'success',
                'error' : ""
            })
            
        except Exception as e:
            logger.error(f"Error processing tagging for {service} in {account_id}/{region}:{resource.identifier} # {str(e)}")
            
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
import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    """
    Route53 Recovery Readiness resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/route53-recovery-readiness/client/tag_resource.html
    """

    resource_configs = {
        'Cell': {
            'method': 'list_cells',
            'key': 'Cells',
            'id_field': 'CellArn',
            'name_field': 'CellName',
            'date_field': None,
            'nested': False,
            'arn_format': '{resource_id}'  # CellArn is already the full ARN
        },
        'ReadinessCheck': {
            'method': 'list_readiness_checks',
            'key': 'ReadinessChecks',
            'id_field': 'ReadinessCheckArn',
            'name_field': 'ReadinessCheckName',
            'date_field': None,
            'nested': False,
            'arn_format': '{resource_id}'  # ReadinessCheckArn is already the full ARN
        },
        'RecoveryGroup': {
            'method': 'list_recovery_groups',
            'key': 'RecoveryGroups',
            'id_field': 'RecoveryGroupArn',
            'name_field': 'RecoveryGroupName',
            'date_field': None,
            'nested': False,
            'arn_format': '{resource_id}'  # RecoveryGroupArn is already the full ARN
        },
        'ResourceSet': {
            'method': 'list_resource_sets',
            'key': 'ResourceSets',
            'id_field': 'ResourceSetArn',
            'name_field': 'ResourceSetName',
            'date_field': None,
            'nested': False,
            'arn_format': '{resource_id}'  # ResourceSetArn is already the full ARN
        }
    }
    
    return resource_configs


def discovery(self, session, account_id, region, service, service_type, logger):    
    
    status = "success"
    error_message = ""
    resources = []

    try:
        # Route53 Recovery Readiness is only available in certain regions
        # Check supported regions: us-west-2, eu-west-1, ap-southeast-2, etc.
        supported_regions = [
            'us-west-2', 'us-east-2', 
            'eu-west-1', 'eu-central-1',
            'ap-southeast-2', 'ap-northeast-1'
        ]
        
        if region not in supported_regions:
            logger.info(f'Route53 Recovery Readiness is not available in region {region}. Supported regions: {", ".join(supported_regions)}')
            return f'{service}:{service_type}', status, "", resources
        
        service_types_list = get_service_types(account_id, region, service, service_type)        
        if service_type not in service_types_list:
            raise ValueError(f"Unsupported service type: {service_type}")

        config = service_types_list[service_type]
        
        # Route53 Recovery Readiness is regional
        client = session.client('route53-recovery-readiness', region_name=region)
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for route53-recovery-readiness client")

        method = getattr(client, config['method'])
        params = {}

        # Handle pagination
        try:
            paginator = client.get_paginator(config['method'])
            page_iterator = paginator.paginate(**params)
        except OperationNotPageableError:
            response = method(**params)
            page_iterator = [response]
        except Exception as endpoint_error:
            if "Could not connect to the endpoint URL" in str(endpoint_error):
                logger.warning(f"Route53 Recovery Readiness endpoint not available in region {region}")
                return f'{service}:{service_type}', status, "", resources
            else:
                raise endpoint_error
        except OperationNotPageableError:
            response = method(**params)
            page_iterator = [response]

        # Process each page of results
        for page in page_iterator:
            items = page[config['key']]

            for item in items:
                resource_id = item[config['id_field']]
                resource_name = item.get(config['name_field'], resource_id) if config['name_field'] else resource_id
                arn = config['arn_format'].format(resource_id=resource_id)

                # Get existing tags
                resource_tags = {}
                try:
                    tags_response = client.list_tags_for_resource(ResourceArn=arn)
                    resource_tags = {tag['Key']: tag['Value'] for tag in tags_response.get('Tags', {})}
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
                    "creation_date": None,
                    "tags": resource_tags,
                    "tags_number": len(resource_tags),
                    "metadata": item,
                    "arn": arn
                })

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} resources')

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

    # Create Route53 Recovery Readiness client
    session = boto3.Session()
    readiness_client = session.client('route53-recovery-readiness', region_name=region)

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags
                readiness_client.tag_resource(
                    ResourceArn=resource.arn,
                    Tags=tags
                )
            elif tags_action == 2:
                # Remove tags
                readiness_client.untag_resource(
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

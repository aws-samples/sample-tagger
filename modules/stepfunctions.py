import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    """
    AWS Step Functions resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/stepfunctions/client/tag_resource.html
    
    Step Functions supports tagging for:
    - StateMachine (Step Functions state machines)
    - Activity (Step Functions activities)
    """

    resource_configs = {
        'StateMachine': {
            'method': 'list_state_machines',
            'key': 'stateMachines',
            'id_field': 'stateMachineArn',
            'name_field': 'name',
            'date_field': 'creationDate',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'Activity': {
            'method': 'list_activities',
            'key': 'activities',
            'id_field': 'activityArn',
            'name_field': 'name',
            'date_field': 'creationDate',
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
        
        # Step Functions is regional
        client = session.client('stepfunctions', region_name=region)
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for stepfunctions client")

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
                resource_arn = item[config['id_field']]
                resource_id = resource_arn.split(':')[-1] if ':' in resource_arn else resource_arn
                
                # Get resource name
                resource_name = item.get(config['name_field'], resource_id) if config['name_field'] else resource_id

                # Get creation date
                creation_date = None
                if config['date_field'] and config['date_field'] in item:
                    creation_date = item[config['date_field']]
                    if hasattr(creation_date, 'isoformat'):
                        creation_date = creation_date.isoformat()

                # Get additional details for state machines
                additional_metadata = {}
                if service_type == 'StateMachine':
                    try:
                        describe_response = client.describe_state_machine(stateMachineArn=resource_arn)
                        additional_metadata = {
                            'type': describe_response.get('type', 'STANDARD'),
                            'status': describe_response.get('status', 'ACTIVE'),
                            'roleArn': describe_response.get('roleArn', ''),
                            'definition': describe_response.get('definition', '')[:100] + '...' if describe_response.get('definition') else ''
                        }
                    except Exception as desc_error:
                        logger.warning(f"Could not get details for state machine {resource_id}: {desc_error}")

                # Get existing tags
                resource_tags = {}
                try:
                    tags_response = client.list_tags_for_resource(resourceArn=resource_arn)
                    tags_list = tags_response.get('tags', [])
                    # Convert list of tag objects to dict
                    resource_tags = {tag['key']: tag['value'] for tag in tags_list}
                except Exception as tag_error:
                    logger.warning(f"Could not retrieve tags for {resource_id}: {tag_error}")
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
                    "arn": resource_arn
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

    # Create Step Functions client
    session = boto3.Session()
    stepfunctions_client = session.client('stepfunctions', region_name=region)

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to Step Functions format (list of objects)
                stepfunctions_tags = [{'key': tag['Key'], 'value': tag['Value']} for tag in tags]
                stepfunctions_client.tag_resource(
                    resourceArn=resource.arn,
                    tags=stepfunctions_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                stepfunctions_client.untag_resource(
                    resourceArn=resource.arn,
                    tagKeys=tag_keys
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

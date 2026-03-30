import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    """
    AWS Bedrock Data Automation resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/bedrock-data-automation/client/tag_resource.html
    
    Bedrock Data Automation supports tagging for:
    - DataAutomationProject (Data automation projects for document processing)
    - Blueprint (Blueprints for data automation workflows)
    """

    resource_configs = {
        'DataAutomationProject': {
            'method': 'list_data_automation_projects',
            'key': 'projects',
            'id_field': 'projectArn',
            'name_field': 'projectName',
            'date_field': 'creationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'Blueprint': {
            'method': 'list_blueprints',
            'key': 'blueprints',
            'id_field': 'blueprintArn',
            'name_field': 'blueprintName',
            'date_field': 'creationTime',
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
        
        # Bedrock Data Automation is regional
        client = session.client('bedrock-data-automation', region_name=region)
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for bedrock-data-automation client")

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

                # Get creation date
                creation_date = None
                if config['date_field'] and config['date_field'] in item:
                    creation_date = item[config['date_field']]
                    if hasattr(creation_date, 'isoformat'):
                        creation_date = creation_date.isoformat()

                # Build ARN - for Bedrock Data Automation, ARN is provided directly
                arn = resource_id

                # Get additional metadata based on resource type
                additional_metadata = {}
                if service_type == 'DataAutomationProject':
                    additional_metadata = {
                        'projectStage': item.get('projectStage', ''),
                        'projectStatus': item.get('projectStatus', ''),
                        'projectDescription': item.get('projectDescription', ''),
                        'standardOutputConfiguration': item.get('standardOutputConfiguration', {}),
                        'customOutputConfiguration': item.get('customOutputConfiguration', {})
                    }
                elif service_type == 'Blueprint':
                    additional_metadata = {
                        'blueprintStage': item.get('blueprintStage', ''),
                        'blueprintVersion': item.get('blueprintVersion', ''),
                        'schema': item.get('schema', {}),
                        'type': item.get('type', '')
                    }

                # Get existing tags
                resource_tags = {}
                try:
                    tags_response = client.list_tags_for_resource(resourceArn=arn)
                    tags_dict = tags_response.get('tags', {})
                    # Bedrock Data Automation uses dict format for tags
                    resource_tags = tags_dict if isinstance(tags_dict, dict) else {}
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

    # Create Bedrock Data Automation client
    session = boto3.Session()
    bedrock_data_automation_client = session.client('bedrock-data-automation', region_name=region)

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to Bedrock Data Automation format (dict)
                bedrock_tags = {tag['Key']: tag['Value'] for tag in tags}
                bedrock_data_automation_client.tag_resource(
                    resourceArn=resource.arn,
                    tags=bedrock_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                bedrock_data_automation_client.untag_resource(
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

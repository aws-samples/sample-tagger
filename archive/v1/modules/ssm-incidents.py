import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    """
    AWS SSM Incidents resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ssm-incidents/client/tag_resource.html
    
    SSM Incidents supports tagging for:
    - ResponsePlan (Response plans for incident management)
    - Incident (Active and resolved incidents)
    - ReplicationSet (Replication sets for multi-region incident management)
    """

    resource_configs = {
        'ResponsePlan': {
            'method': 'list_response_plans',
            'key': 'ResponsePlanSummaries',
            'id_field': 'Arn',
            'name_field': 'Name',
            'date_field': None,  # Not available in list_response_plans
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'Incident': {
            'method': 'list_incident_records',
            'key': 'IncidentRecordSummaries',
            'id_field': 'Arn',
            'name_field': 'Title',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'ReplicationSet': {
            'method': 'list_replication_sets',
            'key': 'ReplicationSetArns',
            'id_field': None,  # Special handling - returns list of ARNs directly
            'name_field': None,
            'date_field': None,
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
        
        # SSM Incidents is regional
        client = session.client('ssm-incidents', region_name=region)
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for ssm-incidents client")

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
            # Special handling for ReplicationSet
            if service_type == 'ReplicationSet':
                items = page.get(config['key'], [])  # This is a list of ARNs
                if not items:  # Handle empty list
                    continue
                    
                for replication_set_arn in items:
                    resource_id = replication_set_arn.split('/')[-1] if '/' in replication_set_arn else replication_set_arn
                    resource_name = f"ReplicationSet-{resource_id}"
                    
                    # Get replication set details
                    additional_metadata = {}
                    creation_date = None
                    try:
                        repl_response = client.get_replication_set(Arn=replication_set_arn)
                        repl_details = repl_response.get('ReplicationSet', {})
                        
                        additional_metadata = {
                            'Status': repl_details.get('Status', 'UNKNOWN'),
                            'RegionMap': repl_details.get('RegionMap', {}),
                            'DeletionProtected': repl_details.get('DeletionProtected', False)
                        }
                        
                        creation_date = repl_details.get('CreatedTime')
                        if hasattr(creation_date, 'isoformat'):
                            creation_date = creation_date.isoformat()
                            
                    except Exception as detail_error:
                        logger.warning(f"Could not get details for replication set {resource_id}: {detail_error}")

                    # Get existing tags
                    resource_tags = {}
                    try:
                        tags_response = client.list_tags_for_resource(ResourceArn=replication_set_arn)
                        tags_dict = tags_response.get('Tags', {})
                        resource_tags = tags_dict
                    except Exception as tag_error:
                        logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                        resource_tags = {}

                    # Create metadata
                    metadata = {'Arn': replication_set_arn, **additional_metadata}

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
                        "arn": replication_set_arn
                    })
            else:
                # Handle ResponsePlan and Incident
                items = page.get(config['key'], [])
                if not items:  # Handle empty list
                    continue

                for item in items:
                    resource_arn = item[config['id_field']]
                    resource_id = resource_arn.split('/')[-1] if '/' in resource_arn else resource_arn
                    resource_name = item.get(config['name_field'], resource_id) if config['name_field'] else resource_id

                    # Get creation date
                    creation_date = None
                    if config['date_field'] and config['date_field'] in item:
                        creation_date = item[config['date_field']]
                        if hasattr(creation_date, 'isoformat'):
                            creation_date = creation_date.isoformat()

                    # Get additional details based on resource type
                    additional_metadata = {}
                    if service_type == 'ResponsePlan':
                        try:
                            plan_response = client.get_response_plan(Arn=resource_arn)
                            plan_details = plan_response
                            
                            additional_metadata = {
                                'DisplayName': plan_details.get('DisplayName', ''),
                                'ChatChannel': plan_details.get('ChatChannel', {}),
                                'Engagements': plan_details.get('Engagements', []),
                                'Actions': plan_details.get('Actions', [])
                            }
                            
                        except Exception as detail_error:
                            logger.warning(f"Could not get details for response plan {resource_name}: {detail_error}")
                            
                    elif service_type == 'Incident':
                        additional_metadata = {
                            'Status': item.get('Status', 'UNKNOWN'),
                            'Impact': item.get('Impact', 0),
                            'ResponsePlanArn': item.get('ResponsePlanArn', ''),
                            'ResolvedTime': item.get('ResolvedTime', '')
                        }

                    # Get existing tags
                    resource_tags = {}
                    try:
                        tags_response = client.list_tags_for_resource(ResourceArn=resource_arn)
                        tags_dict = tags_response.get('Tags', {})
                        resource_tags = tags_dict
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

    # Create SSM Incidents client
    session = boto3.Session()
    ssmincidents_client = session.client('ssm-incidents', region_name=region)

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to SSM Incidents format (dict)
                ssmincidents_tags = {tag['Key']: tag['Value'] for tag in tags}
                ssmincidents_client.tag_resource(
                    ResourceArn=resource.arn,
                    Tags=ssmincidents_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                ssmincidents_client.untag_resource(
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

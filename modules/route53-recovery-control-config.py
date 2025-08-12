import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    """
    Route53 Recovery Control Config resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/route53-recovery-control-config/client/tag_resource.html
    """

    resource_configs = {
        'Cluster': {
            'method': 'list_clusters',
            'key': 'Clusters',
            'id_field': 'ClusterArn',
            'name_field': 'Name',
            'date_field': None,
            'nested': False,
            'arn_format': '{resource_id}'  # ClusterArn is already the full ARN
        },
        'ControlPanel': {
            'method': 'list_control_panels',
            'key': 'ControlPanels',
            'id_field': 'ControlPanelArn',
            'name_field': 'Name',
            'date_field': None,
            'nested': False,
            'arn_format': '{resource_id}'  # ControlPanelArn is already the full ARN
        },
        'RoutingControl': {
            'method': 'list_routing_controls',
            'key': 'RoutingControls',
            'id_field': 'RoutingControlArn',
            'name_field': 'Name',
            'date_field': None,
            'nested': False,
            'arn_format': '{resource_id}',  # RoutingControlArn is already the full ARN
            'requires_control_panel': True
        },
        'SafetyRule': {
            'method': 'list_safety_rules',
            'key': 'SafetyRules',
            'id_field': 'SafetyRuleArn',
            'name_field': 'Name',
            'date_field': None,
            'nested': False,
            'arn_format': '{resource_id}',  # SafetyRuleArn is already the full ARN
            'requires_control_panel': True
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
        
        # Route53 Recovery Control Config is regional
        client = session.client('route53-recovery-control-config', region_name=region)
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for route53-recovery-control-config client")

        method = getattr(client, config['method'])
        params = {}

        # Some resources require a ControlPanelArn parameter
        if config.get('requires_control_panel'):
            # First get all control panels, then iterate through them
            control_panels_response = client.list_control_panels()
            control_panels = control_panels_response.get('ControlPanels', [])
            
            for control_panel in control_panels:
                params = {'ControlPanelArn': control_panel['ControlPanelArn']}
                
                try:
                    response = method(**params)
                    items = response[config['key']]
                    
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
                        
                except Exception as e:
                    logger.warning(f"Error listing {service_type} for control panel {control_panel['ControlPanelArn']}: {e}")
                    continue
        else:
            # Handle pagination for resources that don't require ControlPanelArn
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

    # Create Route53 Recovery Control Config client
    session = boto3.Session()
    recovery_client = session.client('route53-recovery-control-config', region_name=region)

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags
                recovery_client.tag_resource(
                    ResourceArn=resource.arn,
                    Tags=tags
                )
            elif tags_action == 2:
                # Remove tags
                recovery_client.untag_resource(
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

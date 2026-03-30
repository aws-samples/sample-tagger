import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    resource_configs = {
        'Cluster': {
            'method': 'list_clusters',
            'key': 'Clusters',
            'id_field': 'Id',
            'name_field': 'Name',
            'date_field': 'Status.Timeline.CreationDateTime',
            'nested': False,
            'arn_format': 'arn:aws:elasticmapreduce:{region}:{account_id}:cluster/{resource_id}'
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
        client = session.client('emr', region_name=region)
        method = getattr(client, config['method'])
        
        # EMR clusters can be filtered by state
        # By default, we'll fetch clusters in active states (STARTING, BOOTSTRAPPING, RUNNING, WAITING, TERMINATING)
        # You might want to include TERMINATED or TERMINATED_WITH_ERRORS based on your needs
        cluster_states = ['STARTING', 'BOOTSTRAPPING', 'RUNNING', 'WAITING', 'TERMINATING']
        
        try:
            paginator = client.get_paginator(config['method'])
            response_iterator = paginator.paginate(ClusterStates=cluster_states)
        except OperationNotPageableError:
            response_iterator = [method(ClusterStates=cluster_states)]

        for page in response_iterator:
            items = page[config['key']]

            for item in items:
                resource_id = item[config['id_field']]
                
                # Construct the ARN for the cluster
                arn = config['arn_format'].format(
                    region=region,
                    account_id=account_id,
                    resource_id=resource_id
                )
                
                # Get tags for the EMR cluster
                resource_tags = {}
                try:
                    tags_response = client.describe_cluster(ClusterId=resource_id)
                    # EMR returns tags in a specific format - an array of Tag objects
                    tag_list = tags_response.get('Cluster', {}).get('Tags', [])
                    
                    # Convert EMR tags to our standard dict format
                    for tag in tag_list:
                        if 'Key' in tag and 'Value' in tag:
                            resource_tags[tag['Key']] = tag['Value']
                except Exception as tag_error:
                    logger.warning(f"Could not get tags for EMR Cluster {resource_id}: {str(tag_error)}")
                
                # Get name from the response
                name_tag = item.get(config['name_field'], '')
                
                # Get creation date - this requires nested access
                creation_date = ''
                if 'Status' in item and 'Timeline' in item['Status'] and 'CreationDateTime' in item['Status']['Timeline']:
                    creation_date = item['Status']['Timeline']['CreationDateTime']
                
                # Collect useful metadata
                metadata = {
                    'State': item.get('Status', {}).get('State', 'Unknown'),
                    'Applications': [
                        app.get('Name') for app in 
                        client.describe_cluster(ClusterId=resource_id).get('Cluster', {}).get('Applications', [])
                    ],
                    'InstanceCount': item.get('NormalizedInstanceHours', 0),
                    'ReleaseLabel': client.describe_cluster(ClusterId=resource_id).get('Cluster', {}).get('ReleaseLabel', 'Unknown')
                }

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
                    "metadata": metadata,
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
    # EMR expects tags in a specific format
    tags = parse_tags_for_emr(tags_string)
    
    for resource in resources:
        try:
            resource_id = resource.identifier
            
            if tags_action == 1:  # Add tags
                client.add_tags(
                    ResourceId=resource_id,  # EMR uses ResourceId, not ARN
                    Tags=tags
                )
            elif tags_action == 2:  # Remove tags
                # For delete, we need the keys
                tag_keys = [tag['Key'] for tag in tags]
                client.remove_tags(
                    ResourceId=resource_id,
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
    """Standard parse_tags function (returns list of Key-Value dicts)"""
    tags = []
    for tag_pair in tags_string.split(','):
        key, value = tag_pair.split(':')
        tags.append({
            'Key': key.strip(),
            'Value': value.strip()
        })
    return tags

def parse_tags_for_emr(tags_string: str) -> List[Dict[str, str]]:
    """EMR-specific parse_tags function"""
    # EMR uses the same tag format as most services, so we can reuse the standard function
    return parse_tags(tags_string)
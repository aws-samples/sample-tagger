import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    resource_configs = {
        'Cluster': {
            'method': 'list_clusters',
            'key': 'clusterArns',  # list_clusters returns ARNs, not cluster objects
            'id_field': None,  # Special handling needed as this is a list of ARNs
            'detail_method': 'describe_clusters',  # Need to call this to get cluster details
            'detail_key': 'clusters',
            'date_field': None,  # ECS clusters don't have a creation time field in the API
            'nested': False,
            'arn_format': None  # ARNs are returned directly from the API
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
        client = session.client('ecs', region_name=region)
        
        # First, list all clusters (this returns only ARNs)
        list_method = getattr(client, config['method'])
        cluster_arns = []
        
        try:
            paginator = client.get_paginator(config['method'])
            for page in paginator.paginate():
                cluster_arns.extend(page[config['key']])
        except OperationNotPageableError:
            response = list_method()
            cluster_arns.extend(response[config['key']])
        
        # If no clusters found, return empty list
        if not cluster_arns:
            return f'{service}:{service_type}', status, error_message, resources
        
        # Now get details for each cluster
        # ECS allows batch fetching of cluster details
        detail_method = getattr(client, config['detail_method'])
        
        # Process clusters in batches of 100 (API limit)
        for i in range(0, len(cluster_arns), 100):
            batch_arns = cluster_arns[i:i+100]
            response = detail_method(clusters=batch_arns)
            
            for cluster in response[config['detail_key']]:
                # Extract the cluster name from the ARN
                arn = cluster['clusterArn']
                resource_id = arn.split('/')[-1]  # Cluster name is the last part of ARN
                
                # Get tags for the cluster
                try:
                    tags_response = client.list_tags_for_resource(resourceArn=arn)
                    # Convert the tag list to a dict for consistency
                    tags_list = tags_response.get('tags', [])
                    resource_tags = {tag['key']: tag['value'] for tag in tags_list}
                except Exception as tag_error:
                    logger.warning(f"Could not get tags for ECS Cluster {resource_id}: {str(tag_error)}")
                    resource_tags = {}
                
                # Get name from resource ID (for ECS clusters, the name is the ID)
                name_tag = resource_id
                
                # ECS clusters don't have creation time in the API
                creation_date = ''

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
                    "metadata": cluster,
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
    
    # ECS expects tags in a slightly different format
    tags_list = parse_tags(tags_string)
    ecs_tags = []
    for tag in tags_list:
        ecs_tags.append({
            'key': tag['Key'],    # lowercase 'key' for ECS
            'value': tag['Value'] # lowercase 'value' for ECS
        })
    
    for resource in resources:
        try:
            resource_id = resource.identifier
            resource_arn = resource.arn
            
            if tags_action == 1:  # Add tags
                client.tag_resource(
                    resourceArn=resource_arn,
                    tags=ecs_tags  # ECS expects lowercase 'key' and 'value'
                )
            elif tags_action == 2:  # Remove tags
                # For delete, we just need the keys
                tag_keys = [item['Key'] for item in tags_list]
                client.untag_resource(
                    resourceArn=resource_arn,
                    tagKeys=tag_keys
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
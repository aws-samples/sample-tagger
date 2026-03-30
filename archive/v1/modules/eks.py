import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    resource_configs = {
        'Cluster': {
            'method': 'list_clusters',
            'key': 'clusters',  # list_clusters returns a list of cluster names
            'id_field': None,  # Special handling needed as this is just a list of names
            'detail_method': 'describe_cluster',  # Need to call this to get cluster details
            'detail_key': 'cluster',
            'date_field': 'createdAt',  # When the cluster was created
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
        client = session.client('eks', region_name=region)
        
        # First, list all cluster names
        list_method = getattr(client, config['method'])
        cluster_names = []
        
        try:
            paginator = client.get_paginator(config['method'])
            for page in paginator.paginate():
                cluster_names.extend(page[config['key']])
        except OperationNotPageableError:
            response = list_method()
            cluster_names.extend(response[config['key']])
        
        # If no clusters found, return empty list
        if not cluster_names:
            return f'{service}:{service_type}', status, error_message, resources
        
        # Now get details for each cluster
        detail_method = getattr(client, config['detail_method'])
        
        for cluster_name in cluster_names:
            try:
                # Get detailed information about the cluster
                response = detail_method(name=cluster_name)
                cluster = response[config['detail_key']]
                
                # Extract key information
                resource_id = cluster_name
                arn = cluster['arn']
                
                # Get creation date
                creation_date = cluster.get(config['date_field']) if config['date_field'] in cluster else ''
                
                # Get tags (they're already in the cluster response)
                resource_tags = cluster.get('tags', {})
                
                # Use cluster name as display name or look for a Name tag
                name_tag = resource_tags.get('Name', cluster_name)
                
                # Include all cluster information in metadata
                metadata = cluster.copy()  # Include the full cluster details
                
                # Add additional details if needed
                try:
                    # Get information about node groups
                    nodegroups_response = client.list_nodegroups(clusterName=cluster_name)
                    nodegroups = nodegroups_response.get('nodegroups', [])
                    
                    # Get details for each nodegroup
                    nodegroup_details = []
                    for ng_name in nodegroups:
                        ng_response = client.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)
                        nodegroup_details.append(ng_response['nodegroup'])
                    
                    # Add nodegroup information to metadata
                    metadata['nodegroups'] = nodegroup_details
                    
                    # Get information about add-ons
                    addons_response = client.list_addons(clusterName=cluster_name)
                    addons = addons_response.get('addons', [])
                    
                    # Get details for each add-on
                    addon_details = []
                    for addon_name in addons:
                        addon_response = client.describe_addon(
                            clusterName=cluster_name, 
                            addonName=addon_name
                        )
                        addon_details.append(addon_response['addon'])
                    
                    # Add add-on information to metadata
                    metadata['addons'] = addon_details
                    
                except Exception as detail_error:
                    logger.warning(f"Could not get all details for EKS Cluster {cluster_name}: {str(detail_error)}")

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
                logger.warning(f"Error processing cluster {cluster_name}: {str(e)}")

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources

def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    logger.info(f'Tagging # Account: {account_id}, Region: {region}, Service: {service}')
    
    results = []
    tags_dict = parse_tags_to_dict(tags_string)  # EKS expects tags as a dict
    
    for resource in resources:
        try:
            resource_id = resource.identifier
            resource_arn = resource.arn
            
            if tags_action == 1:  # Add tags
                # For EKS, we tag using the ARN and a dict of tags
                client.tag_resource(
                    resourceArn=resource_arn,
                    tags=tags_dict  # Dict format {key: value}
                )
            elif tags_action == 2:  # Remove tags
                # For delete, we just need the keys
                tag_keys = list(tags_dict.keys())
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
    """Standard parse_tags function (returns list of Key-Value dicts)"""
    tags = []
    for tag_pair in tags_string.split(','):
        key, value = tag_pair.split(':')
        tags.append({
            'Key': key.strip(),
            'Value': value.strip()
        })
    return tags

def parse_tags_to_dict(tags_string: str) -> Dict[str, str]:
    """EKS-specific parse_tags function (returns dict)"""
    tags_dict = {}
    for tag_pair in tags_string.split(','):
        key, value = tag_pair.split(':')
        tags_dict[key.strip()] = value.strip()
    return tags_dict
import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    resource_configs = {
        'Cluster': {
            'method': 'list_clusters',
            'key': 'clusters',
            'detail_method': 'describe_cluster',
            'detail_key': 'cluster',
            'date_field': 'createdAt',
            'nested': False,
            'arn_format': None
        },
        'Nodegroup': {
            'method': 'list_nodegroups',
            'key': 'nodegroups',
            'detail_method': 'describe_nodegroup',
            'detail_key': 'nodegroup',
            'date_field': 'createdAt',
            'nested': True,
            'arn_format': None
        },
        'Addon': {
            'method': 'list_addons',
            'key': 'addons',
            'detail_method': 'describe_addon',
            'detail_key': 'addon',
            'date_field': 'createdAt',
            'nested': True,
            'arn_format': None
        },
        'FargateProfile': {
            'method': 'list_fargate_profiles',
            'key': 'fargateProfileNames',
            'detail_method': 'describe_fargate_profile',
            'detail_key': 'fargateProfile',
            'date_field': 'createdAt',
            'nested': True,
            'arn_format': None
        },
        'PodIdentityAssociation': {
            'method': 'list_pod_identity_associations',
            'key': 'associations',
            'detail_method': 'describe_pod_identity_association',
            'detail_key': 'association',
            'date_field': 'createdAt',
            'nested': True,
            'arn_format': None
        },
        'AccessEntry': {
            'method': 'list_access_entries',
            'key': 'accessEntries',
            'detail_method': 'describe_access_entry',
            'detail_key': 'accessEntry',
            'date_field': 'createdAt',
            'nested': True,
            'arn_format': None
        }
    }
    
    return resource_configs

def _list_names(client, method, key, **kwargs):
    """Generic helper to list resource names with pagination."""
    names = []
    try:
        paginator = client.get_paginator(method)
        for page in paginator.paginate(**kwargs):
            names.extend(page[key])
    except OperationNotPageableError:
        response = getattr(client, method)(**kwargs)
        names.extend(response[key])
    return names

def _list_cluster_names(client):
    """List all EKS cluster names."""
    return _list_names(client, 'list_clusters', 'clusters')

def _discover_clusters(client, account_id, region, service, service_type, cluster_names, logger):
    """Discover EKS Cluster resources."""
    resources = []
    for cluster_name in cluster_names:
        try:
            response = client.describe_cluster(name=cluster_name)
            cluster = response['cluster']
            arn = cluster['arn']
            resource_tags = cluster.get('tags', {})
            resources.append({
                "seq": 0, "account_id": account_id, "region": region,
                "service": service, "resource_type": service_type,
                "resource_id": cluster_name, "name": resource_tags.get('Name', cluster_name),
                "creation_date": str(cluster.get('createdAt', '')),
                "tags": resource_tags, "tags_number": len(resource_tags),
                "metadata": cluster, "arn": arn
            })
        except Exception as e:
            logger.warning(f"Error processing cluster {cluster_name}: {str(e)}")
    return resources

def _discover_nodegroups(client, account_id, region, service, service_type, cluster_names, logger):
    """Discover EKS Nodegroup resources."""
    resources = []
    for cluster_name in cluster_names:
        ng_names = _list_names(client, 'list_nodegroups', 'nodegroups', clusterName=cluster_name)
        for ng_name in ng_names:
            try:
                response = client.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)
                ng = response['nodegroup']
                arn = ng['nodegroupArn']
                resource_tags = ng.get('tags', {})
                resources.append({
                    "seq": 0, "account_id": account_id, "region": region,
                    "service": service, "resource_type": service_type,
                    "resource_id": ng_name, "name": resource_tags.get('Name', ng_name),
                    "creation_date": str(ng.get('createdAt', '')),
                    "tags": resource_tags, "tags_number": len(resource_tags),
                    "metadata": ng, "arn": arn
                })
            except Exception as e:
                logger.warning(f"Error processing nodegroup {ng_name} in cluster {cluster_name}: {str(e)}")
    return resources

def _discover_addons(client, account_id, region, service, service_type, cluster_names, logger):
    """Discover EKS Addon resources."""
    resources = []
    for cluster_name in cluster_names:
        addon_names = _list_names(client, 'list_addons', 'addons', clusterName=cluster_name)
        for addon_name in addon_names:
            try:
                response = client.describe_addon(clusterName=cluster_name, addonName=addon_name)
                addon = response['addon']
                arn = addon['addonArn']
                resource_tags = addon.get('tags', {})
                resources.append({
                    "seq": 0, "account_id": account_id, "region": region,
                    "service": service, "resource_type": service_type,
                    "resource_id": addon_name, "name": addon_name,
                    "creation_date": str(addon.get('createdAt', '')),
                    "tags": resource_tags, "tags_number": len(resource_tags),
                    "metadata": addon, "arn": arn
                })
            except Exception as e:
                logger.warning(f"Error processing addon {addon_name} in cluster {cluster_name}: {str(e)}")
    return resources

def _discover_fargate_profiles(client, account_id, region, service, service_type, cluster_names, logger):
    """Discover EKS Fargate Profile resources."""
    resources = []
    for cluster_name in cluster_names:
        fp_names = _list_names(client, 'list_fargate_profiles', 'fargateProfileNames', clusterName=cluster_name)
        for fp_name in fp_names:
            try:
                response = client.describe_fargate_profile(clusterName=cluster_name, fargateProfileName=fp_name)
                fp = response['fargateProfile']
                arn = fp['fargateProfileArn']
                resource_tags = fp.get('tags', {})
                resources.append({
                    "seq": 0, "account_id": account_id, "region": region,
                    "service": service, "resource_type": service_type,
                    "resource_id": fp_name, "name": fp_name,
                    "creation_date": str(fp.get('createdAt', '')),
                    "tags": resource_tags, "tags_number": len(resource_tags),
                    "metadata": fp, "arn": arn
                })
            except Exception as e:
                logger.warning(f"Error processing fargate profile {fp_name} in cluster {cluster_name}: {str(e)}")
    return resources

def _discover_pod_identity_associations(client, account_id, region, service, service_type, cluster_names, logger):
    """Discover EKS Pod Identity Association resources."""
    resources = []
    for cluster_name in cluster_names:
        associations = _list_names(client, 'list_pod_identity_associations', 'associations', clusterName=cluster_name)
        # list_pod_identity_associations returns objects with associationId, not just names
        for assoc in associations:
            assoc_id = assoc if isinstance(assoc, str) else assoc.get('associationId', '')
            try:
                response = client.describe_pod_identity_association(clusterName=cluster_name, associationId=assoc_id)
                association = response['association']
                arn = association['associationArn']
                resource_tags = association.get('tags', {})
                resources.append({
                    "seq": 0, "account_id": account_id, "region": region,
                    "service": service, "resource_type": service_type,
                    "resource_id": assoc_id, "name": assoc_id,
                    "creation_date": str(association.get('createdAt', '')),
                    "tags": resource_tags, "tags_number": len(resource_tags),
                    "metadata": association, "arn": arn
                })
            except Exception as e:
                logger.warning(f"Error processing pod identity association {assoc_id} in cluster {cluster_name}: {str(e)}")
    return resources

def _discover_access_entries(client, account_id, region, service, service_type, cluster_names, logger):
    """Discover EKS Access Entry resources."""
    resources = []
    for cluster_name in cluster_names:
        principal_arns = _list_names(client, 'list_access_entries', 'accessEntries', clusterName=cluster_name)
        for principal_arn in principal_arns:
            try:
                response = client.describe_access_entry(clusterName=cluster_name, principalArn=principal_arn)
                entry = response['accessEntry']
                arn = entry['accessEntryArn']
                resource_tags = entry.get('tags', {})
                resource_id = principal_arn.split('/')[-1]
                resources.append({
                    "seq": 0, "account_id": account_id, "region": region,
                    "service": service, "resource_type": service_type,
                    "resource_id": resource_id, "name": resource_id,
                    "creation_date": str(entry.get('createdAt', '')),
                    "tags": resource_tags, "tags_number": len(resource_tags),
                    "metadata": entry, "arn": arn
                })
            except Exception as e:
                logger.warning(f"Error processing access entry {principal_arn} in cluster {cluster_name}: {str(e)}")
    return resources

_DISCOVERY_MAP = {
    'Cluster': _discover_clusters,
    'Nodegroup': _discover_nodegroups,
    'Addon': _discover_addons,
    'FargateProfile': _discover_fargate_profiles,
    'PodIdentityAssociation': _discover_pod_identity_associations,
    'AccessEntry': _discover_access_entries,
}

def discovery(self, session, account_id, region, service, service_type, logger):
    status = "success"
    error_message = ""
    resources = []

    try:
        service_types_list = get_service_types(account_id, region, service, service_type)
        if service_type not in service_types_list:
            raise ValueError(f"Unsupported service type: {service_type}")

        client = session.client('eks', region_name=region)
        cluster_names = _list_cluster_names(client)

        if not cluster_names:
            return f'{service}:{service_type}', status, error_message, resources

        discover_fn = _DISCOVERY_MAP[service_type]
        resources = discover_fn(client, account_id, region, service, service_type, cluster_names, logger)

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources

def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    logger.info(f'Tagging # Account: {account_id}, Region: {region}, Service: {service}')
    
    results = []
    tags_dict = parse_tags_to_dict(tags_string)
    
    for resource in resources:
        try:
            if tags_action == 1:
                client.tag_resource(resourceArn=resource.arn, tags=tags_dict)
            elif tags_action == 2:
                client.untag_resource(resourceArn=resource.arn, tagKeys=list(tags_dict.keys()))
                    
            results.append({
                'account_id': account_id, 'region': region, 'service': service,
                'identifier': resource.identifier, 'arn': resource.arn,
                'status': 'success', 'error': ""
            })
        except Exception as e:
            logger.error(f"Error processing tagging for {service} in {account_id}/{region}:{resource.identifier} # {str(e)}")
            results.append({
                'account_id': account_id, 'region': region, 'service': service,
                'identifier': resource.identifier, 'arn': resource.arn,
                'status': 'error', 'error': str(e)
            })
    
    return results

def parse_tags(tags_string: str) -> List[Dict[str, str]]:
    tags = []
    for tag_pair in tags_string.split(','):
        key, value = tag_pair.split(':')
        tags.append({'Key': key.strip(), 'Value': value.strip()})
    return tags

def parse_tags_to_dict(tags_string: str) -> Dict[str, str]:
    tags_dict = {}
    for tag_pair in tags_string.split(','):
        key, value = tag_pair.split(':')
        tags_dict[key.strip()] = value.strip()
    return tags_dict

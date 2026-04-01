import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    resource_configs = {
        'Cluster': {
            'method': 'list_clusters',
            'key': 'clusterArns',
            'id_field': None,
            'detail_method': 'describe_clusters',
            'detail_key': 'clusters',
            'date_field': None,
            'nested': False,
            'arn_format': None
        },
        'Service': {
            'method': 'list_services',
            'key': 'serviceArns',
            'id_field': None,
            'detail_method': 'describe_services',
            'detail_key': 'services',
            'date_field': 'createdAt',
            'nested': True,  # Nested under clusters
            'arn_format': None
        },
        'TaskDefinition': {
            'method': 'list_task_definitions',
            'key': 'taskDefinitionArns',
            'id_field': None,
            'detail_method': 'describe_task_definition',
            'detail_key': 'taskDefinition',
            'date_field': 'registeredAt',
            'nested': False,
            'arn_format': None
        },
        'Task': {
            'method': 'list_tasks',
            'key': 'taskArns',
            'id_field': None,
            'detail_method': 'describe_tasks',
            'detail_key': 'tasks',
            'date_field': 'createdAt',
            'nested': True,  # Nested under clusters
            'arn_format': None
        },
        'ContainerInstance': {
            'method': 'list_container_instances',
            'key': 'containerInstanceArns',
            'id_field': None,
            'detail_method': 'describe_container_instances',
            'detail_key': 'containerInstances',
            'date_field': 'registeredAt',
            'nested': True,  # Nested under clusters
            'arn_format': None
        }
    }
    
    return resource_configs

def _list_cluster_arns(client):
    """Helper to list all cluster ARNs."""
    cluster_arns = []
    try:
        paginator = client.get_paginator('list_clusters')
        for page in paginator.paginate():
            cluster_arns.extend(page['clusterArns'])
    except OperationNotPageableError:
        response = client.list_clusters()
        cluster_arns.extend(response['clusterArns'])
    return cluster_arns

def _discover_clusters(client, account_id, region, service, service_type, cluster_arns, logger):
    """Discover ECS Cluster resources."""
    resources = []
    for i in range(0, len(cluster_arns), 100):
        batch_arns = cluster_arns[i:i+100]
        response = client.describe_clusters(clusters=batch_arns)
        for cluster in response['clusters']:
            arn = cluster['clusterArn']
            resource_id = arn.split('/')[-1]
            try:
                tags_response = client.list_tags_for_resource(resourceArn=arn)
                resource_tags = {tag['key']: tag['value'] for tag in tags_response.get('tags', [])}
            except Exception as tag_error:
                logger.warning(f"Could not get tags for ECS Cluster {resource_id}: {str(tag_error)}")
                resource_tags = {}
            resources.append({
                "seq": 0, "account_id": account_id, "region": region,
                "service": service, "resource_type": service_type,
                "resource_id": resource_id, "name": resource_id,
                "creation_date": '', "tags": resource_tags,
                "tags_number": len(resource_tags), "metadata": cluster, "arn": arn
            })
    return resources

def _discover_services(client, account_id, region, service, service_type, cluster_arns, logger):
    """Discover ECS Service resources across all clusters."""
    resources = []
    for cluster_arn in cluster_arns:
        service_arns = []
        try:
            paginator = client.get_paginator('list_services')
            for page in paginator.paginate(cluster=cluster_arn):
                service_arns.extend(page['serviceArns'])
        except OperationNotPageableError:
            response = client.list_services(cluster=cluster_arn)
            service_arns.extend(response['serviceArns'])

        # describe_services accepts max 10 at a time
        for i in range(0, len(service_arns), 10):
            batch_arns = service_arns[i:i+10]
            response = client.describe_services(cluster=cluster_arn, services=batch_arns)
            for svc in response['services']:
                arn = svc['serviceArn']
                resource_id = svc['serviceName']
                try:
                    tags_response = client.list_tags_for_resource(resourceArn=arn)
                    resource_tags = {tag['key']: tag['value'] for tag in tags_response.get('tags', [])}
                except Exception as tag_error:
                    logger.warning(f"Could not get tags for ECS Service {resource_id}: {str(tag_error)}")
                    resource_tags = {}
                creation_date = str(svc.get('createdAt', ''))
                resources.append({
                    "seq": 0, "account_id": account_id, "region": region,
                    "service": service, "resource_type": service_type,
                    "resource_id": resource_id, "name": resource_id,
                    "creation_date": creation_date, "tags": resource_tags,
                    "tags_number": len(resource_tags), "metadata": svc, "arn": arn
                })
    return resources

def _discover_task_definitions(client, account_id, region, service, service_type, logger):
    """Discover ECS Task Definition resources."""
    resources = []
    task_def_arns = []
    try:
        paginator = client.get_paginator('list_task_definitions')
        for page in paginator.paginate():
            task_def_arns.extend(page['taskDefinitionArns'])
    except OperationNotPageableError:
        response = client.list_task_definitions()
        task_def_arns.extend(response['taskDefinitionArns'])

    for td_arn in task_def_arns:
        try:
            response = client.describe_task_definition(taskDefinition=td_arn, include=['TAGS'])
            td = response['taskDefinition']
            arn = td['taskDefinitionArn']
            resource_id = f"{td['family']}:{td['revision']}"
            tags_list = response.get('tags', [])
            resource_tags = {tag['key']: tag['value'] for tag in tags_list}
            creation_date = str(td.get('registeredAt', ''))
            resources.append({
                "seq": 0, "account_id": account_id, "region": region,
                "service": service, "resource_type": service_type,
                "resource_id": resource_id, "name": td['family'],
                "creation_date": creation_date, "tags": resource_tags,
                "tags_number": len(resource_tags), "metadata": td, "arn": arn
            })
        except Exception as e:
            logger.warning(f"Could not describe task definition {td_arn}: {str(e)}")
    return resources

def _discover_tasks(client, account_id, region, service, service_type, cluster_arns, logger):
    """Discover ECS Task resources across all clusters."""
    resources = []
    for cluster_arn in cluster_arns:
        task_arns = []
        try:
            paginator = client.get_paginator('list_tasks')
            for page in paginator.paginate(cluster=cluster_arn):
                task_arns.extend(page['taskArns'])
        except OperationNotPageableError:
            response = client.list_tasks(cluster=cluster_arn)
            task_arns.extend(response['taskArns'])

        # describe_tasks accepts max 100 at a time
        for i in range(0, len(task_arns), 100):
            batch_arns = task_arns[i:i+100]
            response = client.describe_tasks(cluster=cluster_arn, tasks=batch_arns)
            for task in response['tasks']:
                arn = task['taskArn']
                resource_id = arn.split('/')[-1]
                try:
                    tags_response = client.list_tags_for_resource(resourceArn=arn)
                    resource_tags = {tag['key']: tag['value'] for tag in tags_response.get('tags', [])}
                except Exception as tag_error:
                    logger.warning(f"Could not get tags for ECS Task {resource_id}: {str(tag_error)}")
                    resource_tags = {}
                creation_date = str(task.get('createdAt', ''))
                resources.append({
                    "seq": 0, "account_id": account_id, "region": region,
                    "service": service, "resource_type": service_type,
                    "resource_id": resource_id, "name": resource_id,
                    "creation_date": creation_date, "tags": resource_tags,
                    "tags_number": len(resource_tags), "metadata": task, "arn": arn
                })
    return resources

def _discover_container_instances(client, account_id, region, service, service_type, cluster_arns, logger):
    """Discover ECS Container Instance resources across all clusters."""
    resources = []
    for cluster_arn in cluster_arns:
        ci_arns = []
        try:
            paginator = client.get_paginator('list_container_instances')
            for page in paginator.paginate(cluster=cluster_arn):
                ci_arns.extend(page['containerInstanceArns'])
        except OperationNotPageableError:
            response = client.list_container_instances(cluster=cluster_arn)
            ci_arns.extend(response['containerInstanceArns'])

        # describe_container_instances accepts max 100 at a time
        for i in range(0, len(ci_arns), 100):
            batch_arns = ci_arns[i:i+100]
            response = client.describe_container_instances(cluster=cluster_arn, containerInstances=batch_arns)
            for ci in response['containerInstances']:
                arn = ci['containerInstanceArn']
                resource_id = arn.split('/')[-1]
                try:
                    tags_response = client.list_tags_for_resource(resourceArn=arn)
                    resource_tags = {tag['key']: tag['value'] for tag in tags_response.get('tags', [])}
                except Exception as tag_error:
                    logger.warning(f"Could not get tags for ECS ContainerInstance {resource_id}: {str(tag_error)}")
                    resource_tags = {}
                creation_date = str(ci.get('registeredAt', ''))
                resources.append({
                    "seq": 0, "account_id": account_id, "region": region,
                    "service": service, "resource_type": service_type,
                    "resource_id": resource_id, "name": resource_id,
                    "creation_date": creation_date, "tags": resource_tags,
                    "tags_number": len(resource_tags), "metadata": ci, "arn": arn
                })
    return resources

def discovery(self, session, account_id, region, service, service_type, logger):
    status = "success"
    error_message = ""
    resources = []

    try:
        service_types_list = get_service_types(account_id, region, service, service_type)
        if service_type not in service_types_list:
            raise ValueError(f"Unsupported service type: {service_type}")

        client = session.client('ecs', region_name=region)

        if service_type == 'Cluster':
            cluster_arns = _list_cluster_arns(client)
            if cluster_arns:
                resources = _discover_clusters(client, account_id, region, service, service_type, cluster_arns, logger)

        elif service_type == 'Service':
            cluster_arns = _list_cluster_arns(client)
            if cluster_arns:
                resources = _discover_services(client, account_id, region, service, service_type, cluster_arns, logger)

        elif service_type == 'TaskDefinition':
            resources = _discover_task_definitions(client, account_id, region, service, service_type, logger)

        elif service_type == 'Task':
            cluster_arns = _list_cluster_arns(client)
            if cluster_arns:
                resources = _discover_tasks(client, account_id, region, service, service_type, cluster_arns, logger)

        elif service_type == 'ContainerInstance':
            cluster_arns = _list_cluster_arns(client)
            if cluster_arns:
                resources = _discover_container_instances(client, account_id, region, service, service_type, cluster_arns, logger)

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources

def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    logger.info(f'Tagging # Account: {account_id}, Region: {region}, Service: {service}')
    
    results = []
    
    tags_list = parse_tags(tags_string)
    ecs_tags = [{'key': tag['Key'], 'value': tag['Value']} for tag in tags_list]
    
    for resource in resources:
        try:
            resource_arn = resource.arn
            
            if tags_action == 1:  # Add tags
                client.tag_resource(resourceArn=resource_arn, tags=ecs_tags)
            elif tags_action == 2:  # Remove tags
                tag_keys = [item['Key'] for item in tags_list]
                client.untag_resource(resourceArn=resource_arn, tagKeys=tag_keys)
                    
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

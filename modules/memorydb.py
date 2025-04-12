import boto3
import json
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    resource_configs = {
        'Cluster': {
            'method': 'describe_clusters',
            'key': 'Clusters',
            'id_field': 'Name',  # MemoryDB uses Name as primary identifier
            'date_field': 'CreateTime',
            'nested': False,
            'arn_format': 'arn:aws:memorydb:{region}:{account_id}:cluster/{resource_id}'
        },
        'Snapshot': {
            'method': 'describe_snapshots',
            'key': 'Snapshots',
            'id_field': 'Name',  # MemoryDB uses Name as primary identifier
            'date_field': 'CreateTime',
            'nested': False,
            'arn_format': 'arn:aws:memorydb:{region}:{account_id}:snapshot/{resource_id}'
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
        client = session.client(service, region_name=region)

        method = getattr(client, config['method'])
        params = {}

        try:
            paginator = client.get_paginator(config['method'])
            response_iterator = paginator.paginate(**params)
        except OperationNotPageableError:
            response_iterator = [method(**params)]

        for page in response_iterator:
            items = page[config['key']]

            for item in items:
                resource_id = item[config['id_field']]
                # MemoryDB uses a different tag structure with ARN
                resource_tags = {}
                if 'Tags' in item and item['Tags']:
                    resource_tags = {tag.get('Key', ''): tag.get('Value', '') for tag in item.get('Tags', [])}
                
                name = resource_id  # For MemoryDB, Name is the identifier itself
                
                creation_date = item.get(config['date_field']) if config['date_field'] else ''

                arn = item.get('ARN') or config['arn_format'].format(
                    region=region,
                    account_id=account_id,
                    resource_id=resource_id
                )

                resources.append({
                    "seq": 0,
                    "account_id": account_id,
                    "region": region,
                    "service": service,
                    "resource_type": service_type,
                    "resource_id": resource_id,
                    "name": name,
                    "creation_date": creation_date,
                    "tags": resource_tags,
                    "tags_number": len(resource_tags),
                    "metadata": item,
                    "arn": arn
                })

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources

def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    logger.info(f'Discovery # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    for resource in resources:
        try:
            if tags_action == 1:  # Add tags
                client.tag_resource(
                    ResourceArn=resource.arn,
                    Tags=[{'Key': item['Key'], 'Value': item['Value']} for item in tags]
                )
            elif tags_action == 2:  # Remove tags
                client.untag_resource(
                    ResourceArn=resource.arn,
                    TagKeys=[item['Key'] for item in tags]
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
            logger.error(f"Error processing batch for {service} in {account_id}/{region}:{resource.identifier} # {str(e)}")
            
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
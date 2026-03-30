import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    resource_configs = {
        'BackupPlan': {
            'method': 'list_backup_plans',
            'key': 'BackupPlansList',
            'id_field': 'BackupPlanId',
            'name_field': 'BackupPlanName',
            'date_field': 'CreationDate',
            'nested': False,
            'detail_method': 'get_backup_plan',
            'arn_field': 'BackupPlanArn',
            'arn_format': None  # ARN is returned by the API
        },
        'BackupVault': {
            'method': 'list_backup_vaults',
            'key': 'BackupVaultList',
            'id_field': 'BackupVaultName',  # For vaults, name is the ID
            'name_field': 'BackupVaultName',
            'date_field': 'CreationDate',
            'nested': False,
            'arn_field': 'BackupVaultArn',
            'arn_format': None  # ARN is returned by the API
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
        client = session.client('backup', region_name=region)
        method = getattr(client, config['method'])
        
        try:
            paginator = client.get_paginator(config['method'])
            response_iterator = paginator.paginate()
        except OperationNotPageableError:
            response_iterator = [method()]

        for page in response_iterator:
            items = page[config['key']]

            for item in items:
                resource_id = item[config['id_field']]
                
                # Backup Plans need an additional API call to get full details
                if service_type == 'BackupPlan':
                    try:
                        detail_method = getattr(client, config['detail_method'])
                        detail_response = detail_method(
                            BackupPlanId=resource_id
                        )
                        # Merge the detailed info into the item
                        item.update(detail_response.get('BackupPlan', {}))
                    except Exception as detail_error:
                        logger.warning(f"Could not get details for Backup Plan {resource_id}: {str(detail_error)}")

                # Get the ARN - it's already in the response
                arn = item[config['arn_field']]
                
                # Get tags for the resource
                resource_tags = {}
                try:
                    tags_response = client.list_tags(
                        ResourceArn=arn
                    )
                    resource_tags = tags_response.get('Tags', {})
                except Exception as tag_error:
                    logger.warning(f"Could not get tags for {service_type} {resource_id}: {str(tag_error)}")
                
                # Get name from the response
                name_tag = item.get(config['name_field'], resource_id)
                
                # Get creation date
                creation_date = item.get(config['date_field']) if config['date_field'] in item else ''
                
                # Include all item information in metadata
                metadata = item.copy()
                
                # Add additional information for BackupVault
                if service_type == 'BackupVault':
                    try:
                        # Get recovery points (backups) count
                        recovery_points_response = client.list_recovery_points_by_backup_vault(
                            BackupVaultName=resource_id,
                            MaxResults=1  # Just to get count, not all points
                        )
                        metadata['RecoveryPointsCount'] = recovery_points_response.get('NumberOfRecoveryPoints', 0)
                    except Exception as rp_error:
                        logger.warning(f"Could not get recovery points for Backup Vault {resource_id}: {str(rp_error)}")
                
                # Add additional information for BackupPlan
                if service_type == 'BackupPlan':
                    try:
                        # Get selection information (which resources are backed up)
                        selection_response = client.list_backup_selections(
                            BackupPlanId=resource_id
                        )
                        metadata['BackupSelections'] = selection_response.get('BackupSelectionsList', [])
                        
                        # Get information about jobs created by this plan
                        jobs_response = client.list_backup_jobs(
                            BackupPlanId=resource_id,
                            MaxResults=10  # Limit to recent jobs
                        )
                        metadata['RecentBackupJobs'] = jobs_response.get('BackupJobs', [])
                    except Exception as selection_error:
                        logger.warning(f"Could not get selections for Backup Plan {resource_id}: {str(selection_error)}")

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
    tags_dict = parse_tags_to_dict(tags_string)  # AWS Backup expects tags as a dict
   
    
    for resource in resources:
        try:
            resource_id = resource.identifier
            resource_arn = resource.arn
            
            if tags_action == 1:  # Add tags
                client.tag_resource(
                    ResourceArn=resource_arn,
                    Tags=tags_dict  # Dict format {key: value}
                )
            elif tags_action == 2:  # Remove tags
                # For delete, we just need the keys
                tag_keys = list(tags_dict.keys())
                client.untag_resource(
                    ResourceArn=resource_arn,
                    TagKeyList=tag_keys
                )
                    
            results.append({
                'account_id': account_id,
                'region': region,
                'service': service,
                'identifier': resource_id,
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

def parse_tags_to_dict(tags_string: str) -> Dict[str, str]:
    """AWS Backup-specific parse_tags function (returns dict)"""
    tags_dict = {}
    for tag_pair in tags_string.split(','):
        key, value = tag_pair.split(':')
        tags_dict[key.strip()] = value.strip()
    return tags_dict
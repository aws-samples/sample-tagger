import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    resource_configs = {
        'Table': {
            'method': 'list_databases',
            'key': 'Databases',
            'id_field': 'DatabaseName',
            'nested': True,
            'nested_method': 'list_tables',
            'nested_key': 'Tables',
            'nested_id_field': 'TableName',
            'date_field': 'CreationTime',
            'arn_format': 'arn:aws:timestream:{region}:{account_id}:database/{database}/table/{resource_id}'
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
        client = session.client('timestream-write', region_name=region)
        method = getattr(client, config['method'])
        
        try:
            # First list all databases
            paginator = client.get_paginator(config['method'])
            response_iterator = paginator.paginate()
        except OperationNotPageableError:
            response_iterator = [method()]

        for page in response_iterator:
            databases = page[config['key']]

            # For each database, list its tables
            for database in databases:
                database_name = database[config['id_field']]
                
                try:
                    nested_method = getattr(client, config['nested_method'])
                    
                    # List tables in this database
                    try:
                        nested_paginator = client.get_paginator(config['nested_method'])
                        nested_response_iterator = nested_paginator.paginate(DatabaseName=database_name)
                    except OperationNotPageableError:
                        nested_response_iterator = [nested_method(DatabaseName=database_name)]
                    
                    # Process each table in this database
                    for nested_page in nested_response_iterator:
                        tables = nested_page[config['nested_key']]
                        
                        for table in tables:
                            resource_id = table[config['nested_id_field']]
                            
                            # Construct the ARN for the table
                            arn = config['arn_format'].format(
                                region=region,
                                account_id=account_id,
                                database=database_name,
                                resource_id=resource_id
                            )
                            
                            # Get tags for the Timestream table
                            resource_tags = {}
                            try:
                                tags_response = client.list_tags_for_resource(ResourceARN=arn)
                                # Convert the tag list to a dict for consistency
                                for tag in tags_response.get('Tags', []):
                                    if 'Key' in tag and 'Value' in tag:
                                        resource_tags[tag['Key']] = tag['Value']
                            except Exception as tag_error:
                                logger.warning(f"Could not get tags for Timestream Table {resource_id}: {str(tag_error)}")
                            
                            # Get name from resource ID (table name)
                            name_tag = resource_id
                            
                            # Get creation date
                            creation_date = table.get(config['date_field']) if config['date_field'] in table else ''
                            
                            # Collect useful metadata
                            metadata = {
                                **table,
                                'DatabaseName': database_name,
                                'TableName': resource_id,
                                'RetentionProperties': table.get('RetentionProperties', {}),
                                'TableStatus': table.get('TableStatus', 'Unknown')
                            }

                            resources.append({
                                "seq": 0,
                                "account_id": account_id,
                                "region": region,
                                "service": service,
                                "resource_type": service_type,
                                "resource_id": f"{database_name}/{resource_id}",  # Use database/table format for ID
                                "name": name_tag,
                                "creation_date": creation_date,
                                "tags": resource_tags,
                                "tags_number": len(resource_tags),
                                "metadata": metadata,
                                "arn": arn,
                                "database_name": database_name,  # Store database name for tagging
                                "table_name": resource_id  # Store table name for tagging
                            })
                            
                except Exception as nested_error:
                    logger.warning(f"Error listing tables for database {database_name}: {str(nested_error)}")

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
                    ResourceARN=resource.arn,
                    Tags=[{'Key': item['Key'], 'Value': item['Value']} for item in tags]
                )
            elif tags_action == 2:  # Remove tags
                client.untag_resource(
                    ResourceARN=resource.arn,
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
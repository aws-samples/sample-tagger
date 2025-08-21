import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError, ClientError, ConnectTimeoutError, ReadTimeoutError
from botocore.config import Config

def get_service_types(account_id, region, service, service_type):
    """
    AWS Glue DataBrew resources that support tagging.
    
    DataBrew supports tagging for:
    - Dataset (DataBrew datasets)
    - Project (DataBrew projects)
    - Job (DataBrew jobs - profile and recipe jobs)
    - Recipe (DataBrew recipes)
    - Ruleset (DataBrew rulesets for data quality)
    - Schedule (DataBrew schedules)
    """

    resource_configs = {
        'Dataset': {
            'method': 'list_datasets',
            'key': 'Datasets',
            'id_field': 'Name',
            'name_field': 'Name',
            'date_field': 'CreateDate',
            'nested': False,
            'arn_format': 'arn:aws:databrew:{region}:{account_id}:dataset/{resource_id}'
        },
        'Project': {
            'method': 'list_projects',
            'key': 'Projects',
            'id_field': 'Name',
            'name_field': 'Name',
            'date_field': 'CreateDate',
            'nested': False,
            'arn_format': 'arn:aws:databrew:{region}:{account_id}:project/{resource_id}'
        },
        'Job': {
            'method': 'list_jobs',
            'key': 'Jobs',
            'id_field': 'Name',
            'name_field': 'Name',
            'date_field': 'CreateDate',
            'nested': False,
            'arn_format': 'arn:aws:databrew:{region}:{account_id}:job/{resource_id}'
        },
        'Recipe': {
            'method': 'list_recipes',
            'key': 'Recipes',
            'id_field': 'Name',
            'name_field': 'Name',
            'date_field': 'CreateDate',
            'nested': False,
            'arn_format': 'arn:aws:databrew:{region}:{account_id}:recipe/{resource_id}'
        },
        'Ruleset': {
            'method': 'list_rulesets',
            'key': 'Rulesets',
            'id_field': 'Name',
            'name_field': 'Name',
            'date_field': 'CreateDate',
            'nested': False,
            'arn_format': 'arn:aws:databrew:{region}:{account_id}:ruleset/{resource_id}'
        },
        'Schedule': {
            'method': 'list_schedules',
            'key': 'Schedules',
            'id_field': 'Name',
            'name_field': 'Name',
            'date_field': 'CreateDate',
            'nested': False,
            'arn_format': 'arn:aws:databrew:{region}:{account_id}:schedule/{resource_id}'
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
        
        # Configure client with timeouts
        client_config = Config(
            read_timeout=15,
            connect_timeout=10,
            retries={'max_attempts': 2, 'mode': 'standard'}
        )
        
        try:
            client = session.client('databrew', region_name=region, config=client_config)
        except Exception as e:
            logger.warning(f"DataBrew client creation failed in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        
        if not hasattr(client, config['method']):
            logger.warning(f"Method {config['method']} not available for databrew client")
            return f'{service}:{service_type}', "success", "", []

        method = getattr(client, config['method'])
        params = {}

        # Handle DataBrew API calls with proper error handling
        try:
            logger.info(f"Calling DataBrew {config['method']} in region {region}")
            
            # Handle pagination
            try:
                paginator = client.get_paginator(config['method'])
                page_iterator = paginator.paginate(**params)
            except OperationNotPageableError:
                response = method(**params)
                page_iterator = [response]
                
        except (ConnectTimeoutError, ReadTimeoutError) as e:
            logger.warning(f"DataBrew timeout in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code in ['UnauthorizedOperation', 'AccessDenied', 'InvalidAction']:
                logger.warning(f"DataBrew not available in region {region}: {error_code}")
                return f'{service}:{service_type}', "success", "", []
            else:
                logger.error(f"DataBrew API error in region {region}: {str(e)}")
                return f'{service}:{service_type}', "error", str(e), []
        except Exception as e:
            logger.warning(f"DataBrew general error in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []

        # Process results
        for page in page_iterator:
            items = page.get(config['key'], [])

            for item in items:
                try:
                    resource_id = item[config['id_field']]
                    resource_name = item.get(config['name_field'], resource_id) if config['name_field'] else resource_id

                    # Get creation date
                    creation_date = None
                    if config['date_field'] and config['date_field'] in item:
                        creation_date = item[config['date_field']]
                        if hasattr(creation_date, 'isoformat'):
                            creation_date = creation_date.isoformat()

                    # Build ARN - DataBrew provides ResourceArn directly in most cases
                    if 'ResourceArn' in item:
                        arn = item['ResourceArn']
                    else:
                        arn = config['arn_format'].format(
                            region=region,
                            account_id=account_id,
                            resource_id=resource_id
                        )

                    # Get existing tags - DataBrew includes tags in the list response
                    resource_tags = {}
                    if 'Tags' in item:
                        resource_tags = item.get('Tags', {})
                    else:
                        # If tags are not in the list response, try to get them separately
                        try:
                            tags_response = client.list_tags_for_resource(ResourceArn=arn)
                            resource_tags = tags_response.get('Tags', {})
                        except (ConnectTimeoutError, ReadTimeoutError):
                            logger.warning(f"Timeout retrieving tags for DataBrew resource {resource_name}")
                            resource_tags = {}
                        except Exception as tag_error:
                            logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                            resource_tags = {}

                    # Get additional metadata based on resource type
                    additional_metadata = {}
                    if service_type == 'Dataset':
                        additional_metadata = {
                            'Format': item.get('Format', ''),
                            'FormatOptions': item.get('FormatOptions', {}),
                            'Input': item.get('Input', {}),
                            'Source': item.get('Source', ''),
                            'PathOptions': item.get('PathOptions', {}),
                            'LastModifiedDate': item.get('LastModifiedDate', ''),
                            'LastModifiedBy': item.get('LastModifiedBy', '')
                        }
                    elif service_type == 'Project':
                        additional_metadata = {
                            'DatasetName': item.get('DatasetName', ''),
                            'RecipeName': item.get('RecipeName', ''),
                            'Sample': item.get('Sample', {}),
                            'RoleArn': item.get('RoleArn', ''),
                            'LastModifiedDate': item.get('LastModifiedDate', ''),
                            'LastModifiedBy': item.get('LastModifiedBy', ''),
                            'OpenDate': item.get('OpenDate', ''),
                            'OpenedBy': item.get('OpenedBy', '')
                        }
                    elif service_type == 'Job':
                        additional_metadata = {
                            'Type': item.get('Type', ''),
                            'DatasetName': item.get('DatasetName', ''),
                            'ProjectName': item.get('ProjectName', ''),
                            'RecipeName': item.get('RecipeName', ''),
                            'RoleArn': item.get('RoleArn', ''),
                            'LastModifiedDate': item.get('LastModifiedDate', ''),
                            'LastModifiedBy': item.get('LastModifiedBy', ''),
                            'LogSubscription': item.get('LogSubscription', ''),
                            'MaxCapacity': item.get('MaxCapacity', 0),
                            'MaxRetries': item.get('MaxRetries', 0),
                            'Outputs': item.get('Outputs', []),
                            'Timeout': item.get('Timeout', 0)
                        }
                    elif service_type == 'Recipe':
                        additional_metadata = {
                            'ProjectName': item.get('ProjectName', ''),
                            'PublishedBy': item.get('PublishedBy', ''),
                            'PublishedDate': item.get('PublishedDate', ''),
                            'Description': item.get('Description', ''),
                            'LastModifiedDate': item.get('LastModifiedDate', ''),
                            'LastModifiedBy': item.get('LastModifiedBy', ''),
                            'RecipeVersion': item.get('RecipeVersion', '')
                        }
                    elif service_type == 'Ruleset':
                        additional_metadata = {
                            'TargetArn': item.get('TargetArn', ''),
                            'Description': item.get('Description', ''),
                            'RuleCount': item.get('RuleCount', 0),
                            'LastModifiedDate': item.get('LastModifiedDate', ''),
                            'LastModifiedBy': item.get('LastModifiedBy', '')
                        }
                    elif service_type == 'Schedule':
                        additional_metadata = {
                            'JobNames': item.get('JobNames', []),
                            'CronExpression': item.get('CronExpression', ''),
                            'LastModifiedDate': item.get('LastModifiedDate', ''),
                            'LastModifiedBy': item.get('LastModifiedBy', '')
                        }

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
                        "arn": arn
                    })
                except Exception as item_error:
                    logger.warning(f"Error processing DataBrew item: {str(item_error)}")
                    continue

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} {service_type.lower()}s')

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in DataBrew discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources


def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    if tags_action == 2:        
        tag_keys = list(tags.keys()) if isinstance(tags, dict) else [tag['Key'] for tag in tags]

    # Create DataBrew client with timeout protection
    session = boto3.Session()
    client_config = Config(
        read_timeout=15,
        connect_timeout=10,
        retries={'max_attempts': 2, 'mode': 'standard'}
    )
    
    try:
        databrew_client = session.client('databrew', region_name=region, config=client_config)
    except Exception as e:
        logger.error(f"Failed to create DataBrew client: {str(e)}")
        return []

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - DataBrew uses dictionary format
                if isinstance(tags, list):
                    databrew_tags = {tag['Key']: tag['Value'] for tag in tags}
                else:
                    databrew_tags = tags
                    
                databrew_client.tag_resource(
                    ResourceArn=resource.arn,
                    Tags=databrew_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                databrew_client.untag_resource(
                    ResourceArn=resource.arn,
                    TagsToRemove=tag_keys
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
    """Parse tags from string format to dictionary"""
    tags = {}
    if tags_string:
        for tag_pair in tags_string.split(','):
            if ':' in tag_pair:
                key, value = tag_pair.split(':', 1)
                tags[key.strip()] = value.strip()
    return tags

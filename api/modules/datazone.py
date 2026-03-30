import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError, ClientError, ConnectTimeoutError, ReadTimeoutError
from botocore.config import Config

def get_service_types(account_id, region, service, service_type):
    """
    Amazon DataZone resources that support tagging.
    
    Based on AWS DataZone documentation:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/datazone.html
    
    DataZone supports tagging for:
    - Domain (DataZone domains for data governance)
    - Environment (Data environments for analytics workloads)
    - EnvironmentProfile (Environment profiles/templates)
    - DataSource (Data sources for cataloging)
    - Project (DataZone projects for collaboration)
    - Glossary (Business glossaries for data definitions)
    - GlossaryTerm (Individual glossary terms)
    - AssetType (Custom asset types)
    - FormType (Custom form types for metadata)
    """

    resource_configs = {
        'Domain': {
            'method': 'list_domains',
            'key': 'items',
            'id_field': 'id',
            'name_field': 'name',
            'date_field': 'createdAt',
            'nested': False,
            'arn_format': 'arn:aws:datazone:{region}:{account_id}:domain/{resource_id}',
            'describe_method': 'get_domain',
            'describe_param': 'identifier'
        },
        'Environment': {
            'method': 'list_environments',
            'key': 'items',
            'id_field': 'id',
            'name_field': 'name',
            'date_field': 'createdAt',
            'nested': False,
            'arn_format': 'arn:aws:datazone:{region}:{account_id}:environment/{resource_id}',
            'describe_method': 'get_environment',
            'describe_param': 'identifier',
            'requires_domain': True
        },
        'EnvironmentProfile': {
            'method': 'list_environment_profiles',
            'key': 'items',
            'id_field': 'id',
            'name_field': 'name',
            'date_field': 'createdAt',
            'nested': False,
            'arn_format': 'arn:aws:datazone:{region}:{account_id}:environment-profile/{resource_id}',
            'describe_method': 'get_environment_profile',
            'describe_param': 'identifier',
            'requires_domain': True
        },
        'DataSource': {
            'method': 'list_data_sources',
            'key': 'items',
            'id_field': 'dataSourceId',
            'name_field': 'name',
            'date_field': 'createdAt',
            'nested': False,
            'arn_format': 'arn:aws:datazone:{region}:{account_id}:data-source/{resource_id}',
            'describe_method': 'get_data_source',
            'describe_param': 'identifier',
            'requires_domain': True
        },
        'Project': {
            'method': 'list_projects',
            'key': 'items',
            'id_field': 'id',
            'name_field': 'name',
            'date_field': 'createdAt',
            'nested': False,
            'arn_format': 'arn:aws:datazone:{region}:{account_id}:project/{resource_id}',
            'describe_method': 'get_project',
            'describe_param': 'identifier',
            'requires_domain': True
        },
        'Glossary': {
            'method': 'list_glossaries',
            'key': 'items',
            'id_field': 'id',
            'name_field': 'name',
            'date_field': 'createdAt',
            'nested': False,
            'arn_format': 'arn:aws:datazone:{region}:{account_id}:glossary/{resource_id}',
            'describe_method': 'get_glossary',
            'describe_param': 'identifier',
            'requires_domain': True
        },
        'GlossaryTerm': {
            'method': 'list_glossary_terms',
            'key': 'items',
            'id_field': 'id',
            'name_field': 'name',
            'date_field': 'createdAt',
            'nested': False,
            'arn_format': 'arn:aws:datazone:{region}:{account_id}:glossary-term/{resource_id}',
            'describe_method': 'get_glossary_term',
            'describe_param': 'identifier',
            'requires_domain': True,
            'requires_glossary': True
        },
        'AssetType': {
            'method': 'list_asset_types',
            'key': 'items',
            'id_field': 'typeIdentifier',
            'name_field': 'name',
            'date_field': 'createdAt',
            'nested': False,
            'arn_format': 'arn:aws:datazone:{region}:{account_id}:asset-type/{resource_id}',
            'describe_method': 'get_asset_type',
            'describe_param': 'identifier',
            'requires_domain': True
        },
        'FormType': {
            'method': 'list_form_types',
            'key': 'items',
            'id_field': 'typeIdentifier',
            'name_field': 'name',
            'date_field': 'createdAt',
            'nested': False,
            'arn_format': 'arn:aws:datazone:{region}:{account_id}:form-type/{resource_id}',
            'describe_method': 'get_form_type',
            'describe_param': 'identifier',
            'requires_domain': True
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
            client = session.client('datazone', region_name=region, config=client_config)
        except Exception as e:
            logger.warning(f"DataZone client creation failed in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        
        if not hasattr(client, config['method']):
            logger.warning(f"Method {config['method']} not available for datazone client")
            return f'{service}:{service_type}', "success", "", []

        method = getattr(client, config['method'])
        params = {}
        
        # Special handling for resources that require domain IDs
        if config.get('requires_domain', False):
            # First get list of domains
            try:
                domains_response = client.list_domains()
                domain_ids = [domain['id'] for domain in domains_response.get('items', [])]
                if not domain_ids:
                    logger.info(f"No domains found for {service_type} discovery")
                    return f'{service}:{service_type}', "success", "", []
                
                # Get resources for each domain
                all_items = []
                for domain_id in domain_ids:
                    try:
                        domain_params = {'domainIdentifier': domain_id}
                        
                        # Special handling for GlossaryTerm which also requires glossary ID
                        if config.get('requires_glossary', False):
                            # Get glossaries for this domain first
                            glossaries_response = client.list_glossaries(domainIdentifier=domain_id)
                            glossary_ids = [glossary['id'] for glossary in glossaries_response.get('items', [])]
                            
                            for glossary_id in glossary_ids:
                                try:
                                    glossary_params = {'domainIdentifier': domain_id, 'glossaryIdentifier': glossary_id}
                                    response = method(**glossary_params)
                                    all_items.extend(response.get(config['key'], []))
                                except Exception as glossary_error:
                                    logger.warning(f"Error getting glossary terms for glossary {glossary_id}: {glossary_error}")
                                    continue
                        else:
                            response = method(**domain_params)
                            all_items.extend(response.get(config['key'], []))
                            
                    except Exception as domain_error:
                        logger.warning(f"Error getting {service_type} for domain {domain_id}: {domain_error}")
                        continue
                        
                page_iterator = [{config['key']: all_items}]
                
            except Exception as domain_error:
                logger.warning(f"Error listing domains for {service_type}: {domain_error}")
                return f'{service}:{service_type}', "success", "", []
        else:
            # Handle DataZone API calls with proper error handling
            try:
                logger.info(f"Calling DataZone {config['method']} in region {region}")
                
                # Handle pagination
                try:
                    paginator = client.get_paginator(config['method'])
                    page_iterator = paginator.paginate(**params)
                except OperationNotPageableError:
                    response = method(**params)
                    page_iterator = [response]
                    
            except (ConnectTimeoutError, ReadTimeoutError) as e:
                logger.warning(f"DataZone timeout in region {region}: {str(e)}")
                return f'{service}:{service_type}', "success", "", []
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                if error_code in ['UnauthorizedOperation', 'AccessDenied', 'InvalidAction']:
                    logger.warning(f"DataZone not available in region {region}: {error_code}")
                    return f'{service}:{service_type}', "success", "", []
                else:
                    logger.error(f"DataZone API error in region {region}: {str(e)}")
                    return f'{service}:{service_type}', "error", str(e), []
            except Exception as e:
                logger.warning(f"DataZone general error in region {region}: {str(e)}")
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

                    # Build ARN
                    arn = config['arn_format'].format(
                        region=region,
                        account_id=account_id,
                        resource_id=resource_id
                    )

                    # Get existing tags
                    resource_tags = {}
                    try:
                        tags_response = client.list_tags_for_resource(resourceArn=arn)
                        tags_dict = tags_response.get('tags', {})
                        # DataZone returns tags as a dictionary
                        resource_tags = tags_dict
                    except (ConnectTimeoutError, ReadTimeoutError):
                        logger.warning(f"Timeout retrieving tags for DataZone resource {resource_name}")
                        resource_tags = {}
                    except Exception as tag_error:
                        logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                        resource_tags = {}

                    # Get additional metadata based on resource type
                    additional_metadata = {}
                    if service_type == 'Domain':
                        additional_metadata = {
                            'description': item.get('description', ''),
                            'status': item.get('status', ''),
                            'domainExecutionRole': item.get('domainExecutionRole', ''),
                            'kmsKeyIdentifier': item.get('kmsKeyIdentifier', ''),
                            'singleSignOn': item.get('singleSignOn', {}),
                            'lastUpdatedAt': item.get('lastUpdatedAt', ''),
                            'portalUrl': item.get('portalUrl', '')
                        }
                    elif service_type == 'Environment':
                        additional_metadata = {
                            'description': item.get('description', ''),
                            'domainId': item.get('domainId', ''),
                            'projectId': item.get('projectId', ''),
                            'provider': item.get('provider', ''),
                            'status': item.get('status', ''),
                            'environmentProfileId': item.get('environmentProfileId', ''),
                            'awsAccountId': item.get('awsAccountId', ''),
                            'awsAccountRegion': item.get('awsAccountRegion', ''),
                            'lastUpdatedAt': item.get('lastUpdatedAt', '')
                        }
                    elif service_type == 'Project':
                        additional_metadata = {
                            'description': item.get('description', ''),
                            'domainId': item.get('domainId', ''),
                            'domainUnitId': item.get('domainUnitId', ''),
                            'projectStatus': item.get('projectStatus', ''),
                            'failureReasons': item.get('failureReasons', []),
                            'lastUpdatedAt': item.get('lastUpdatedAt', '')
                        }
                    elif service_type == 'DataSource':
                        additional_metadata = {
                            'description': item.get('description', ''),
                            'domainId': item.get('domainId', ''),
                            'projectId': item.get('projectId', ''),
                            'environmentId': item.get('environmentId', ''),
                            'type': item.get('type', ''),
                            'status': item.get('status', ''),
                            'enableSetting': item.get('enableSetting', ''),
                            'publishOnImport': item.get('publishOnImport', False),
                            'lastRunAt': item.get('lastRunAt', ''),
                            'lastUpdatedAt': item.get('lastUpdatedAt', '')
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
                    logger.warning(f"Error processing DataZone item: {str(item_error)}")
                    continue

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} {service_type.lower()}s')

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in DataZone discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources


def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    if tags_action == 2:        
        tag_keys = list(tags.keys()) if isinstance(tags, dict) else [tag['Key'] for tag in tags]

    # Create DataZone client with timeout protection
    session = boto3.Session()
    client_config = Config(
        read_timeout=15,
        connect_timeout=10,
        retries={'max_attempts': 2, 'mode': 'standard'}
    )
    
    try:
        datazone_client = session.client('datazone', region_name=region, config=client_config)
    except Exception as e:
        logger.error(f"Failed to create DataZone client: {str(e)}")
        return []

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - DataZone uses dictionary format
                if isinstance(tags, list):
                    datazone_tags = {tag['Key']: tag['Value'] for tag in tags}
                else:
                    datazone_tags = tags
                    
                datazone_client.tag_resource(
                    resourceArn=resource.arn,
                    tags=datazone_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                datazone_client.untag_resource(
                    resourceArn=resource.arn,
                    tagKeys=tag_keys
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

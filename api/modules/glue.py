import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    """
    AWS Glue resources that support tagging.
    Based on: https://docs.aws.amazon.com/glue/latest/dg/monitor-tags.html
    
    Glue supports tagging for:
    - Connection (data source connections)
    - Database (data catalog databases)
    - Crawler (data crawlers)
    - Session (interactive sessions)
    - DevEndpoint (development endpoints)
    - Job (ETL jobs)
    - Trigger (job triggers)
    - Workflow (workflows)
    - Blueprint (blueprints)
    - MLTransform (machine learning transforms)
    - DataQualityRuleset (data quality rulesets)
    - Registry (stream schema registries)
    - Schema (stream schemas)
    """

    resource_configs = {
        'Connection': {
            'method': 'get_connections',
            'key': 'ConnectionList',
            'id_field': 'Name',
            'name_field': 'Name',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': 'arn:aws:glue:{region}:{account_id}:connection/{resource_id}'
        },
        'Database': {
            'method': 'get_databases',
            'key': 'DatabaseList',
            'id_field': 'Name',
            'name_field': 'Name',
            'date_field': 'CreateTime',
            'nested': False,
            'arn_format': 'arn:aws:glue:{region}:{account_id}:database/{resource_id}'
        },
        'Crawler': {
            'method': 'get_crawlers',
            'key': 'Crawlers',
            'id_field': 'Name',
            'name_field': 'Name',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': 'arn:aws:glue:{region}:{account_id}:crawler/{resource_id}'
        },
        'Session': {
            'method': 'list_sessions',
            'key': 'Sessions',
            'id_field': 'Id',
            'name_field': 'Id',
            'date_field': 'CreatedOn',
            'nested': False,
            'arn_format': 'arn:aws:glue:{region}:{account_id}:session/{resource_id}'
        },
        'DevEndpoint': {
            'method': 'get_dev_endpoints',
            'key': 'DevEndpoints',
            'id_field': 'EndpointName',
            'name_field': 'EndpointName',
            'date_field': 'CreatedTimestamp',
            'nested': False,
            'arn_format': 'arn:aws:glue:{region}:{account_id}:devEndpoint/{resource_id}'
        },
        'Job': {
            'method': 'get_jobs',
            'key': 'Jobs',
            'id_field': 'Name',
            'name_field': 'Name',
            'date_field': 'CreatedOn',
            'nested': False,
            'arn_format': 'arn:aws:glue:{region}:{account_id}:job/{resource_id}'
        },
        'Trigger': {
            'method': 'get_triggers',
            'key': 'Triggers',
            'id_field': 'Name',
            'name_field': 'Name',
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:glue:{region}:{account_id}:trigger/{resource_id}'
        },
        'Workflow': {
            'method': 'list_workflows',
            'key': 'Workflows',
            'id_field': None,  # Workflows returns just names
            'name_field': None,
            'date_field': None,
            'nested': False,
            'arn_format': 'arn:aws:glue:{region}:{account_id}:workflow/{resource_id}'
        },
        'Blueprint': {
            'method': 'list_blueprints',
            'key': 'Blueprints',
            'id_field': 'Name',
            'name_field': 'Name',
            'date_field': 'CreatedOn',
            'nested': False,
            'arn_format': 'arn:aws:glue:{region}:{account_id}:blueprint/{resource_id}'
        },
        'MLTransform': {
            'method': 'get_ml_transforms',
            'key': 'Transforms',
            'id_field': 'TransformId',
            'name_field': 'Name',
            'date_field': 'CreatedOn',
            'nested': False,
            'arn_format': 'arn:aws:glue:{region}:{account_id}:mlTransform/{resource_id}'
        },
        'DataQualityRuleset': {
            'method': 'list_data_quality_rulesets',
            'key': 'Rulesets',
            'id_field': 'Name',
            'name_field': 'Name',
            'date_field': 'CreatedOn',
            'nested': False,
            'arn_format': 'arn:aws:glue:{region}:{account_id}:dataQualityRuleset/{resource_id}'
        },
        'Registry': {
            'method': 'list_registries',
            'key': 'Registries',
            'id_field': 'RegistryName',
            'name_field': 'RegistryName',
            'date_field': 'CreatedTime',
            'nested': False,
            'arn_format': 'arn:aws:glue:{region}:{account_id}:registry/{resource_id}'
        },
        'Schema': {
            'method': 'list_schemas',
            'key': 'Schemas',
            'id_field': 'SchemaName',
            'name_field': 'SchemaName',
            'date_field': 'CreatedTime',
            'nested': True,  # Schemas need registry name
            'arn_format': 'arn:aws:glue:{region}:{account_id}:schema/{registry_name}/{resource_id}'
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
        
        # Glue is regional
        client = session.client('glue', region_name=region)
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for glue client")

        method = getattr(client, config['method'])

        # Handle special cases for nested resources
        if service_type == 'Schema':
            # Schemas need to be discovered per registry
            try:
                registries_response = client.list_registries()
                registries = registries_response.get('Registries', [])
                
                for registry in registries:
                    registry_name = registry['RegistryName']
                    params = {'RegistryId': {'RegistryName': registry_name}}
                    
                    try:
                        # Handle pagination for schemas
                        try:
                            paginator = client.get_paginator(config['method'])
                            page_iterator = paginator.paginate(**params)
                        except OperationNotPageableError:
                            response = method(**params)
                            page_iterator = [response]

                        # Process each page of results
                        for page in page_iterator:
                            items = page[config['key']]
                            
                            for item in items:
                                resource_id = item[config['id_field']]
                                resource_name = item.get(config['name_field'], resource_id) if config['name_field'] else resource_id

                                # Get creation date
                                creation_date = None
                                if config['date_field'] and config['date_field'] in item:
                                    creation_date = item[config['date_field']]
                                    if hasattr(creation_date, 'isoformat'):
                                        creation_date = creation_date.isoformat()

                                # Build ARN for schema
                                arn = config['arn_format'].format(
                                    region=region,
                                    account_id=account_id,
                                    registry_name=registry_name,
                                    resource_id=resource_id
                                )

                                # Get existing tags
                                resource_tags = {}
                                try:
                                    tags_response = client.get_tags(ResourceArn=arn)
                                    resource_tags = tags_response.get('Tags', {})
                                except Exception as tag_error:
                                    logger.warning(f"Could not retrieve tags for {resource_id}: {tag_error}")
                                    resource_tags = {}

                                resources.append({
                                    "account_id": account_id,
                                    "region": region,
                                    "service": service,
                                    "resource_type": service_type,
                                    "resource_id": f"{registry_name}.{resource_id}",  # Include registry name
                                    "name": resource_name,
                                    "creation_date": creation_date,
                                    "tags": resource_tags,
                                    "tags_number": len(resource_tags),
                                    "metadata": item,
                                    "arn": arn
                                })
                                
                    except Exception as reg_error:
                        logger.warning(f"Could not get schemas for registry {registry_name}: {reg_error}")
                        
            except Exception as e:
                logger.warning(f"Could not list registries for schemas: {e}")
                    
        elif service_type == 'Workflow':
            # Workflows return just names, need to get details separately
            params = {}
            
            try:
                paginator = client.get_paginator(config['method'])
                page_iterator = paginator.paginate(**params)
            except OperationNotPageableError:
                response = method(**params)
                page_iterator = [response]

            # Process each page of results
            for page in page_iterator:
                workflow_names = page[config['key']]
                
                for workflow_name in workflow_names:
                    # Get workflow details
                    try:
                        workflow_response = client.get_workflow(Name=workflow_name)
                        workflow_details = workflow_response.get('Workflow', {})
                        
                        resource_id = workflow_name
                        resource_name = workflow_name

                        # Get creation date
                        creation_date = None
                        if 'CreatedOn' in workflow_details:
                            creation_date = workflow_details['CreatedOn']
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
                            tags_response = client.get_tags(ResourceArn=arn)
                            resource_tags = tags_response.get('Tags', {})
                        except Exception as tag_error:
                            logger.warning(f"Could not retrieve tags for {resource_id}: {tag_error}")
                            resource_tags = {}

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
                            "metadata": workflow_details,
                            "arn": arn
                        })
                        
                    except Exception as wf_error:
                        logger.warning(f"Could not get workflow details for {workflow_name}: {wf_error}")
                        
        else:
            # Standard resource discovery
            params = {}

            # Handle pagination
            try:
                paginator = client.get_paginator(config['method'])
                page_iterator = paginator.paginate(**params)
            except OperationNotPageableError:
                response = method(**params)
                page_iterator = [response]

            # Process each page of results
            for page in page_iterator:
                items = page[config['key']]

                for item in items:
                    if config['id_field']:
                        resource_id = item[config['id_field']]
                    else:
                        resource_id = item  # For simple lists like workflows
                        
                    # Get resource name
                    if isinstance(item, dict):
                        resource_name = item.get(config['name_field'], resource_id) if config['name_field'] else resource_id
                    else:
                        resource_name = resource_id

                    # Get creation date
                    creation_date = None
                    if isinstance(item, dict) and config['date_field'] and config['date_field'] in item:
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
                        tags_response = client.get_tags(ResourceArn=arn)
                        resource_tags = tags_response.get('Tags', {})
                    except Exception as tag_error:
                        logger.warning(f"Could not retrieve tags for {resource_id}: {tag_error}")
                        resource_tags = {}

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
                        "metadata": item,
                        "arn": arn
                    })

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} {service_type.lower()}s')

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources


####----| Tagging method
def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    if tags_action == 2:        
        tag_keys = [item['Key'] for item in tags]

    # Create Glue client
    session = boto3.Session()
    glue_client = session.client('glue', region_name=region)

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to Glue format (dict)
                glue_tags = {tag['Key']: tag['Value'] for tag in tags}
                glue_client.tag_resource(
                    ResourceArn=resource.arn,
                    TagsToAdd=glue_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                glue_client.untag_resource(
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
    """Parse tags from string format to list of dictionaries"""
    tags = []
    if tags_string:
        for tag_pair in tags_string.split(','):
            if ':' in tag_pair:
                key, value = tag_pair.split(':', 1)
                tags.append({'Key': key.strip(), 'Value': value.strip()})
    return tags

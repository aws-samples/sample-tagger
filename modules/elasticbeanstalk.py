import json
import boto3
import time
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError, ClientError, ConnectTimeoutError, ReadTimeoutError
from botocore.config import Config

def get_service_types(account_id, region, service, service_type):
    """
    AWS Elastic Beanstalk resources that support tagging.
    
    Based on AWS Elastic Beanstalk documentation:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elasticbeanstalk.html
    
    Elastic Beanstalk supports tagging for:
    - Application (Elastic Beanstalk applications)
    - ApplicationVersion (Application versions)
    - Environment (Elastic Beanstalk environments)
    - ConfigurationTemplate (Configuration templates)
    - PlatformVersion (Custom platform versions)
    """

    resource_configs = {
        'Application': {
            'method': 'describe_applications',
            'key': 'Applications',
            'id_field': 'ApplicationName',
            'name_field': 'ApplicationName',
            'date_field': 'DateCreated',
            'nested': False,
            'arn_format': 'arn:aws:elasticbeanstalk:{region}:{account_id}:application/{resource_id}',
            'describe_method': 'describe_applications',
            'describe_param': 'ApplicationNames'
        },
        'ApplicationVersion': {
            'method': 'describe_application_versions',
            'key': 'ApplicationVersions',
            'id_field': 'VersionLabel',
            'name_field': 'VersionLabel',
            'date_field': 'DateCreated',
            'nested': False,
            'arn_format': 'arn:aws:elasticbeanstalk:{region}:{account_id}:applicationversion/{application_name}/{resource_id}',
            'describe_method': 'describe_application_versions',
            'describe_param': 'VersionLabels',
            'requires_application': True
        },
        'Environment': {
            'method': 'describe_environments',
            'key': 'Environments',
            'id_field': 'EnvironmentName',
            'name_field': 'EnvironmentName',
            'date_field': 'DateCreated',
            'nested': False,
            'arn_format': 'arn:aws:elasticbeanstalk:{region}:{account_id}:environment/{application_name}/{resource_id}',
            'describe_method': 'describe_environments',
            'describe_param': 'EnvironmentNames',
            'requires_application': True
        },
        'ConfigurationTemplate': {
            'method': 'describe_configuration_settings',
            'key': 'ConfigurationSettings',
            'id_field': 'TemplateName',
            'name_field': 'TemplateName',
            'date_field': 'DateCreated',
            'nested': False,
            'arn_format': 'arn:aws:elasticbeanstalk:{region}:{account_id}:configurationtemplate/{application_name}/{resource_id}',
            'describe_method': 'describe_configuration_settings',
            'describe_param': 'TemplateName',
            'requires_application': True,
            'template_only': True
        },
        'PlatformVersion': {
            'method': 'list_platform_versions',
            'key': 'PlatformSummaryList',
            'id_field': 'PlatformArn',
            'name_field': 'PlatformArn',
            'date_field': 'DateCreated',
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'describe_method': 'describe_platform_version',
            'describe_param': 'PlatformArn'
            # Removed custom_only filter - will get all platforms and filter later
        }
    }
    
    return resource_configs


def retry_with_backoff(func, max_retries=5, base_delay=1, max_delay=60):
    """
    Retry function with exponential backoff for handling rate limiting
    """
    for attempt in range(max_retries):
        try:
            return func()
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code in ['TooManyRequestsException', 'Throttling', 'ThrottlingException']:
                if attempt < max_retries - 1:
                    delay = min(base_delay * (2 ** attempt), max_delay)
                    time.sleep(delay)
                    continue
            raise
        except Exception as e:
            raise
    return None


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
            retries={'max_attempts': 3, 'mode': 'standard'}
        )
        
        try:
            client = session.client('elasticbeanstalk', region_name=region, config=client_config)
        except Exception as e:
            logger.warning(f"Elastic Beanstalk client creation failed in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        
        if not hasattr(client, config['method']):
            logger.warning(f"Method {config['method']} not available for elasticbeanstalk client")
            return f'{service}:{service_type}', "success", "", []

        method = getattr(client, config['method'])
        params = {}
        
        # Special handling for resources that require application names
        if config.get('requires_application', False):
            # First get list of applications
            try:
                def get_applications():
                    return client.describe_applications()
                
                apps_response = retry_with_backoff(get_applications, max_retries=3)
                if not apps_response:
                    logger.info(f"No Elastic Beanstalk applications found for {service_type} discovery")
                    return f'{service}:{service_type}', "success", "", []
                    
                application_names = [app['ApplicationName'] for app in apps_response.get('Applications', [])]
                if not application_names:
                    logger.info(f"No Elastic Beanstalk applications found for {service_type} discovery")
                    return f'{service}:{service_type}', "success", "", []
                
                # Get resources for each application
                all_items = []
                for app_name in application_names:
                    try:
                        def get_app_resources():
                            app_params = {'ApplicationName': app_name}
                            
                            # Special handling for ConfigurationTemplate
                            if config.get('template_only', False):
                                # Get configuration settings and filter for templates only
                                response = method(**app_params)
                                items = response.get(config['key'], [])
                                # Filter only templates (have TemplateName)
                                items = [item for item in items if item.get('TemplateName')]
                            else:
                                response = method(**app_params)
                                items = response.get(config['key'], [])
                            
                            # Add application_name to each item for ARN construction
                            for item in items:
                                item['_application_name'] = app_name
                            return items
                        
                        app_items = retry_with_backoff(get_app_resources, max_retries=3)
                        if app_items is not None:
                            all_items.extend(app_items)
                        else:
                            logger.warning(f"Failed to get {service_type} for application {app_name}")
                            
                    except Exception as app_error:
                        logger.warning(f"Error getting {service_type} for application {app_name}: {app_error}")
                        continue
                        
                page_iterator = [{config['key']: all_items}]
                
            except Exception as app_error:
                logger.warning(f"Error listing applications for {service_type}: {app_error}")
                return f'{service}:{service_type}', "success", "", []
        else:
            # Handle Elastic Beanstalk API calls with proper error handling and retry logic
            try:
                logger.info(f"Calling Elastic Beanstalk {config['method']} in region {region}")
                
                def get_resources():
                    # Handle pagination
                    try:
                        paginator = client.get_paginator(config['method'])
                        pages = []
                        for page in paginator.paginate(**params):
                            pages.append(page)
                        return pages
                    except OperationNotPageableError:
                        response = method(**params)
                        return [response]
                
                page_iterator = retry_with_backoff(get_resources, max_retries=5)
                if page_iterator is None:
                    logger.warning(f"Failed to get {service_type} after retries")
                    return f'{service}:{service_type}', "success", "", []
                    
            except (ConnectTimeoutError, ReadTimeoutError) as e:
                logger.warning(f"Elastic Beanstalk timeout in region {region}: {str(e)}")
                return f'{service}:{service_type}', "success", "", []
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                if error_code in ['UnauthorizedOperation', 'AccessDenied', 'InvalidAction']:
                    logger.warning(f"Elastic Beanstalk not available in region {region}: {error_code}")
                    return f'{service}:{service_type}', "success", "", []
                elif error_code in ['ResourceNotFoundException', 'InvalidParameterException']:
                    logger.info(f"Elastic Beanstalk {service_type} not found in region {region}")
                    return f'{service}:{service_type}', "success", "", []
                else:
                    logger.error(f"Elastic Beanstalk API error in region {region}: {str(e)}")
                    return f'{service}:{service_type}', "error", str(e), []
            except Exception as e:
                logger.warning(f"Elastic Beanstalk general error in region {region}: {str(e)}")
                return f'{service}:{service_type}', "success", "", []

        # Process results
        for page in page_iterator:
            items = page.get(config['key'], [])
            
            # Filter PlatformVersion to only include custom platforms (owned by this account)
            if service_type == 'PlatformVersion':
                items = [item for item in items if item.get('PlatformOwner') == account_id]

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
                    if config['arn_format']:
                        if config.get('requires_application', False):
                            app_name = item.get('_application_name', item.get('ApplicationName', ''))
                            arn = config['arn_format'].format(
                                region=region,
                                account_id=account_id,
                                application_name=app_name,
                                resource_id=resource_id
                            )
                        else:
                            arn = config['arn_format'].format(
                                region=region,
                                account_id=account_id,
                                resource_id=resource_id
                            )
                    else:
                        arn = resource_id  # ARN is provided directly (PlatformVersion)

                    # Get existing tags with retry logic
                    resource_tags = {}
                    try:
                        def get_tags():
                            return client.list_tags_for_resource(ResourceArn=arn)
                        
                        tags_response = retry_with_backoff(get_tags, max_retries=3)
                        if tags_response:
                            # Elastic Beanstalk returns tags in ResourceTags array
                            tags_list = tags_response.get('ResourceTags', [])
                            resource_tags = {tag.get('Key', ''): tag.get('Value', '') for tag in tags_list}
                        else:
                            logger.warning(f"Failed to get tags for Elastic Beanstalk resource {resource_name}")
                            resource_tags = {}
                            
                    except (ConnectTimeoutError, ReadTimeoutError):
                        logger.warning(f"Timeout retrieving tags for Elastic Beanstalk resource {resource_name}")
                        resource_tags = {}
                    except ClientError as tag_error:
                        tag_error_code = tag_error.response.get('Error', {}).get('Code', 'Unknown')
                        if tag_error_code in ['ResourceNotFoundException', 'AccessDenied', 'InvalidParameterValueException']:
                            logger.info(f"No tags found for Elastic Beanstalk resource {resource_name}")
                            resource_tags = {}
                        else:
                            logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                            resource_tags = {}
                    except Exception as tag_error:
                        logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                        resource_tags = {}

                    # Get additional metadata based on resource type
                    additional_metadata = {}
                    if service_type == 'Application':
                        additional_metadata = {
                            'Description': item.get('Description', ''),
                            'Versions': item.get('Versions', []),
                            'ConfigurationTemplates': item.get('ConfigurationTemplates', []),
                            'ResourceLifecycleConfig': item.get('ResourceLifecycleConfig', {})
                        }
                    elif service_type == 'ApplicationVersion':
                        additional_metadata = {
                            'ApplicationName': item.get('ApplicationName', ''),
                            'Description': item.get('Description', ''),
                            'SourceBundle': item.get('SourceBundle', {}),
                            'BuildArn': item.get('BuildArn', ''),
                            'SourceBuildInformation': item.get('SourceBuildInformation', {}),
                            'Status': item.get('Status', '')
                        }
                    elif service_type == 'Environment':
                        additional_metadata = {
                            'ApplicationName': item.get('ApplicationName', ''),
                            'EnvironmentId': item.get('EnvironmentId', ''),
                            'Description': item.get('Description', ''),
                            'EndpointURL': item.get('EndpointURL', ''),
                            'CNAME': item.get('CNAME', ''),
                            'Status': item.get('Status', ''),
                            'Health': item.get('Health', ''),
                            'HealthStatus': item.get('HealthStatus', ''),
                            'SolutionStackName': item.get('SolutionStackName', ''),
                            'PlatformArn': item.get('PlatformArn', ''),
                            'Tier': item.get('Tier', {}),
                            'VersionLabel': item.get('VersionLabel', ''),
                            'OperationsRole': item.get('OperationsRole', ''),
                            'AbortableOperationInProgress': item.get('AbortableOperationInProgress', False)
                        }
                    elif service_type == 'ConfigurationTemplate':
                        additional_metadata = {
                            'ApplicationName': item.get('ApplicationName', ''),
                            'Description': item.get('Description', ''),
                            'SolutionStackName': item.get('SolutionStackName', ''),
                            'PlatformArn': item.get('PlatformArn', ''),
                            'EnvironmentName': item.get('EnvironmentName', ''),
                            'DeploymentStatus': item.get('DeploymentStatus', ''),
                            'OptionSettings': item.get('OptionSettings', [])
                        }
                    elif service_type == 'PlatformVersion':
                        additional_metadata = {
                            'PlatformName': item.get('PlatformName', ''),
                            'PlatformVersion': item.get('PlatformVersion', ''),
                            'PlatformStatus': item.get('PlatformStatus', ''),
                            'PlatformCategory': item.get('PlatformCategory', ''),
                            'PlatformOwner': item.get('PlatformOwner', ''),
                            'SupportedTierList': item.get('SupportedTierList', []),
                            'SupportedAddonList': item.get('SupportedAddonList', [])
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
                    logger.warning(f"Error processing Elastic Beanstalk item: {str(item_error)}")
                    continue

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} {service_type.lower()}s')

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in Elastic Beanstalk discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources


def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    # Create Elastic Beanstalk client with timeout protection
    session = boto3.Session()
    client_config = Config(
        read_timeout=15,
        connect_timeout=10,
        retries={'max_attempts': 3, 'mode': 'standard'}
    )
    
    try:
        eb_client = session.client('elasticbeanstalk', region_name=region, config=client_config)
    except Exception as e:
        logger.error(f"Failed to create Elastic Beanstalk client: {str(e)}")
        return []

    for resource in resources:
        try:
            def tag_resource():
                if tags_action == 1:  # Add tags
                    # Convert tags to Elastic Beanstalk format (list of Key-Value objects)
                    tags_list = [{'Key': tag['Key'], 'Value': tag['Value']} for tag in tags]
                    eb_client.update_tags_for_resource(
                        ResourceArn=resource.arn,
                        TagsToAdd=tags_list
                    )
                elif tags_action == 2:  # Remove tags
                    eb_client.update_tags_for_resource(
                        ResourceArn=resource.arn,
                        TagsToRemove=[tag['Key'] for tag in tags]
                    )
            
            # Use retry logic for tagging operations
            retry_with_backoff(tag_resource, max_retries=3)
                
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

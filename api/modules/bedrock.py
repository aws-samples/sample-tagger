import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError, ClientError, ConnectTimeoutError, ReadTimeoutError
from botocore.config import Config

def get_service_types(account_id, region, service, service_type):
    """
    AWS Bedrock resources that support tagging - COMPLETE LIST.
    
    Based on AWS Bedrock documentation:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/bedrock.html
    
    Bedrock supports tagging for ALL these resources:
    - CustomModel (Custom foundation models created by users)
    - ProvisionedModelThroughput (Provisioned throughput for models)
    - ModelCustomizationJob (Model customization jobs)
    - InferenceProfile (Inference profiles for optimized model performance)
    - ModelInvocationJob (Batch inference jobs - formerly called batch inference profiles)
    - Guardrail (Content filtering and safety guardrails)
    - EvaluationJob (Model evaluation jobs)
    - ModelCopyJob (Model copy jobs between regions/accounts)
    - ModelImportJob (Model import jobs from external sources)
    - ImportedModel (Models imported from external sources)
    - PromptRouter (Prompt routing configurations)
    - MarketplaceModelEndpoint (Marketplace model endpoints)
    - CustomModelDeployment (Custom model deployments)
    
    Note: Foundation models cannot be tagged as they are managed by AWS/providers
    """

    resource_configs = {
        'CustomModel': {
            'method': 'list_custom_models',
            'key': 'modelSummaries',
            'id_field': 'modelArn',
            'name_field': 'modelName',
            'date_field': 'creationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'ProvisionedModelThroughput': {
            'method': 'list_provisioned_model_throughputs',
            'key': 'provisionedModelSummaries',
            'id_field': 'provisionedModelArn',
            'name_field': 'provisionedModelName',
            'date_field': 'creationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'ModelCustomizationJob': {
            'method': 'list_model_customization_jobs',
            'key': 'modelCustomizationJobSummaries',
            'id_field': 'jobArn',
            'name_field': 'jobName',
            'date_field': 'creationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'InferenceProfile': {
            'method': 'list_inference_profiles',
            'key': 'inferenceProfileSummaries',
            'id_field': 'inferenceProfileArn',
            'name_field': 'inferenceProfileName',
            'date_field': 'createdAt',
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'describe_method': 'get_inference_profile',
            'describe_param': 'inferenceProfileIdentifier'
        },
        'ModelInvocationJob': {
            'method': 'list_model_invocation_jobs',
            'key': 'invocationJobSummaries',
            'id_field': 'jobArn',
            'name_field': 'jobName',
            'date_field': 'submitTime',
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'describe_method': 'get_model_invocation_job',
            'describe_param': 'jobIdentifier'
        },
        'Guardrail': {
            'method': 'list_guardrails',
            'key': 'guardrails',
            'id_field': 'arn',
            'name_field': 'name',
            'date_field': 'createdAt',
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'describe_method': 'get_guardrail',
            'describe_param': 'guardrailIdentifier'
        },
        'EvaluationJob': {
            'method': 'list_evaluation_jobs',
            'key': 'jobSummaries',
            'id_field': 'jobArn',
            'name_field': 'jobName',
            'date_field': 'creationTime',
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'describe_method': 'get_evaluation_job',
            'describe_param': 'jobIdentifier'
        },
        'ModelCopyJob': {
            'method': 'list_model_copy_jobs',
            'key': 'modelCopyJobSummaries',
            'id_field': 'jobArn',
            'name_field': 'jobName',
            'date_field': 'creationTime',
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'describe_method': 'get_model_copy_job',
            'describe_param': 'jobArn'
        },
        'ModelImportJob': {
            'method': 'list_model_import_jobs',
            'key': 'modelImportJobSummaries',
            'id_field': 'jobArn',
            'name_field': 'jobName',
            'date_field': 'creationTime',
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'describe_method': 'get_model_import_job',
            'describe_param': 'jobIdentifier'
        },
        'ImportedModel': {
            'method': 'list_imported_models',
            'key': 'modelSummaries',
            'id_field': 'modelArn',
            'name_field': 'modelName',
            'date_field': 'creationTime',
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'describe_method': 'get_imported_model',
            'describe_param': 'modelIdentifier'
        },
        'PromptRouter': {
            'method': 'list_prompt_routers',
            'key': 'promptRouters',
            'id_field': 'promptRouterArn',
            'name_field': 'promptRouterName',
            'date_field': 'createdAt',
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'describe_method': 'get_prompt_router',
            'describe_param': 'promptRouterArn'
        },
        'MarketplaceModelEndpoint': {
            'method': 'list_marketplace_model_endpoints',
            'key': 'marketplaceModelEndpoints',
            'id_field': 'endpointArn',
            'name_field': 'endpointName',
            'date_field': 'createdAt',
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'describe_method': 'get_marketplace_model_endpoint',
            'describe_param': 'endpointArn'
        },
        'CustomModelDeployment': {
            'method': 'list_custom_model_deployments',
            'key': 'customModelDeploymentSummaries',
            'id_field': 'deploymentArn',
            'name_field': 'deploymentName',
            'date_field': 'creationTime',
            'nested': False,
            'arn_format': None,  # ARN is provided directly
            'describe_method': 'get_custom_model_deployment',
            'describe_param': 'deploymentArn'
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
            client = session.client('bedrock', region_name=region, config=client_config)
        except Exception as e:
            logger.warning(f"Bedrock client creation failed in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        
        if not hasattr(client, config['method']):
            logger.warning(f"Method {config['method']} not available for bedrock client in region {region}")
            return f'{service}:{service_type}', "success", "", []

        method = getattr(client, config['method'])
        params = {}

        try:
            logger.info(f"Calling Bedrock {config['method']} in region {region}")
            
            # Handle pagination
            try:
                paginator = client.get_paginator(config['method'])
                page_iterator = paginator.paginate(**params)
            except OperationNotPageableError:
                response = method(**params)
                page_iterator = [response]
                
        except (ConnectTimeoutError, ReadTimeoutError) as e:
            logger.warning(f"Bedrock timeout in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code in ['UnauthorizedOperation', 'AccessDenied', 'InvalidAction', 'UnknownOperationException']:
                logger.warning(f"Bedrock {service_type} not available in region {region}: {error_code}")
                return f'{service}:{service_type}', "success", "", []
            else:
                logger.error(f"Bedrock API error in region {region}: {str(e)}")
                return f'{service}:{service_type}', "error", str(e), []
        except Exception as e:
            logger.warning(f"Bedrock general error in region {region}: {str(e)}")
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

                    # ARN is provided directly in Bedrock
                    arn = resource_id

                    # Get existing tags
                    resource_tags = {}
                    try:
                        tags_response = client.list_tags_for_resource(resourceARN=arn)
                        tags_list = tags_response.get('tags', [])
                        # Convert Bedrock tag format to standard format
                        resource_tags = {tag.get('key', ''): tag.get('value', '') for tag in tags_list}
                    except (ConnectTimeoutError, ReadTimeoutError):
                        logger.warning(f"Timeout retrieving tags for Bedrock resource {resource_name}")
                        resource_tags = {}
                    except Exception as tag_error:
                        logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                        resource_tags = {}

                    # Get additional metadata based on resource type
                    additional_metadata = {}
                    if service_type == 'CustomModel':
                        additional_metadata = {
                            'baseModelArn': item.get('baseModelArn', ''),
                            'modelName': item.get('modelName', ''),
                            'customizationType': item.get('customizationType', ''),
                            'ownerAccountId': item.get('ownerAccountId', ''),
                            'baseModelName': item.get('baseModelName', ''),
                            'hyperParameters': item.get('hyperParameters', {}),
                            'trainingDataConfig': item.get('trainingDataConfig', {}),
                            'validationDataConfig': item.get('validationDataConfig', {}),
                            'outputDataConfig': item.get('outputDataConfig', {})
                        }
                    elif service_type == 'ProvisionedModelThroughput':
                        additional_metadata = {
                            'provisionedModelName': item.get('provisionedModelName', ''),
                            'modelArn': item.get('modelArn', ''),
                            'desiredModelArn': item.get('desiredModelArn', ''),
                            'foundationModelArn': item.get('foundationModelArn', ''),
                            'modelUnits': item.get('modelUnits', 0),
                            'desiredModelUnits': item.get('desiredModelUnits', 0),
                            'status': item.get('status', ''),
                            'commitmentDuration': item.get('commitmentDuration', ''),
                            'commitmentExpirationTime': item.get('commitmentExpirationTime', ''),
                            'lastModifiedTime': item.get('lastModifiedTime', '')
                        }
                    elif service_type == 'ModelCustomizationJob':
                        additional_metadata = {
                            'jobName': item.get('jobName', ''),
                            'status': item.get('status', ''),
                            'baseModelArn': item.get('baseModelArn', ''),
                            'customModelName': item.get('customModelName', ''),
                            'customModelArn': item.get('customModelArn', ''),
                            'customizationType': item.get('customizationType', ''),
                            'roleArn': item.get('roleArn', ''),
                            'endTime': item.get('endTime', ''),
                            'lastModifiedTime': item.get('lastModifiedTime', '')
                        }
                    elif service_type == 'InferenceProfile':
                        additional_metadata = {
                            'inferenceProfileName': item.get('inferenceProfileName', ''),
                            'description': item.get('description', ''),
                            'status': item.get('status', ''),
                            'type': item.get('type', ''),
                            'models': item.get('models', []),
                            'updatedAt': item.get('updatedAt', '')
                        }
                    elif service_type == 'ModelInvocationJob':
                        additional_metadata = {
                            'jobName': item.get('jobName', ''),
                            'modelId': item.get('modelId', ''),
                            'clientRequestToken': item.get('clientRequestToken', ''),
                            'roleArn': item.get('roleArn', ''),
                            'status': item.get('status', ''),
                            'message': item.get('message', ''),
                            'lastModifiedTime': item.get('lastModifiedTime', ''),
                            'endTime': item.get('endTime', ''),
                            'inputDataConfig': item.get('inputDataConfig', {}),
                            'outputDataConfig': item.get('outputDataConfig', {}),
                            'vpcConfig': item.get('vpcConfig', {}),
                            'timeoutDurationInHours': item.get('timeoutDurationInHours', 0),
                            'jobExpirationTime': item.get('jobExpirationTime', '')
                        }
                    elif service_type == 'Guardrail':
                        additional_metadata = {
                            'name': item.get('name', ''),
                            'description': item.get('description', ''),
                            'id': item.get('id', ''),
                            'version': item.get('version', ''),
                            'status': item.get('status', ''),
                            'updatedAt': item.get('updatedAt', '')
                        }
                    elif service_type == 'EvaluationJob':
                        additional_metadata = {
                            'jobName': item.get('jobName', ''),
                            'status': item.get('status', ''),
                            'jobType': item.get('jobType', ''),
                            'evaluationTaskTypes': item.get('evaluationTaskTypes', []),
                            'modelIdentifiers': item.get('modelIdentifiers', []),
                            'roleArn': item.get('roleArn', '')
                        }
                    elif service_type == 'ModelCopyJob':
                        additional_metadata = {
                            'jobName': item.get('jobName', ''),
                            'status': item.get('status', ''),
                            'sourceAccountId': item.get('sourceAccountId', ''),
                            'sourceModelArn': item.get('sourceModelArn', ''),
                            'targetModelName': item.get('targetModelName', ''),
                            'roleArn': item.get('roleArn', ''),
                            'targetModelKmsKeyArn': item.get('targetModelKmsKeyArn', ''),
                            'targetModelTags': item.get('targetModelTags', []),
                            'failureMessage': item.get('failureMessage', ''),
                            'sourceModelName': item.get('sourceModelName', '')
                        }
                    elif service_type == 'ModelImportJob':
                        additional_metadata = {
                            'jobName': item.get('jobName', ''),
                            'status': item.get('status', ''),
                            'lastModifiedTime': item.get('lastModifiedTime', ''),
                            'endTime': item.get('endTime', ''),
                            'importedModelArn': item.get('importedModelArn', ''),
                            'importedModelName': item.get('importedModelName', '')
                        }
                    elif service_type == 'ImportedModel':
                        additional_metadata = {
                            'modelName': item.get('modelName', ''),
                            'modelArchitecture': item.get('modelArchitecture', ''),
                            'instructSupported': item.get('instructSupported', False)
                        }
                    elif service_type == 'PromptRouter':
                        additional_metadata = {
                            'promptRouterName': item.get('promptRouterName', ''),
                            'routingCriteria': item.get('routingCriteria', {}),
                            'description': item.get('description', ''),
                            'status': item.get('status', ''),
                            'models': item.get('models', []),
                            'fallbackModel': item.get('fallbackModel', {}),
                            'type': item.get('type', ''),
                            'updatedAt': item.get('updatedAt', '')
                        }
                    elif service_type == 'MarketplaceModelEndpoint':
                        additional_metadata = {
                            'endpointName': item.get('endpointName', ''),
                            'endpointStatus': item.get('endpointStatus', ''),
                            'modelId': item.get('modelId', ''),
                            'desiredModelId': item.get('desiredModelId', ''),
                            'desiredInferenceComponentCount': item.get('desiredInferenceComponentCount', 0),
                            'inferenceComponentCount': item.get('inferenceComponentCount', 0),
                            'endpointStatusMessage': item.get('endpointStatusMessage', ''),
                            'lastModifiedTime': item.get('lastModifiedTime', '')
                        }
                    elif service_type == 'CustomModelDeployment':
                        additional_metadata = {
                            'deploymentName': item.get('deploymentName', ''),
                            'modelArn': item.get('modelArn', ''),
                            'status': item.get('status', ''),
                            'statusMessage': item.get('statusMessage', ''),
                            'lastModifiedTime': item.get('lastModifiedTime', '')
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
                    logger.warning(f"Error processing Bedrock item: {str(item_error)}")
                    continue

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} {service_type.lower()}s')

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in Bedrock discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources

def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    if tags_action == 2:        
        tag_keys = [item['key'] for item in tags]

    # Create Bedrock client with timeout protection
    session = boto3.Session()
    client_config = Config(
        read_timeout=15,
        connect_timeout=10,
        retries={'max_attempts': 2, 'mode': 'standard'}
    )
    
    try:
        bedrock_client = session.client('bedrock', region_name=region, config=client_config)
    except Exception as e:
        logger.error(f"Failed to create Bedrock client: {str(e)}")
        return []

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to Bedrock format (list of objects with 'key' and 'value')
                bedrock_tags = [{'key': tag['key'], 'value': tag['value']} for tag in tags]
                bedrock_client.tag_resource(
                    resourceARN=resource.arn,
                    tags=bedrock_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                bedrock_client.untag_resource(
                    resourceARN=resource.arn,
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
    """Parse tags from string format to list of dictionaries with 'key' and 'value'"""
    tags = []
    if tags_string:
        for tag_pair in tags_string.split(','):
            if ':' in tag_pair:
                key, value = tag_pair.split(':', 1)
                tags.append({'key': key.strip(), 'value': value.strip()})
    return tags

import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    """
    AWS SageMaker resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sagemaker/client/add_tags.html
    
    SageMaker supports tagging for many resources. This includes the most commonly used ones:
    - TrainingJob (Training jobs for ML models)
    - Model (ML models)
    - Endpoint (Model endpoints for inference)
    - EndpointConfig (Endpoint configurations)
    - NotebookInstance (Jupyter notebook instances)
    - ProcessingJob (Data processing jobs)
    - TransformJob (Batch transform jobs)
    - HyperParameterTuningJob (Hyperparameter tuning jobs)
    - AutoMLJob (AutoML jobs)
    - Domain (SageMaker Studio domains)
    - UserProfile (User profiles in domains)
    - App (Apps in domains)
    - Space (Spaces in domains)
    - CodeRepository (Git repositories)
    - Algorithm (Custom algorithms)
    - ModelPackage (Model packages)
    - Pipeline (ML pipelines)
    - Experiment (ML experiments)
    - Trial (Experiment trials)
    - TrialComponent (Trial components)
    - FeatureGroup (Feature store groups)
    - Project (SageMaker projects)
    - Cluster (Training clusters)
    """

    resource_configs = {
        'TrainingJob': {
            'method': 'list_training_jobs',
            'key': 'TrainingJobSummaries',
            'id_field': 'TrainingJobArn',
            'name_field': 'TrainingJobName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'Model': {
            'method': 'list_models',
            'key': 'Models',
            'id_field': 'ModelArn',
            'name_field': 'ModelName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'Endpoint': {
            'method': 'list_endpoints',
            'key': 'Endpoints',
            'id_field': 'EndpointArn',
            'name_field': 'EndpointName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'EndpointConfig': {
            'method': 'list_endpoint_configs',
            'key': 'EndpointConfigs',
            'id_field': 'EndpointConfigArn',
            'name_field': 'EndpointConfigName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'NotebookInstance': {
            'method': 'list_notebook_instances',
            'key': 'NotebookInstances',
            'id_field': 'NotebookInstanceArn',
            'name_field': 'NotebookInstanceName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'ProcessingJob': {
            'method': 'list_processing_jobs',
            'key': 'ProcessingJobSummaries',
            'id_field': 'ProcessingJobArn',
            'name_field': 'ProcessingJobName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'TransformJob': {
            'method': 'list_transform_jobs',
            'key': 'TransformJobSummaries',
            'id_field': 'TransformJobArn',
            'name_field': 'TransformJobName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'HyperParameterTuningJob': {
            'method': 'list_hyper_parameter_tuning_jobs',
            'key': 'HyperParameterTuningJobSummaries',
            'id_field': 'HyperParameterTuningJobArn',
            'name_field': 'HyperParameterTuningJobName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'AutoMLJob': {
            'method': 'list_auto_ml_jobs',
            'key': 'AutoMLJobSummaries',
            'id_field': 'AutoMLJobArn',
            'name_field': 'AutoMLJobName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'Domain': {
            'method': 'list_domains',
            'key': 'Domains',
            'id_field': 'DomainArn',
            'name_field': 'DomainName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'UserProfile': {
            'method': 'list_user_profiles',
            'key': 'UserProfiles',
            'id_field': 'UserProfileArn',
            'name_field': 'UserProfileName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'App': {
            'method': 'list_apps',
            'key': 'Apps',
            'id_field': 'AppArn',
            'name_field': 'AppName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'Space': {
            'method': 'list_spaces',
            'key': 'Spaces',
            'id_field': 'SpaceArn',
            'name_field': 'SpaceName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'CodeRepository': {
            'method': 'list_code_repositories',
            'key': 'CodeRepositorySummaryList',
            'id_field': 'CodeRepositoryArn',
            'name_field': 'CodeRepositoryName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'Algorithm': {
            'method': 'list_algorithms',
            'key': 'AlgorithmSummaryList',
            'id_field': 'AlgorithmArn',
            'name_field': 'AlgorithmName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'ModelPackage': {
            'method': 'list_model_packages',
            'key': 'ModelPackageSummaryList',
            'id_field': 'ModelPackageArn',
            'name_field': 'ModelPackageName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'Pipeline': {
            'method': 'list_pipelines',
            'key': 'PipelineSummaries',
            'id_field': 'PipelineArn',
            'name_field': 'PipelineName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'Experiment': {
            'method': 'list_experiments',
            'key': 'ExperimentSummaries',
            'id_field': 'ExperimentArn',
            'name_field': 'ExperimentName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'Trial': {
            'method': 'list_trials',
            'key': 'TrialSummaries',
            'id_field': 'TrialArn',
            'name_field': 'TrialName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'TrialComponent': {
            'method': 'list_trial_components',
            'key': 'TrialComponentSummaries',
            'id_field': 'TrialComponentArn',
            'name_field': 'TrialComponentName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'FeatureGroup': {
            'method': 'list_feature_groups',
            'key': 'FeatureGroupSummaries',
            'id_field': 'FeatureGroupArn',
            'name_field': 'FeatureGroupName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'Project': {
            'method': 'list_projects',
            'key': 'ProjectSummaryList',
            'id_field': 'ProjectArn',
            'name_field': 'ProjectName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'Cluster': {
            'method': 'list_clusters',
            'key': 'ClusterSummaries',
            'id_field': 'ClusterArn',
            'name_field': 'ClusterName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
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
        
        # SageMaker is regional
        client = session.client('sagemaker', region_name=region)
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for sagemaker client")

        method = getattr(client, config['method'])
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
                resource_id = item[config['id_field']]
                resource_name = item.get(config['name_field'], resource_id) if config['name_field'] else resource_id

                # Get creation date
                creation_date = None
                if config['date_field'] and config['date_field'] in item:
                    creation_date = item[config['date_field']]
                    if hasattr(creation_date, 'isoformat'):
                        creation_date = creation_date.isoformat()

                # Build ARN - for SageMaker, ARN is provided directly
                arn = resource_id

                # Get additional metadata based on resource type
                additional_metadata = {}
                if service_type == 'TrainingJob':
                    additional_metadata = {
                        'TrainingJobStatus': item.get('TrainingJobStatus', ''),
                        'TrainingEndTime': item.get('TrainingEndTime', '').isoformat() if hasattr(item.get('TrainingEndTime', ''), 'isoformat') else item.get('TrainingEndTime', ''),
                        'LastModifiedTime': item.get('LastModifiedTime', '').isoformat() if hasattr(item.get('LastModifiedTime', ''), 'isoformat') else item.get('LastModifiedTime', '')
                    }
                elif service_type == 'Endpoint':
                    additional_metadata = {
                        'EndpointStatus': item.get('EndpointStatus', ''),
                        'LastModifiedTime': item.get('LastModifiedTime', '').isoformat() if hasattr(item.get('LastModifiedTime', ''), 'isoformat') else item.get('LastModifiedTime', '')
                    }
                elif service_type == 'NotebookInstance':
                    additional_metadata = {
                        'NotebookInstanceStatus': item.get('NotebookInstanceStatus', ''),
                        'InstanceType': item.get('InstanceType', ''),
                        'LastModifiedTime': item.get('LastModifiedTime', '').isoformat() if hasattr(item.get('LastModifiedTime', ''), 'isoformat') else item.get('LastModifiedTime', '')
                    }
                elif service_type == 'Domain':
                    additional_metadata = {
                        'Status': item.get('Status', ''),
                        'LastModifiedTime': item.get('LastModifiedTime', '').isoformat() if hasattr(item.get('LastModifiedTime', ''), 'isoformat') else item.get('LastModifiedTime', '')
                    }

                # Get existing tags
                resource_tags = {}
                try:
                    tags_response = client.list_tags(ResourceArn=arn)
                    tags_list = tags_response.get('Tags', [])
                    # Convert SageMaker tag format to standard format
                    resource_tags = {tag.get('Key', ''): tag.get('Value', '') for tag in tags_list}
                except Exception as tag_error:
                    logger.warning(f"Could not retrieve tags for {resource_name}: {tag_error}")
                    resource_tags = {}

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

    # Create SageMaker client
    session = boto3.Session()
    sagemaker_client = session.client('sagemaker', region_name=region)

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to SageMaker format (list of objects)
                sagemaker_tags = [{'Key': tag['Key'], 'Value': tag['Value']} for tag in tags]
                sagemaker_client.add_tags(
                    ResourceArn=resource.arn,
                    Tags=sagemaker_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                sagemaker_client.delete_tags(
                    ResourceArn=resource.arn,
                    TagKeys=tag_keys
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

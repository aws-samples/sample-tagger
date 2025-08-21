import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    """
    AWS Comprehend resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/comprehend/client/tag_resource.html
    
    Comprehend supports tagging for:
    - DocumentClassifier (Custom document classification models)
    - EntityRecognizer (Custom entity recognition models)
    - Endpoint (Real-time inference endpoints)
    - Flywheel (Flywheel resources for iterative model training)
    - DocumentClassificationJob (Document classification jobs)
    - EntitiesDetectionJob (Entity detection jobs)
    - KeyPhrasesDetectionJob (Key phrases detection jobs)
    - SentimentDetectionJob (Sentiment analysis jobs)
    - TopicsDetectionJob (Topic modeling jobs)
    - DominantLanguageDetectionJob (Language detection jobs)
    - PiiEntitiesDetectionJob (PII entities detection jobs)
    - EventsDetectionJob (Events detection jobs)
    - TargetedSentimentDetectionJob (Targeted sentiment analysis jobs)
    """

    resource_configs = {
        'DocumentClassifier': {
            'method': 'list_document_classifiers',
            'key': 'DocumentClassifierPropertiesList',
            'id_field': 'DocumentClassifierArn',
            'name_field': 'DocumentClassifierName',
            'date_field': 'SubmitTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'EntityRecognizer': {
            'method': 'list_entity_recognizers',
            'key': 'EntityRecognizerPropertiesList',
            'id_field': 'EntityRecognizerArn',
            'name_field': 'RecognizerName',
            'date_field': 'SubmitTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'Endpoint': {
            'method': 'list_endpoints',
            'key': 'EndpointPropertiesList',
            'id_field': 'EndpointArn',
            'name_field': 'EndpointName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'Flywheel': {
            'method': 'list_flywheels',
            'key': 'FlywheelSummaryList',
            'id_field': 'FlywheelArn',
            'name_field': 'FlywheelName',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'DocumentClassificationJob': {
            'method': 'list_document_classification_jobs',
            'key': 'DocumentClassificationJobPropertiesList',
            'id_field': 'JobArn',
            'name_field': 'JobName',
            'date_field': 'SubmitTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'EntitiesDetectionJob': {
            'method': 'list_entities_detection_jobs',
            'key': 'EntitiesDetectionJobPropertiesList',
            'id_field': 'JobArn',
            'name_field': 'JobName',
            'date_field': 'SubmitTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'KeyPhrasesDetectionJob': {
            'method': 'list_key_phrases_detection_jobs',
            'key': 'KeyPhrasesDetectionJobPropertiesList',
            'id_field': 'JobArn',
            'name_field': 'JobName',
            'date_field': 'SubmitTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'SentimentDetectionJob': {
            'method': 'list_sentiment_detection_jobs',
            'key': 'SentimentDetectionJobPropertiesList',
            'id_field': 'JobArn',
            'name_field': 'JobName',
            'date_field': 'SubmitTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'TopicsDetectionJob': {
            'method': 'list_topics_detection_jobs',
            'key': 'TopicsDetectionJobPropertiesList',
            'id_field': 'JobArn',
            'name_field': 'JobName',
            'date_field': 'SubmitTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'DominantLanguageDetectionJob': {
            'method': 'list_dominant_language_detection_jobs',
            'key': 'DominantLanguageDetectionJobPropertiesList',
            'id_field': 'JobArn',
            'name_field': 'JobName',
            'date_field': 'SubmitTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'PiiEntitiesDetectionJob': {
            'method': 'list_pii_entities_detection_jobs',
            'key': 'PiiEntitiesDetectionJobPropertiesList',
            'id_field': 'JobArn',
            'name_field': 'JobName',
            'date_field': 'SubmitTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'EventsDetectionJob': {
            'method': 'list_events_detection_jobs',
            'key': 'EventsDetectionJobPropertiesList',
            'id_field': 'JobArn',
            'name_field': 'JobName',
            'date_field': 'SubmitTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'TargetedSentimentDetectionJob': {
            'method': 'list_targeted_sentiment_detection_jobs',
            'key': 'TargetedSentimentDetectionJobPropertiesList',
            'id_field': 'JobArn',
            'name_field': 'JobName',
            'date_field': 'SubmitTime',
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
        
        # Comprehend is regional
        client = session.client('comprehend', region_name=region)
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for comprehend client")

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

                # Build ARN - for Comprehend, ARN is provided directly
                arn = resource_id

                # Get additional metadata based on resource type
                additional_metadata = {}
                if service_type in ['DocumentClassifier', 'EntityRecognizer']:
                    additional_metadata = {
                        'Status': item.get('Status', ''),
                        'LanguageCode': item.get('LanguageCode', ''),
                        'TrainingStartTime': item.get('TrainingStartTime', '').isoformat() if hasattr(item.get('TrainingStartTime', ''), 'isoformat') else item.get('TrainingStartTime', ''),
                        'TrainingEndTime': item.get('TrainingEndTime', '').isoformat() if hasattr(item.get('TrainingEndTime', ''), 'isoformat') else item.get('TrainingEndTime', '')
                    }
                elif service_type == 'Endpoint':
                    additional_metadata = {
                        'Status': item.get('Status', ''),
                        'ModelArn': item.get('ModelArn', ''),
                        'DesiredInferenceUnits': item.get('DesiredInferenceUnits', ''),
                        'CurrentInferenceUnits': item.get('CurrentInferenceUnits', ''),
                        'LastModifiedTime': item.get('LastModifiedTime', '').isoformat() if hasattr(item.get('LastModifiedTime', ''), 'isoformat') else item.get('LastModifiedTime', '')
                    }
                elif service_type == 'Flywheel':
                    additional_metadata = {
                        'Status': item.get('Status', ''),
                        'ModelType': item.get('ModelType', ''),
                        'Message': item.get('Message', ''),
                        'LastModifiedTime': item.get('LastModifiedTime', '').isoformat() if hasattr(item.get('LastModifiedTime', ''), 'isoformat') else item.get('LastModifiedTime', '')
                    }
                elif 'Job' in service_type:
                    additional_metadata = {
                        'JobStatus': item.get('JobStatus', ''),
                        'LanguageCode': item.get('LanguageCode', ''),
                        'EndTime': item.get('EndTime', '').isoformat() if hasattr(item.get('EndTime', ''), 'isoformat') else item.get('EndTime', ''),
                        'Message': item.get('Message', '')
                    }

                # Get existing tags
                resource_tags = {}
                try:
                    tags_response = client.list_tags_for_resource(ResourceArn=arn)
                    tags_list = tags_response.get('Tags', [])
                    # Convert Comprehend tag format to standard format
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

    # Create Comprehend client
    session = boto3.Session()
    comprehend_client = session.client('comprehend', region_name=region)

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to Comprehend format (list of objects)
                comprehend_tags = [{'Key': tag['Key'], 'Value': tag['Value']} for tag in tags]
                comprehend_client.tag_resource(
                    ResourceArn=resource.arn,
                    Tags=comprehend_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                comprehend_client.untag_resource(
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

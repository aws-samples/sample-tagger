import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    """
    AWS SNS resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns/client/tag_resource.html
    
    SNS supports tagging for:
    - Topic (SNS topics for pub/sub messaging)
    """

    resource_configs = {
        'Topic': {
            'method': 'list_topics',
            'key': 'Topics',
            'id_field': 'TopicArn',
            'name_field': None,  # Will extract from ARN
            'date_field': None,  # Not available in list_topics
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
        
        # SNS is regional
        client = session.client('sns', region_name=region)
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for sns client")

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
                topic_arn = item[config['id_field']]
                
                # Extract topic name from ARN
                topic_name = topic_arn.split(':')[-1] if ':' in topic_arn else topic_arn
                
                # Get topic attributes for additional information
                additional_metadata = {}
                creation_date = None
                try:
                    attrs_response = client.get_topic_attributes(TopicArn=topic_arn)
                    attributes = attrs_response.get('Attributes', {})
                    
                    # Extract useful attributes
                    additional_metadata = {
                        'DisplayName': attributes.get('DisplayName', ''),
                        'Owner': attributes.get('Owner', ''),
                        'Policy': attributes.get('Policy', '')[:100] + '...' if attributes.get('Policy') else '',
                        'SubscriptionsConfirmed': attributes.get('SubscriptionsConfirmed', '0'),
                        'SubscriptionsPending': attributes.get('SubscriptionsPending', '0'),
                        'SubscriptionsDeleted': attributes.get('SubscriptionsDeleted', '0'),
                        'DeliveryPolicy': attributes.get('DeliveryPolicy', ''),
                        'EffectiveDeliveryPolicy': attributes.get('EffectiveDeliveryPolicy', ''),
                        'KmsMasterKeyId': attributes.get('KmsMasterKeyId', ''),
                        'FifoTopic': attributes.get('FifoTopic', 'false')
                    }
                    
                except Exception as attr_error:
                    logger.warning(f"Could not get attributes for topic {topic_name}: {attr_error}")

                # Get existing tags
                resource_tags = {}
                try:
                    tags_response = client.list_tags_for_resource(ResourceArn=topic_arn)
                    tags_list = tags_response.get('Tags', [])
                    # Convert list of tag objects to dict
                    resource_tags = {tag['Key']: tag['Value'] for tag in tags_list}
                except Exception as tag_error:
                    logger.warning(f"Could not retrieve tags for {topic_name}: {tag_error}")
                    resource_tags = {}

                # Combine original item with additional metadata
                metadata = {**item, **additional_metadata}

                resources.append({
                    "account_id": account_id,
                    "region": region,
                    "service": service,
                    "resource_type": service_type,
                    "resource_id": topic_name,
                    "name": topic_name,
                    "creation_date": creation_date,
                    "tags": resource_tags,
                    "tags_number": len(resource_tags),
                    "metadata": metadata,
                    "arn": topic_arn
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

    # Create SNS client
    session = boto3.Session()
    sns_client = session.client('sns', region_name=region)

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to SNS format (list of objects)
                sns_tags = [{'Key': tag['Key'], 'Value': tag['Value']} for tag in tags]
                sns_client.tag_resource(
                    ResourceArn=resource.arn,
                    Tags=sns_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                sns_client.untag_resource(
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

import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

def get_service_types(account_id, region, service, service_type):
    """
    AWS SSM Contacts resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ssm-contacts/client/tag_resource.html
    
    SSM Contacts supports tagging for:
    - Contact (SSM Contacts for incident management)
    """

    resource_configs = {
        'Contact': {
            'method': 'list_contacts',
            'key': 'Contacts',
            'id_field': 'ContactArn',
            'name_field': 'Alias',
            'date_field': None,  # Not available in list_contacts
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
        
        # SSM Contacts is regional
        client = session.client('ssm-contacts', region_name=region)
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for ssm-contacts client")

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
                contact_arn = item[config['id_field']]
                contact_alias = item.get(config['name_field'], contact_arn.split('/')[-1])
                
                # Extract contact ID from ARN for resource_id
                contact_id = contact_arn.split('/')[-1] if '/' in contact_arn else contact_arn

                # Get additional contact details
                additional_metadata = {}
                creation_date = None
                try:
                    contact_response = client.get_contact(ContactId=contact_arn)
                    contact_details = contact_response
                    
                    additional_metadata = {
                        'Type': contact_details.get('Type', 'PERSONAL'),
                        'DisplayName': contact_details.get('DisplayName', ''),
                        'Plan': contact_details.get('Plan', {})
                    }
                    
                    # Extract creation date if available
                    # Note: SSM Contacts doesn't provide creation date in the API response
                    
                except Exception as detail_error:
                    logger.warning(f"Could not get details for contact {contact_alias}: {detail_error}")

                # Get existing tags
                resource_tags = {}
                try:
                    tags_response = client.list_tags_for_resource(ResourceARN=contact_arn)
                    tags_list = tags_response.get('Tags', [])
                    # Convert list of tag objects to dict
                    resource_tags = {tag['Key']: tag['Value'] for tag in tags_list}
                except Exception as tag_error:
                    logger.warning(f"Could not retrieve tags for {contact_alias}: {tag_error}")
                    resource_tags = {}

                # Combine original item with additional metadata
                metadata = {**item, **additional_metadata}

                resources.append({
                    "account_id": account_id,
                    "region": region,
                    "service": service,
                    "resource_type": service_type,
                    "resource_id": contact_id,
                    "name": contact_alias,
                    "creation_date": creation_date,
                    "tags": resource_tags,
                    "tags_number": len(resource_tags),
                    "metadata": metadata,
                    "arn": contact_arn
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

    # Create SSM Contacts client
    session = boto3.Session()
    ssmcontacts_client = session.client('ssm-contacts', region_name=region)

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to SSM Contacts format (list of objects)
                ssmcontacts_tags = [{'Key': tag['Key'], 'Value': tag['Value']} for tag in tags]
                ssmcontacts_client.tag_resource(
                    ResourceARN=resource.arn,
                    Tags=ssmcontacts_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                ssmcontacts_client.untag_resource(
                    ResourceARN=resource.arn,
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

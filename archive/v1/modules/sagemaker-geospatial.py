import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError

# SageMaker Geospatial is only available in specific regions
SUPPORTED_REGIONS = [
    'us-west-2',  # US West (Oregon) - Confirmed working
    # Add more regions as they become available
]

def get_service_types(account_id, region, service, service_type):
    """
    AWS SageMaker Geospatial resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sagemaker-geospatial/client/tag_resource.html
    
    SageMaker Geospatial supports tagging for:
    - EarthObservationJob (Earth observation jobs for satellite imagery analysis)
    - VectorEnrichmentJob (Vector enrichment jobs for geospatial data processing)
    - RasterDataCollection (Raster data collections - read-only, managed by AWS)
    
    Note: 
    - RasterDataCollections are managed by AWS and may have limited tagging capabilities
    - SageMaker Geospatial is only available in specific regions: us-west-2
    """

    resource_configs = {
        'EarthObservationJob': {
            'method': 'list_earth_observation_jobs',
            'key': 'EarthObservationJobSummaries',
            'id_field': 'Arn',
            'name_field': 'Name',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'VectorEnrichmentJob': {
            'method': 'list_vector_enrichment_jobs',
            'key': 'VectorEnrichmentJobSummaries',
            'id_field': 'Arn',
            'name_field': 'Name',
            'date_field': 'CreationTime',
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'RasterDataCollection': {
            'method': 'list_raster_data_collections',
            'key': 'RasterDataCollectionSummaries',
            'id_field': 'Arn',
            'name_field': 'Name',
            'date_field': None,  # Not available for raster data collections
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
        # Check if region is supported
        if region not in SUPPORTED_REGIONS:
            raise ValueError(f"SageMaker Geospatial is not available in region {region}. Supported regions: {', '.join(SUPPORTED_REGIONS)}")
        
        service_types_list = get_service_types(account_id, region, service, service_type)        
        if service_type not in service_types_list:
            raise ValueError(f"Unsupported service type: {service_type}")

        config = service_types_list[service_type]
        
        # SageMaker Geospatial is regional
        client = session.client('sagemaker-geospatial', region_name=region)
        
        if not hasattr(client, config['method']):
            raise ValueError(f"Method {config['method']} not available for sagemaker-geospatial client")

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

                # Build ARN - for SageMaker Geospatial, ARN is provided directly
                arn = resource_id

                # Get additional metadata based on resource type
                additional_metadata = {}
                if service_type == 'EarthObservationJob':
                    additional_metadata = {
                        'Status': item.get('Status', ''),
                        'DurationInSeconds': item.get('DurationInSeconds', ''),
                        'Type': item.get('Type', '')
                    }
                elif service_type == 'VectorEnrichmentJob':
                    additional_metadata = {
                        'Status': item.get('Status', ''),
                        'DurationInSeconds': item.get('DurationInSeconds', ''),
                        'Type': item.get('Type', '')
                    }
                elif service_type == 'RasterDataCollection':
                    additional_metadata = {
                        'Description': item.get('Description', ''),
                        'DescriptionPageUrl': item.get('DescriptionPageUrl', ''),
                        'SupportedFilters': item.get('SupportedFilters', []),
                        'Type': item.get('Type', '')
                    }

                # Get existing tags
                resource_tags = {}
                try:
                    tags_response = client.list_tags_for_resource(ResourceArn=arn)
                    tags_dict = tags_response.get('Tags', {})
                    # SageMaker Geospatial returns tags as a dictionary
                    resource_tags = tags_dict
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
    
    # Check if region is supported
    if region not in SUPPORTED_REGIONS:
        logger.error(f"SageMaker Geospatial is not available in region {region}. Supported regions: {', '.join(SUPPORTED_REGIONS)}")
        return []
    
    results = []    
    tags = parse_tags(tags_string)

    if tags_action == 2:        
        tag_keys = list(tags.keys()) if isinstance(tags, dict) else [tag['Key'] for tag in tags]

    # Create SageMaker Geospatial client
    session = boto3.Session()
    geospatial_client = session.client('sagemaker-geospatial', region_name=region)

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to SageMaker Geospatial format (dictionary)
                if isinstance(tags, list):
                    geospatial_tags = {tag['Key']: tag['Value'] for tag in tags}
                else:
                    geospatial_tags = tags
                    
                geospatial_client.tag_resource(
                    ResourceArn=resource.arn,
                    Tags=geospatial_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                geospatial_client.untag_resource(
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
    """Parse tags from string format to dictionary"""
    tags = {}
    if tags_string:
        for tag_pair in tags_string.split(','):
            if ':' in tag_pair:
                key, value = tag_pair.split(':', 1)
                tags[key.strip()] = value.strip()
    return tags

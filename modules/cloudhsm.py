import json
import boto3
from typing import List, Dict, Tuple
from botocore.exceptions import OperationNotPageableError, ClientError, ConnectTimeoutError, ReadTimeoutError
from botocore.config import Config

def get_service_types(account_id, region, service, service_type):
    """
    AWS CloudHSM Classic resources that support tagging.
    Based on: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudhsm/client/add_tags_to_resource.html
    
    CloudHSM Classic supports tagging for:
    - HSM (Hardware Security Modules)
    - HAPG (High Availability Partition Groups)
    - LunaClient (Luna Network HSM clients)
    
    Note: CloudHSM Classic is the legacy version. CloudHSMv2 is the current recommended service.
    CloudHSM Classic may not be available in all regions or for new customers.
    """

    resource_configs = {
        'HSM': {
            'method': 'list_hsms',
            'key': 'HsmList',
            'id_field': 'HsmArn',
            'name_field': None,  # Will use HsmArn as name
            'date_field': None,  # Not available in list response
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'HAPG': {
            'method': 'list_hapgs',
            'key': 'HapgList',
            'id_field': 'HapgArn',
            'name_field': 'Label',
            'date_field': None,  # Not available in list response
            'nested': False,
            'arn_format': None  # ARN is provided directly
        },
        'LunaClient': {
            'method': 'list_luna_clients',
            'key': 'ClientList',
            'id_field': 'ClientArn',
            'name_field': 'Label',
            'date_field': None,  # Not available in list response
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
        
        # CloudHSM Classic is regional but may not be available in all regions
        # Configure client with short timeouts to prevent hanging
        client_config = Config(
            read_timeout=10,
            connect_timeout=5,
            retries={'max_attempts': 1, 'mode': 'standard'}
        )
        
        try:
            client = session.client('cloudhsm', region_name=region, config=client_config)
        except Exception as e:
            logger.warning(f"CloudHSM Classic client creation failed in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        
        if not hasattr(client, config['method']):
            logger.warning(f"Method {config['method']} not available for cloudhsm client")
            return f'{service}:{service_type}', "success", "", []

        method = getattr(client, config['method'])
        params = {}

        # Handle CloudHSM Classic API calls with proper error handling
        try:
            logger.info(f"Attempting to call CloudHSM Classic {config['method']} in region {region}")
            response = method(**params)
            page_iterator = [response]
            logger.info(f"CloudHSM Classic {config['method']} succeeded in region {region}")
        except (ConnectTimeoutError, ReadTimeoutError) as e:
            logger.warning(f"CloudHSM Classic timeout in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code in ['UnauthorizedOperation', 'AccessDenied', 'InvalidAction', 'ServiceUnavailable']:
                logger.warning(f"CloudHSM Classic not available in region {region}: {error_code}")
                return f'{service}:{service_type}', "success", "", []
            else:
                logger.error(f"CloudHSM Classic API error in region {region}: {str(e)}")
                return f'{service}:{service_type}', "error", str(e), []
        except Exception as e:
            logger.warning(f"CloudHSM Classic general error in region {region}: {str(e)}")
            return f'{service}:{service_type}', "success", "", []

        # Process each page of results
        for page in page_iterator:
            items = page.get(config['key'], [])

            for item in items:
                try:
                    resource_id = item[config['id_field']]
                    resource_name = item.get(config['name_field'], resource_id) if config['name_field'] else resource_id

                    # Get creation date (not available in CloudHSM Classic list responses)
                    creation_date = None

                    # Build ARN - CloudHSM Classic provides ARN directly
                    arn = resource_id

                    # Get additional metadata based on resource type
                    additional_metadata = {}
                    if service_type == 'HSM':
                        additional_metadata = {
                            'HsmArn': resource_id,
                            'Status': item.get('Status', ''),
                            'StatusDetails': item.get('StatusDetails', ''),
                            'AvailabilityZone': item.get('AvailabilityZone', ''),
                            'EniId': item.get('EniId', ''),
                            'EniIp': item.get('EniIp', ''),
                            'SubscriptionType': item.get('SubscriptionType', ''),
                            'SubscriptionStartDate': item.get('SubscriptionStartDate', ''),
                            'SubscriptionEndDate': item.get('SubscriptionEndDate', ''),
                            'VpcId': item.get('VpcId', ''),
                            'SubnetId': item.get('SubnetId', ''),
                            'IamRoleArn': item.get('IamRoleArn', ''),
                            'SerialNumber': item.get('SerialNumber', ''),
                            'VendorName': item.get('VendorName', ''),
                            'HsmType': item.get('HsmType', ''),
                            'SoftwareVersion': item.get('SoftwareVersion', '')
                        }
                    elif service_type == 'HAPG':
                        additional_metadata = {
                            'HapgArn': resource_id,
                            'HapgSerial': item.get('HapgSerial', ''),
                            'HsmsLastActionFailed': item.get('HsmsLastActionFailed', []),
                            'HsmsPendingDeletion': item.get('HsmsPendingDeletion', []),
                            'HsmsPendingRegistration': item.get('HsmsPendingRegistration', []),
                            'State': item.get('State', ''),
                            'LastModifiedTimestamp': item.get('LastModifiedTimestamp', ''),
                            'PartitionSerialList': item.get('PartitionSerialList', [])
                        }
                    elif service_type == 'LunaClient':
                        additional_metadata = {
                            'ClientArn': resource_id,
                            'Certificate': item.get('Certificate', ''),
                            'CertificateFingerprint': item.get('CertificateFingerprint', ''),
                            'LastModifiedTimestamp': item.get('LastModifiedTimestamp', '')
                        }

                    # Get existing tags with timeout protection
                    resource_tags = {}
                    try:
                        tags_response = client.list_tags_for_resource(ResourceArn=arn)
                        tags_list = tags_response.get('TagList', [])
                        # Convert CloudHSM Classic tag format to standard format
                        resource_tags = {tag.get('Key', ''): tag.get('Value', '') for tag in tags_list}
                    except (ConnectTimeoutError, ReadTimeoutError):
                        logger.warning(f"Timeout retrieving tags for CloudHSM resource {resource_name}")
                        resource_tags = {}
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
                except Exception as item_error:
                    logger.warning(f"Error processing CloudHSM item: {str(item_error)}")
                    continue

        logger.info(f'Discovery completed for {service}:{service_type}. Found {len(resources)} {service_type.lower()}s')

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.error(f"Error in CloudHSM discover function: {error_message}")

    return f'{service}:{service_type}', status, error_message, resources


####----| Tagging method
def tagging(account_id, region, service, client, resources, tags_string, tags_action, logger):
    
    logger.info(f'Tagging # Account : {account_id}, Region : {region}, Service : {service}')
    
    results = []    
    tags = parse_tags(tags_string)

    if tags_action == 2:        
        tag_keys = [item['Key'] for item in tags]

    # Create CloudHSM Classic client with timeout protection
    session = boto3.Session()
    client_config = Config(
        read_timeout=10,
        connect_timeout=5,
        retries={'max_attempts': 1, 'mode': 'standard'}
    )
    
    try:
        cloudhsm_client = session.client('cloudhsm', region_name=region, config=client_config)
    except Exception as e:
        logger.error(f"Failed to create CloudHSM client: {str(e)}")
        return []

    for resource in resources:            
        try:
            if tags_action == 1:
                # Add tags - Convert to CloudHSM Classic format (list of objects)
                cloudhsm_tags = [{'Key': tag['Key'], 'Value': tag['Value']} for tag in tags]
                cloudhsm_client.add_tags_to_resource(
                    ResourceArn=resource.arn,
                    TagList=cloudhsm_tags
                )
                        
            elif tags_action == 2:
                # Remove tags
                cloudhsm_client.remove_tags_from_resource(
                    ResourceArn=resource.arn,
                    TagKeyList=tag_keys
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
            
        except (ConnectTimeoutError, ReadTimeoutError) as e:
            logger.warning(f"Timeout processing CloudHSM resource {resource.identifier}: {str(e)}")
            results.append({
                'account_id': account_id,
                'region': region,
                'service': service,
                'identifier': resource.identifier,
                'arn': resource.arn,
                'status': 'error',
                'error': f"Timeout: {str(e)}"
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

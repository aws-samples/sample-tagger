import json
import boto3
import os
from datetime import datetime

def launch_ecs_tasks(task_count):
    """Launch ECS Fargate tasks based on workload"""
    ecs = boto3.client('ecs')
    
    try:
        cluster = os.environ.get('ECS_CLUSTER')
        task_definition = os.environ.get('TASK_DEFINITION')
        subnets = os.environ.get('SUBNETS', '').split(',')
        security_groups = os.environ.get('SECURITY_GROUPS', '').split(',')
        
        for _ in range(task_count):
            response = ecs.run_task(
                cluster=cluster,
                taskDefinition=task_definition,
                launchType='FARGATE',
                networkConfiguration={
                    'awsvpcConfiguration': {
                        'subnets': subnets,
                        'securityGroups': security_groups,
                        'assignPublicIp': 'ENABLED'
                    }
                }
            )
            print(f"Launched ECS task: {response['tasks'][0]['taskArn']}")
            
    except Exception as e:
        print(f"Error launching ECS tasks: {e}")
        raise

def lambda_handler(event, context):
    """
    Lambda function to orchestrate MAP tagging by sending jobs to SQS and launching ECS tasks
    Configuration is read from environment variables.
    """
    
    # Get configuration from environment variables
    accounts = os.environ.get('ACCOUNTS', '').split(',') if os.environ.get('ACCOUNTS') else []
    regions = os.environ.get('REGIONS', 'us-east-1').split(',')
    services = os.environ.get('SERVICES', '').split(',') if os.environ.get('SERVICES') else get_supported_services()
    start_date = os.environ.get('START_DATE', '2024-01-01')
    map_tag_key = os.environ.get('MAP_TAG_KEY', 'map-migrated')
    map_tag_value = os.environ.get('MAP_TAG_VALUE', '12345')
    
    # Remove empty strings from lists
    accounts = [acc.strip() for acc in accounts if acc.strip()]
    regions = [reg.strip() for reg in regions if reg.strip()]
    services = [svc.strip() for svc in services if svc.strip()]
    
    queue_url = os.environ.get('QUEUE_URL')
    if not queue_url:
        raise ValueError("QUEUE_URL environment variable not set")
    
    sqs = boto3.client('sqs')
    
    messages_sent = 0
    
    # Create a job for each combination of account, region, and service
    for account_id in accounts:
        for region in regions:
            for service in services:
                message = {
                    'account_id': account_id,
                    'region': region,
                    'service': service,
                    'start_date': start_date,
                    'map_tag_key': map_tag_key,
                    'map_tag_value': map_tag_value,
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                try:
                    response = sqs.send_message(
                        QueueUrl=queue_url,
                        MessageBody=json.dumps(message),
                        MessageAttributes={
                            'service': {
                                'StringValue': service,
                                'DataType': 'String'
                            },
                            'account_id': {
                                'StringValue': account_id,
                                'DataType': 'String'
                            },
                            'region': {
                                'StringValue': region,
                                'DataType': 'String'
                            }
                        }
                    )
                    messages_sent += 1
                    print(f"Sent message for {service} in {account_id}/{region}")
                    
                except Exception as e:
                    print(f"Error sending message for {service} in {account_id}/{region}: {e}")
    
    # Launch ECS tasks based on number of messages
    if messages_sent > 0:
        # Calculate number of tasks to launch
        # Adjust these numbers based on your needs
        messages_per_task = int(os.environ.get('MESSAGES_PER_TASK', '100'))
        max_tasks = int(os.environ.get('MAX_TASKS', '10'))
        
        # Calculate desired number of tasks
        task_count = min(messages_sent // messages_per_task + 1, max_tasks)
        print(f"Launching {task_count} tasks for {messages_sent} messages")
        
        try:
            launch_ecs_tasks(task_count)
        except Exception as e:
            print(f"Failed to launch ECS tasks: {e}")
            # Note: Messages are still in queue and can be processed later
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': f'Successfully queued {messages_sent} tagging jobs',
            'jobs_queued': messages_sent,
            'tasks_launched': task_count if messages_sent > 0 else 0
        })
    }

def get_supported_services():
    """Return list of supported AWS services for MAP tagging"""
    return [
        'apigateway', 'apigatewayv2', 'apprunner', 'athena', 'backup',
        'bedrock', 'bedrock-agent', 'bedrock-data-automation', 'cloudfront',
        'cloudhsm', 'cloudhsmv2', 'cognito-identity', 'cognito-idp',
        'comprehend', 'connect', 'connectcampaigns', 'connectcampaignsv2',
        'connectcases', 'databrew', 'datasync', 'datazone', 'directconnect',
        'docdb', 'drs', 'ds', 'dynamodb', 'ec2', 'ecr', 'ecs', 'efs',
        'eks', 'elasticache', 'elasticbeanstalk', 'elb', 'elbv2', 'emr',
        'fsx', 'glacier', 'glue', 'kafka', 'kafkaconnect', 'kendra',
        'kendraranking', 'kms', 'lambda', 'medical-imaging', 'memorydb',
        'mgn', 'neptune', 'neptune-graph', 'network-firewall', 'rds',
        'redshift', 'redshift-serverless', 'rekognition', 'route53',
        'route53domains', 'route53profiles', 'route53resolver',
        'route53-recovery-control-config', 'route53-recovery-readiness',
        's3', 's3control', 'sagemaker', 'sagemaker-geospatial',
        'secretsmanager', 'securityhub', 'sns', 'sqs', 'ssm',
        'ssm-contacts', 'ssm-incidents', 'stepfunctions', 'storagegateway',
        'textract', 'timestream-write', 'transfer', 'waf', 'waf-regional',
        'wafv2', 'wisdom', 'workspaces'
    ]
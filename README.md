# Taggr Solution for AWS Services

> **Disclaimer:** The sample code; software libraries; command line tools; proofs of concept; templates; or other related technology (including any of the foregoing that are provided by our personnel) is provided to you as AWS Content under the AWS Customer Agreement, or the relevant written agreement between you and AWS (whichever applies). You are responsible for testing, securing, and optimizing the AWS Content, such as sample code, as appropriate for production grade use based on your specific quality control practices and standards. Deploying AWS Content may incur AWS charges for creating or using AWS chargeable resources, such as running Amazon App Runner, using Cognito, API Gateway, Aurora DSQL, Lambda, S3.


## What is Taggr Solution ?

Taggr Solution a revolutionary application designed to streamline and enhance your AWS metadata management.

This powerful tool automates the tagging process across multiple accounts and regions, providing unprecedented control and visibility over your cloud infrastructure. With its advanced filtering capabilities and comprehensive metadata management,

Taggr Solution empowers organizations to optimize their AWS resources, improve cost allocation, and enhance security compliance effortlessly.



## Key features

- Cross-account and cross-region automated tagging.

- Custom tag filtering for precise resource management.

- Comprehensive metadata search functionality.

- Fully serverless architecture for scalability and cost-efficiency.



## Use cases

- #### Cost Allocation
A large enterprise uses Taggr Solution to automatically tag resources across multiple departments, enabling accurate cost attribution and budgeting.

- #### Security Compliance
A financial services company leverages the application to ensure all resources are properly tagged for regulatory compliance, using custom filters to identify and rectify any non-compliant resources.

- #### Resource Optimization
A startup uses the metadata search feature to quickly locate underutilized resources across their AWS infrastructure, allowing them to optimize their cloud spend and improve efficiency.



## Architecture and Deployment Options

### Private Deployment Architecture

<img width="1089" alt="image" src="frontend/src/img/architecture-private.png">

The Private deployment of the Taggr Solution is designed for organizations requiring enhanced network security and isolation.
Key Components:

1.	Network Configuration
    - Deployed within a dedicated VPC
    - Uses Private Subnets for resource placement
    - Includes a Private Endpoint for secure internal access
    - Security Group controls traffic flow to App Runner service

2.	Frontend Service
    - AWS App Runner hosts the web application
    - Access is restricted through VPC Endpoint integration
    - Not directly exposed to the public internet

3.	Authentication
    - Amazon Cognito provides secure user authentication
    - API Gateway integrates with Cognito for authorization
    - User sessions are securely managed through Cognito tokens


4.	Backend Services
    - API Gateway manages and routes API requests
    - Lambda functions perform business logic and data processing
    - Lambda loads required Python libraries from an S3 Bucket
    - Aurora DSQL database stores application metadata and configuration

5.	Cross-Account Access
    - IAM Roles enable secure cross-account access
    - Solution can manage resources across multiple AWS accounts
    - Principle of least privilege enforced throughout


#### Benefits:
- Enhanced security through network isolation
- Access restricted to users within the VPC or through VPC endpoints
- Reduced attack surface by eliminating direct internet exposure
- Complies with strict network security requirements
- Suitable for sensitive environments and regulated industries


### Public Deployment Architecture

<img width="1089" alt="image" src="frontend/src/img/architecture-public.png">


The Public deployment of the Taggr Solution provides easier accessibility while maintaining security controls.
Key Components:

1.	Network Configuration
    - Deployed with public accessibility
    - AWS Web Application Firewall (WAF) protects the application from common web threats
    - IP-based access controls via CIDR rules in WAF configuration

2.	Frontend Service
    - AWS App Runner hosts the web application
    - Directly accessible over the internet through WAF
    - WAF filters and protects against malicious traffic

3.	Authentication
    - Amazon Cognito provides secure user authentication
    - API Gateway integrates with Cognito for authorization
    - User sessions are securely managed through Cognito tokens

4.	Backend Services
    - API Gateway manages and routes API requests
    - Lambda functions perform business logic and data processing
    - Lambda loads required Python libraries from an S3 Bucket
    - Aurora DSQL database stores application metadata and configuration

5.	Cross-Account Access
    - IAM Roles enable secure cross-account access
    - Solution can manage resources across multiple AWS accounts
    - Principle of least privilege enforced throughout

#### Benefits:
- Simplified accessibility from anywhere with internet access
- Web Application Firewall provides security for internet-facing resources
- IP filtering capabilities for controlled access
- Easier onboarding for users outside your corporate network
- Reduced network infrastructure complexity
- Suitable for less restrictive environments and broader user bases



## How looks like ?


<img width="1089" alt="image" src="img/img-01.png">
<img width="1089" alt="image" src="img/img-02.png">
<img width="1089" alt="image" src="img/img-04.png">
<img width="1089" alt="image" src="img/img-08.png">

 

## Solution Deployment

> **Time to deploy:** Approximately 10 minutes.

### Public method access version


Follow these step-by-step instructions to configure and deploy the Taggr Solution Frontend into your AWS account using CloudFormation.

1. Download clodformation template ([cloudformation.public.yaml](https://raw.githubusercontent.com/aws-samples/sample-tagger/refs/heads/main/cloudformation.public.yaml))
    
2. Sign in to the AWS Management Console
    - Navigate to the AWS Console (https://console.aws.amazon.com )
    - Sign in with your credentials

3. Navigate to the AWS CloudFormation service
    - From the AWS Console, search for "CloudFormation" in the search bar
    - Click on the CloudFormation service


4. Start Stack Creation
    - Click the "Create stack" button
    - Select "With new resources (standard)"


5. Specify Template Source
    - Choose "Upload a template file"
    - Click "Choose file" and select your CloudFormation template file
    - Click "Next"

6. Specify Stack Details
    - Enter a meaningful name for the stack in the "Stack name" field (e.g., "tagger-solution-frontend")


7. Configure General Configuration Parameters
    - GitHubRepositoryUrl: Enter the HTTPS URL for your GitHub repository where the Taggr Solution code is stored
    - AppUser: Enter the email address that will be used for the application user (e.g., admin@example.com )

8. Configure Network and Security Parameters
    - WAFRequired: Select "true" if you want to enable AWS WAF protection, or "false" to disable it
    - IPv4CIDR: (Optional, required only if WAF is enabled) Enter the IPv4 CIDR range that should be allowed access (e.g., 192.168.1.0/24)
    - IPv6CIDR: (Optional, required only if WAF is enabled) Enter the IPv6 CIDR range that should be allowed access (e.g., 2605:59c8:731d:4810:415:bd81:f251:f260/128)


9. Configure Stack Options (Optional)
    - Add any tags to help identify and manage your stack resources
    - Configure advanced options if needed (notifications, stack policy, rollback configuration, etc.)
    - Click "Next"

10. Review Stack Configuration
    - Review all the parameters and settings for your stack
    - Scroll down and check the acknowledgment box that states "I acknowledge that AWS CloudFormation might create IAM resources with custom names"
    - Click "Create stack"

11. Monitor Stack Creation
    - The CloudFormation console will display the stack creation status
    - View the "Events" tab to monitor the progress and troubleshoot any issues
    - Wait until the stack status changes to "CREATE_COMPLETE"

12. Access Stack Outputs
    - Once the stack creation is complete, navigate to the "Outputs" tab
    - Here you'll find important information such as the URL to access the frontend application
    - Log in using the provided application user email (you may receive temporary credentials via email)



### Private method access version


Follow these step-by-step instructions to configure and deploy the Taggr Solution Frontend into your AWS account using CloudFormation.


1. Download clodformation template ([cloudformation.private.yaml](https://raw.githubusercontent.com/aws-samples/sample-tagger/refs/heads/main/cloudformation.private.yaml))

2. Sign in to the AWS Management Console
    - Navigate to the AWS Console (https://console.aws.amazon.com )
    - Sign in with your credentials



3. Navigate to the AWS CloudFormation service
        - From the AWS Console, search for "CloudFormation" in the search bar
        - Click on the CloudFormation service


4. Start Stack Creation
    - Click the "Create stack" button
    - Select "With new resources (standard)"

5. Specify Template Source
    - Choose "Upload a template file"
    - Click "Choose file" and select your CloudFormation template file
    - Click "Next"

6. Specify Stack Details
    - Enter a meaningful name for the stack in the "Stack name" field (e.g., "tagger-solution-frontend")

7. Configure General Configuration Parameters
    - GitHubRepositoryUrl: Enter the HTTPS URL for your GitHub repository where the Taggr Solution code is stored
    - AppUser: Enter the email address that will be used for the application user (e.g., admin@example.com )


8. Configure Network and Security Parameters
    - VPCId: Select the VPC ID where you want to deploy the App Runner service
    - SubnetId: Select the Subnet ID for the App Runner VPC Connector
    - IPv4CIDR: Enter the IPv4 CIDR range that should be allowed access through AWS Security Group (e.g., 192.168.1.0/24)
    - IPv6CIDR: Enter the IPv6 CIDR range that should be allowed access through AWS Security Group (e.g., 2605:59c8:731d:4810:415:bd81:f251:f260/128)

9. Configure Stack Options (Optional)
    - Add any tags to help identify and manage your stack resources
    - Configure advanced options if needed (notifications, stack policy, rollback configuration, etc.)
    - Click "Next"


10. Review Stack Configuration
    - Review all the parameters and settings for your stack
    - Scroll down and check the acknowledgment box that states "I acknowledge that AWS CloudFormation might create IAM resources with custom names"
    - Click "Create stack"


11. Monitor Stack Creation
    - The CloudFormation console will display the stack creation status
    - View the "Events" tab to monitor the progress and troubleshoot any issues
    - Wait until the stack status changes to "CREATE_COMPLETE"


12. Access Stack Outputs
    - Once the stack creation is complete, navigate to the "Outputs" tab
    - Here you'll find important information such as the URL to access the frontend application
    - Save or note down these output values for future reference

13. Verify Deployment
    - Once the stack creation is complete, navigate to the "Outputs" tab
    - Here you'll find important information such as the URL to access the frontend application
    - Log in using the provided application user email (you may receive temporary credentials via email)



### IAM Role Deployment

If the tagging process needs to be performed across multiple AWS accounts (which is the most common scenario), you will need to deploy a cross-account IAM role to access those accounts. The recommended approach is to deploy this role as an AWS CloudFormation StackSet from your management account. This will allow the role to be accessible across all the accounts that are part of the MAP project.

1. Download clodformation template ([cloudformation.iam.role.yaml](https://raw.githubusercontent.com/aws-samples/sample-tagger/refs/heads/main/cloudformation.iam.role.yaml))

2.	Sign in to the AWS Management Console.
3.	Navigate to the AWS CloudFormation service.
4.	Click on StackSets on the left-side menu.
5.	Click on Create StackSet.
6.	In the "Choose template" screen, select Service-managed permissions.
7.	Specify Template Source
    - Choose "Upload a template file" 
    - Click "Choose file" and select your CloudFormation template (cloudformation.iam.role.yaml)    
    - Click "Next"
8.	Enter a name for the StackSet in the "StackSet name" field.
9.	In the "RoleARN" field enter the role ARN that was created during the the first template deployment (found in the Outputs section).
10.	Click Next.
11.	In the “Set deployment options” select Deploy new stacks.
12.	Under the “Deployment targets” section select the option that fits best for the deployment.
13.	Under "Specify regions," select only one region (e.g., US East - N. Virginia).
Note: Since this CloudFormation StackSet only deploys an IAM role, which is a global service, selecting multiple regions will cause deployment errors. The StackSet will attempt to deploy the same IAM role in each region, leading to failures.
15.	Under "Deployment options," set Failure tolerance to 1. Important: This setting is crucial because the StackSet will attempt to redeploy the existing role in the original account. If the tolerance is not set to 1, the entire deployment will fail.
16.	In the "Review" screen, verify that all the parameters are correct.
17.	Select the I acknowledge that AWS CloudFormation might create IAM resources with custom names checkbox.
18.	Click Submit.


## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.



## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE.txt) file.



CREATE TABLE IF NOT EXISTS tbprofiles (            
            profile_id VARCHAR,            
            json_profile VARCHAR,
            PRIMARY KEY (profile_id)
);

CREATE TABLE IF NOT EXISTS tbprocess (            
            scan_id VARCHAR,            
            name VARCHAR,
            parameters VARCHAR,
            start_time VARCHAR,
            end_time VARCHAR,
            status VARCHAR,
            message VARCHAR,
            resources INT DEFAULT 0,
            start_time_tagging VARCHAR,
            end_time_tagging VARCHAR,
            status_tagging VARCHAR,
            message_tagging VARCHAR,
            resources_tagged_success INT DEFAULT 0,
            resources_tagged_error INT DEFAULT 0,
            action INT DEFAULT 0,
            type INT DEFAULT 0,
            PRIMARY KEY (scan_id)
);

CREATE TABLE IF NOT EXISTS tbresources (            
            scan_id VARCHAR,            
            seq INT,
            account_id VARCHAR,
            region VARCHAR,
            service VARCHAR,
            resource_type VARCHAR,
            resource_id VARCHAR,
            name VARCHAR,
            creation_date VARCHAR,
            tags VARCHAR,
            metadata VARCHAR,
            action INT default 0,
            tags_number INT default 0,            
            arn VARCHAR,
            PRIMARY KEY (scan_id,seq)
);


CREATE TABLE IF NOT EXISTS tbtag_errors (            
            scan_id VARCHAR,            
            account_id VARCHAR,
            region VARCHAR,
            service VARCHAR,
            resource_id VARCHAR,
            arn VARCHAR,
            status VARCHAR,
            error VARCHAR
);



INSERT INTO tbprofiles (profile_id,json_profile) VALUES ('001','{"name": "Profile-Metadata-Search", "description": "Profile used for Metadata Search", "accounts": ["1234567890"], "regions": ["us-east-1"], "services": ["apigateway::RestApi", "apigateway::RestApiPrivate", "apigatewayv2::HttpApi", "apigatewayv2::WebSocketApi", "backup::BackupPlan", "backup::BackupVault", "docdb::Cluster", "docdb::Instance","docdb::Snapshot", "dynamodb::Table", "ec2::CustomerGateway", "ec2::EIP", "ec2::Image", "ec2::Instance", "ec2::InternetGateway", "ec2::NatGateway", "ec2::NetworkACL", "ec2::RouteTable","ec2::SecurityGroup", "ec2::Snapshot", "ec2::Subnet", "ec2::TransitGateway", "ec2::TransitGatewayAttachment", "ec2::TransitGatewayRouteTable", "ec2::TransitGatewayVpcAttachment", "ec2::VPC", "ec2::VPNConnection", "ec2::VPNGateway", "ec2::Volume", "ecr::Repository", "ecs::Cluster", "efs::FileSystem", "eks::Cluster", "elasticache::ReplicationGroup", "elasticache::Snapshot", "elb::ClassicLoadBalancer", "elbv2::ApplicationLoadBalancer", "elbv2::NetworkLoadBalancer", "emr::Cluster", "fsx::Backup", "fsx::FileSystem", "lambda::Function", "memorydb::Cluster", "memorydb::Snapshot", "neptune::Cluster", "neptune::Instance", "neptune::Snapshot", "rds::DBCluster", "rds::DBClusterSnapshot", "rds::DBInstance", "rds::DBSnapshot", "s3::Bucket", "timestream-write::Table", "transfer::Server", "workspaces::Workspace"], "filter": "", "tags": [], "action": "add"}');
              
INSERT INTO tbprofiles (profile_id,json_profile) VALUES ('002','{"name": "Profile-Map-Tagger", "description": "Profile used for AWS MAP Program", "accounts": ["1234567890", "123456789012"], "regions": ["us-east-1", "us-east-2"], "services": ["apigateway::RestApi", "apigateway::RestApiPrivate", "apigatewayv2::HttpApi", "apigatewayv2::WebSocketApi", "backup::BackupPlan", "backup::BackupVault", "docdb::Cluster", "docdb::Instance","docdb::Snapshot", "dynamodb::Table", "ec2::CustomerGateway", "ec2::EIP", "ec2::Image", "ec2::Instance", "ec2::InternetGateway", "ec2::NatGateway", "ec2::NetworkACL", "ec2::RouteTable","ec2::SecurityGroup", "ec2::Snapshot", "ec2::Subnet", "ec2::TransitGateway", "ec2::TransitGatewayAttachment", "ec2::TransitGatewayRouteTable", "ec2::TransitGatewayVpcAttachment", "ec2::VPC", "ec2::VPNConnection", "ec2::VPNGateway", "ec2::Volume", "ecr::Repository", "ecs::Cluster", "efs::FileSystem", "eks::Cluster", "elasticache::ReplicationGroup", "elasticache::Snapshot", "elb::ClassicLoadBalancer", "elbv2::ApplicationLoadBalancer", "elbv2::NetworkLoadBalancer", "emr::Cluster", "fsx::Backup", "fsx::FileSystem", "lambda::Function", "memorydb::Cluster", "memorydb::Snapshot", "neptune::Cluster", "neptune::Instance", "neptune::Snapshot", "rds::DBCluster", "rds::DBClusterSnapshot", "rds::DBInstance", "rds::DBSnapshot", "s3::Bucket", "timestream-write::Table", "transfer::Server", "workspaces::Workspace"], "filter": " creation_date > ''2024-01-01 01:00'' AND POSITION(''map-migrated'' IN tags) = 0", "tags": [{"key": "map-migrated", "value": "12345678"}], "action": "add"}');

INSERT INTO tbprofiles (profile_id,json_profile) VALUES ('003','{"name": "Profile-Tag-Environment", "description": "Profile used to tag resources for Development Environments", "accounts": ["1234567890", "123456789012"], "regions": ["us-east-1"], "services": ["apigateway::RestApi", "apigateway::RestApiPrivate", "apigatewayv2::HttpApi", "apigatewayv2::WebSocketApi", "backup::BackupPlan", "backup::BackupVault", "docdb::Cluster", "docdb::Instance","docdb::Snapshot", "dynamodb::Table", "ec2::CustomerGateway", "ec2::EIP", "ec2::Image", "ec2::Instance", "ec2::InternetGateway", "ec2::NatGateway", "ec2::NetworkACL", "ec2::RouteTable","ec2::SecurityGroup", "ec2::Snapshot", "ec2::Subnet", "ec2::TransitGateway", "ec2::TransitGatewayAttachment", "ec2::TransitGatewayRouteTable", "ec2::TransitGatewayVpcAttachment", "ec2::VPC", "ec2::VPNConnection", "ec2::VPNGateway", "ec2::Volume", "ecr::Repository", "ecs::Cluster", "efs::FileSystem", "eks::Cluster", "elasticache::ReplicationGroup", "elasticache::Snapshot", "elb::ClassicLoadBalancer", "elbv2::ApplicationLoadBalancer", "elbv2::NetworkLoadBalancer", "emr::Cluster", "fsx::Backup", "fsx::FileSystem", "lambda::Function", "memorydb::Cluster", "memorydb::Snapshot", "neptune::Cluster", "neptune::Instance", "neptune::Snapshot", "rds::DBCluster", "rds::DBClusterSnapshot", "rds::DBInstance", "rds::DBSnapshot", "s3::Bucket", "timestream-write::Table", "transfer::Server", "workspaces::Workspace"], "filter": " POSITION(''Environment'' IN tags) = 0 ", "tags": [{"key": "Environment", "value": "Development"}], "action": "add"}');

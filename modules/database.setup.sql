
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




INSERT INTO tbprofiles (profile_id,json_profile) VALUES ('001','{"name": "Profile-Metadata-Search", "description": "Profile used for Metadata Search", "accounts": ["039783469744"], "regions": ["All"], "services": ["ec2::Instance", "rds::DBInstance"], "filter": "", "tags": [], "action": "add"}');
              
INSERT INTO tbprofiles (profile_id,json_profile) VALUES ('002','{"name": "Profile-Map-Tagger", "description": "Profile used for AWS MAP Program", "accounts": ["039783469744", "568994528172"], "regions": ["us-east-1", "us-east-2"], "services": ["ec2::Instance", "rds::DBInstance"], "filter": " creation_date > ''2022-01-01 00:00'' and position( ''map-migrated'' in tags ) <= 0", "tags": [{"key": "map-migrated", "value": "12345678"}], "action": "add"}');

INSERT INTO tbprofiles (profile_id,json_profile) VALUES ('003','{"name": "Profile-Tag-Environment", "description": "Profile used to tag resources for Development Environments", "accounts": ["039783469744", "568994528172"], "regions": ["All"], "services": ["All"], "filter": " position( ''Environment'' in tags ) <= 0 and position( ''subnet-03bff4b2b43b0d393'' in metadata ) > 0 ", "tags": [{"key": "Environment", "value": "Development"}], "action": "add"}');

import os
import json
from datetime import datetime
import logging
import boto3
from typing import TypedDict, Any
import psycopg2
from psycopg2 import pool
import time
import importlib.util
import sys
import concurrent.futures
import math

logger = logging.getLogger()
logger.setLevel(logging.INFO)


######################################################
######################################################
###
###--------- CLASS : DataStore
###
######################################################
######################################################

class DataStore:

    ###
    ###-- Initialization
    ###
    
    def __init__(self,        
                db_config=None,
                region=None):
      
      # Configure logging
      logging.basicConfig(
          level=logging.INFO,
          format='%(asctime)s - %(levelname)s - %(message)s'
      )
      self.logger = logging.getLogger(__name__)
              
      # Create connection pool
      try:
          client = boto3.client("dsql", region_name=region)    
          password_token = client.generate_db_connect_admin_auth_token(db_config['host'], region)
          self.db_config = { **db_config, 'password' : password_token }
          self.connection_pool = psycopg2.pool.SimpleConnectionPool(
              1, 20, **self.db_config
          )
      except Exception as e:
          self.logger.error(f"Error creating database connection pool: {e}")
          raise


    ###
    ###-- Execute a query
    ###

    def execute_query(self,query):      

      connection = None
      cursor = None
      results = []
      try:
          connection = self.connection_pool.getconn()
          cursor = connection.cursor()
          cursor.execute(query)
          results = cursor.fetchall()
          connection.commit()          
      
      except Exception as e:
          self.logger.error(f"Error : {e}")
          if connection:
              connection.rollback()
          raise
      
      finally:
          if cursor:
              cursor.close()
          if connection:
              self.connection_pool.putconn(connection)
      
      print(results)
      return results


    ###
    ###-- Execute generic command
    ###

    def execute_command(self,query):      

      connection = None
      cursor = None
      results = []
      try:
          connection = self.connection_pool.getconn()
          cursor = connection.cursor()
          cursor.execute(query)          
          connection.commit()          
      
      except Exception as e:
          self.logger.error(f"Error : {e}")
          if connection:
              connection.rollback()
          raise
      
      finally:
          if cursor:
              cursor.close()
          if connection:
              self.connection_pool.putconn(connection)            
      return results


    ###
    ###-- Execute a insert command
    ###

    def execute_insert(self,query, data):      

      connection = None
      cursor = None
      results = []
      try:
          connection = self.connection_pool.getconn()
          cursor = connection.cursor()          
          cursor.executemany(query, 
                data
        )
          connection.commit()          
      
      except Exception as e:
          self.logger.error(f"Error : {e}")
          if connection:
              connection.rollback()
          raise
      
      finally:
          if cursor:
              cursor.close()
          if connection:
              self.connection_pool.putconn(connection)            
      return results


    ###
    ###-- Execute a DML
    ###

    def execute_dml(self,query, data):      

      connection = None
      cursor = None
      results = []
      try:
          connection = self.connection_pool.getconn()
          cursor = connection.cursor()          
          cursor.execute(query, data)
          connection.commit()          
      
      except Exception as e:
          self.logger.error(f"Error : {e}")
          if connection:
              connection.rollback()
          raise
      
      finally:
          if cursor:
              cursor.close()
          if connection:
              self.connection_pool.putconn(connection)            
      return results



    ###
    ###-- Execute a select command
    ###

    def execute_select(self, query, data):      
      
      connection = None
      cursor = None
      results = []
      try:
          connection = self.connection_pool.getconn()
          cursor = connection.cursor()          
          cursor.execute(query,data)          
          results = cursor.fetchall()
          connection.commit()          
      
      except Exception as e:
          self.logger.error(f"Error : {e}")
          if connection:
              connection.rollback()
          raise
      
      finally:
          if cursor:
              cursor.close()
          if connection:
              self.connection_pool.putconn(connection)            
      return results



######################################################
######################################################
###
###--------- CLASS : APIGatewayResponse
###
######################################################
######################################################

class APIGatewayResponse(TypedDict):
    statusCode: int
    headers: dict[str, str]
    body: str




######################################################
######################################################
###
###--------- CLASS : ErrorResponse
###
######################################################
######################################################

class ErrorResponse(TypedDict):
    message: str
    code: str




######################################################
######################################################
###
###--------- Contants
###
######################################################
######################################################


CORS_HEADERS = {
    "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,X-Amz-Security-Token,Authorization,X-Api-Key,X-Requested-With,Accept,Access-Control-Allow-Methods,Access-Control-Allow-Origin,Access-Control-Allow-Headers",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT",
    "X-Requested-With": "*"
}

ERROR_CODES = {
    "BAD_REQUEST": "BAD_REQUEST",
    "NOT_FOUND": "NOT_FOUND",
    "INTERNAL_ERROR": "INTERNAL_ERROR"
}


DB_CONFIG = {        
        'host': os.environ['DBHOST'],
        'database': os.environ['DBNAME'],
        'user': os.environ['DBUSER'],       
        'port': os.environ['DBPORT'],
        'sslmode': 'require'
    }

REGION = os.environ['REGION']

LAMBDA_METADATA_DISCOVERY = os.environ['LAMBDA_METADATA_DISCOVERY']

LAMBDA_METADATA_TAGGING = os.environ['LAMBDA_METADATA_TAGGING']

S3_BUCKET_MODULES = os.environ['S3_BUCKET_MODULES']

IAM_SCAN_ROLE = os.environ['IAM_SCAN_ROLE']

MAX_WORKERS = int(os.environ['MAX_WORKERS'])




######################################################
######################################################
###
###--------- Functions
###
######################################################
######################################################


def create_response(status_code: int, body: Any) -> APIGatewayResponse:
    return {
        "statusCode": status_code,
        "headers": CORS_HEADERS,
        "body": json.dumps(body)
    }

def create_error_response(status_code: int, message: str, code: str) -> APIGatewayResponse:
    error_response: ErrorResponse = {
        "message": message,
        "code": code
    }
    return create_response(status_code, error_response)



######################################################
######################################################
###
###--------- API Calls
###
######################################################
######################################################

###
###-- Get metadata results used by normal tagger process
###


def fn_01_get_metadata_results(event: dict) -> APIGatewayResponse:
    try:
        
        total_records  = 0
        resources = []
        
        # Get total pages
        select_query = """
        SELECT
            count(*)
        FROM
            tbresources
        WHERE
            scan_id = %s
            AND
            ( action = %s OR %s = 3)       
        """
        
        parameters = (event['scanId'],int(event['action']), int(event['action']) )

        ds = DataStore(db_config=DB_CONFIG, region=REGION)
        rows = ds.execute_select(select_query,parameters)
        for row in rows:
            total_records = row[0]
        
        pages = math.ceil(total_records / int(event['limit']))

        # Get all resources
        select_query = """
        SELECT
            scan_id,            
            seq,
            account_id, 
            region, 
            service,
            resource_type, 
            resource_id, 
            name,
            creation_date,
            tags,  
            tags_number,          
            action
        FROM
            tbresources
        WHERE
            scan_id = %s
            AND
            ( action = %s OR %s = 3)
        ORDER BY
            seq ASC
        OFFSET 
            %s
        LIMIT 
            %s

        """
    
        parameters = (event['scanId'],int(event['action']), int(event['action']), int(event['page']) * int(event['limit']), int(event['limit']) )

        ds = DataStore(db_config=DB_CONFIG, region=REGION)
        rows = ds.execute_select(select_query,parameters)
        for row in rows:
            resources.append({
                'scan_id' : row[0],
                'seq' : row[1],
                'account' : row[2],
                'region' : row[3],
                'service' : row[4],
                'type' : row[5],
                'identifier' : row[6],
                'name' : row[7],
                'creation' : row[8],
                'tags_list' : row[9],
                'tags_number' : row[10],                
                'action' : row[11]
            })

        return create_response(200, { 
                                        "response" :  { "resources" : resources, "pages" : pages, "records" : total_records }
                                    }
        )

    except Exception as e:
        logger.error(f"Error in fn_01_get_metadata_results: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )



###
###-- Launch discovery process with lambda invokation
###

def fn_02_create_metadata_search(event: dict) -> APIGatewayResponse:
    try:

        
        # Write data store record
        create_table_query = """        
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
        )
        """

        insert_query = """
        INSERT INTO tbprocess (
            scan_id,            
            name,
            parameters,
            start_time,
            end_time,
            status,
            message,
            type
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        insert_data = [
                (event['scanId'], event['name'], json.dumps(event['ruleset']), (datetime.now()).strftime("%Y-%m-%d %H:%M:%S"), "-", "in-progress", "-",  event['type'] )
        ]        

        ds = DataStore(db_config=DB_CONFIG, region=REGION)
        ds.execute_command(create_table_query)
        ds.execute_insert(insert_query, insert_data)
        

        # Call lambda function
        lambda_client = boto3.client('lambda', region_name=REGION)
        response=lambda_client.invoke(
            FunctionName=LAMBDA_METADATA_DISCOVERY,
            InvocationType='Event',
            Payload=json.dumps(event)
        )

        return create_response(200, { 
                                        "response" :  { "scan_id" : event['scanId'], "state" : "success" }
                                    }
        )

    except Exception as e:
        logger.error(f"Error in fn_02_create_metadata_search: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )


###
###-- Get status for normal tagger process
###

def fn_03_get_metadata_search_status(event: dict) -> APIGatewayResponse:
    try:
   
        select_query = """
        SELECT
            status,
            resources
        FROM
            tbprocess
        WHERE scan_id = %s
        """    
        
        parameters = (event["scanId"],)

        ds = DataStore(db_config=DB_CONFIG, region=REGION)
        rows = ds.execute_select(select_query, parameters)
        status = ""
        resources = 0
        for row in rows:
            status = row[0]            
            resources = row[1]

        return create_response(200, { 
                                        "response" :  { "status" : status, "resources" : resources }
                                    }
        )

    except Exception as e:
        logger.error(f"Error in fn_03_get_metadata_search_status: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )



###
###-- Update resource action - filter-in / filter-out
###

def fn_04_update_resource_action(event: dict) -> APIGatewayResponse:
    try:
   
        update_query = """
        UPDATE tbresources
        SET action = %s
        WHERE scan_id = %s AND seq = %s
        """

        parameters = (int(event['action']), event['scanId'], int(event['seq']))


        
        
        ds = DataStore(db_config=DB_CONFIG, region=REGION)
        ds.execute_dml(update_query, parameters)
                
        return create_response(200, { 
                                        "response" :  { "status" : "success" }
                                    }
        )

    except Exception as e:
        logger.error(f"Error in fn_04_update_resource_action: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )



###
###-- Launch tagging process with lambda invokation
###

def fn_05_create_tagging_process(event: dict) -> APIGatewayResponse:
    try:

    
        update_query = """
        UPDATE tbprocess 
        SET start_time_tagging = %s, status_tagging = %s, message_tagging = NULL
        WHERE scan_id = %s
        """

        parameters = ((datetime.now()).strftime("%Y-%m-%d %H:%M:%S"), "in-progress", event['scanId'])
        
        ds = DataStore(db_config=DB_CONFIG, region=REGION)        
        ds.execute_dml(update_query, parameters)
        

        # Call lambda function
        lambda_client = boto3.client('lambda', region_name=REGION)
        response=lambda_client.invoke(
            FunctionName=LAMBDA_METADATA_TAGGING,
            InvocationType='Event',
            Payload=json.dumps(event)
        )

        return create_response(200, { 
                                        "response" :  { "scan_id" : event['scanId'], "state" : "success" }
                                    }
        )

    except Exception as e:
        logger.error(f"Error in fn_05_create_tagging_processch: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )



###
###-- Get status for tagging process
###


def fn_06_get_tagging_process_status(event: dict) -> APIGatewayResponse:
    try:
   
        select_query = """
        SELECT
            status_tagging,
            message_tagging
        FROM
            tbprocess
        WHERE scan_id = %s
        """    
        
        parameters = (event["scanId"],)

        ds = DataStore(db_config=DB_CONFIG, region=REGION)
        rows = ds.execute_select(select_query, parameters)
        
        response = {
            "status" : "",
            "message" : ""
        }
        
        for row in rows:
            response['status'] = row[0]
            response['message'] = row[1]

        return create_response(200, { 
                                        "response" : response
                                    }
        )

    except Exception as e:
        logger.error(f"Error in fn_06_get_tagging_process_status: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )




###
###-- Get metadata for specific resource
###


def fn_07_get_resource_metadata(event: dict) -> APIGatewayResponse:
    try:
   
        select_query = """
        SELECT
            metadata
        FROM
            tbresources
        WHERE 
            scan_id = %s
            and
            seq = %s
        """    
        
        parameters = (event["scanId"],event["seq"])

        ds = DataStore(db_config=DB_CONFIG, region=REGION)
        rows = ds.execute_select(select_query, parameters)
        
        response = {
            "status" : "",
            "metadata" : ""
        }
        
        for row in rows:
            response['status'] = "success"
            response['metadata'] = row[0]

        return create_response(200, { 
                                        "response" : response
                                    }
        )

    except Exception as e:
        logger.error(f"Error in fn_07_get_resource_metadata: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )



###
###-- Get resources for specific tagging process
###

def fn_08_get_dataset_tagging(event: dict) -> APIGatewayResponse:
    try:
        
        ds = DataStore(db_config=DB_CONFIG, region=REGION)
        
        select_query = """
        SELECT
            scan_id,            
            parameters,
            start_time,
            end_time,
            status,
            message,
            resources,
            start_time_tagging,
            end_time_tagging,
            status_tagging,
            message_tagging,
            resources_tagged_success,
            resources_tagged_error,
            action
        FROM
            tbprocess
        WHERE
            start_time_tagging is NOT NULL
            and
            end_time_tagging is NOT NULL
            and
            type = 1
        ORDER BY
            scan_id DESC
        LIMIT
            %s
        
        """    
        
        parameters = (100,)
        rows = ds.execute_select(select_query, parameters)
        
        processes  = []
        summary = { "added" : [], "removed" : []}
        limit_records = 0
        for row in rows:
            processes.append({
                         "scan_id" : row[0], 
                         "parameters" : row[1], 
                         "start_time" : row[2], 
                         "end_time" : row[3], 
                         "status" : row[4], 
                         "message" : row[5], 
                         "resources" : row[6], 
                         "start_time_tagging" : row[7], 
                         "end_time_tagging" : row[8], 
                         "status_tagging" : row[9], 
                         "message_tagging" : row[10], 
                         "resources_tagged_success" : row[11], 
                         "resources_tagged_error" : row[12],
                         "action" : row[13]
                         }
            )
            if limit_records < 10:
                if ( row[13] == 1 ):
                    summary['added'].append({ "x" : row[0], "y" : row[11] })
                    summary['removed'].append({ "x" : row[0], "y" : 0 })
                elif  (row[13] == 2 ):
                    summary['added'].append({ "x" : row[0], "y" : 0 })
                    summary['removed'].append({ "x" : row[0], "y" : row[11] })
            
            limit_records += 1

        
        # Chart Summary

        select_query = """
        SELECT
            scan_id,
            service,                        
            COUNT(*) AS total
        FROM
            tbresources
        WHERE scan_id IN (
            SELECT
                scan_id
            FROM
                tbprocess
            WHERE
                start_time_tagging is NOT NULL
                and
                end_time_tagging is NOT NULL
            ORDER BY
                scan_id DESC
            LIMIT
                %s
        )
            AND
            action = 1
        GROUP BY
            scan_id,
            service
        ORDER BY
            scan_id DESC
        
        """    
        parameters = (10,)
        rows = ds.execute_select(select_query, parameters)
          
        services = {}
        result_services = []
        for row in rows:
            if row[1] not in services:
                services[row[1]] = []
            services[row[1]].append({'x': row[0], 'y': float(row[2])})

        for service in services.keys():
            result_services.append({'title': service, 'type': 'bar', 'data': services[service]})



        return create_response(200, { 
                                        "response" : { "processes" : processes, "summary" : summary, "services" : result_services }
                                    }
        )
       

    except Exception as e:
        logger.error(f"Error in fn_08_get_dataset_tagging: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )



###
###-- Create a profile
###


def fn_09_create_profile(event: dict) -> APIGatewayResponse:
    try:

        
        # Write data store record
        create_table_query = """        
        CREATE TABLE IF NOT EXISTS tbprofiles (            
            profile_id VARCHAR,            
            json_profile VARCHAR,
            PRIMARY KEY (profile_id)
        )
        """

        insert_query = """
        INSERT INTO tbprofiles (
            profile_id,
            json_profile
        )
        VALUES (%s, %s)
        """

        insert_data = [
                (event['profileId'], json.dumps(event['jsonProfile']))
        ]  

        ds = DataStore(db_config=DB_CONFIG, region=REGION)
        ds.execute_command(create_table_query)
        ds.execute_insert(insert_query, insert_data)
        
        return create_response(200, { 
                                        "response" :  { "profile_id" : event['profileId'], "state" : "success" }
                                    }
        )

    except Exception as e:
        logger.error(f"Error in fn_09_create_profile: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )



###
###-- Update a profile
###

def fn_10_update_profile(event: dict) -> APIGatewayResponse:
    try:

        
        update_query = """
        UPDATE tbprofiles
        SET json_profile = %s
        WHERE profile_id = %s
        """

        parameters = (json.dumps(event['jsonProfile']), event['profileId'])
        
        ds = DataStore(db_config=DB_CONFIG, region=REGION)        
        ds.execute_dml(update_query, parameters)        

        
        return create_response(200, { 
                                        "response" :  { "profileId" : event['profileId'], "jsonProfile" : event['jsonProfile'], "state" : "success" }
                                    }
        )

    except Exception as e:
        logger.error(f"Error in fn_10_update_profile: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )



###
###-- Delete a profile
###

def fn_11_delete_profile(event: dict) -> APIGatewayResponse:
    try:

        
        update_query = """
        DELETE FROM tbprofiles      
        WHERE profile_id = %s
        """

        parameters = (event['profileId'],)
        
        ds = DataStore(db_config=DB_CONFIG, region=REGION)        
        ds.execute_dml(update_query, parameters)        

        
        return create_response(200, { 
                                        "response" :  { "scan_id" : event['profileId'], "state" : "success" }
                                    }
        )

    except Exception as e:
        logger.error(f"Error in fn_11_delete_profile: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )




###
###-- Get profiles
###

def fn_12_get_profiles(event: dict) -> APIGatewayResponse:
    try:
   
        select_query = """
        SELECT
            profile_id,
            json_profile
        FROM
            tbprofiles
        ORDER BY
            profile_id DESC
        """


        ds = DataStore(db_config=DB_CONFIG, region=REGION)
        rows = ds.execute_select(select_query, None)

        response = []
        for row in rows:
            response.append({
                "profileId" : row[0],
                "jsonProfile" : json.loads(row[1])
            })

        return create_response(200, {
                                        "response" : response
                                    }
        )

    except Exception as e:
        logger.error(f"Error in fn_12_get_profiles: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )




###
###-- Get metadata bases
###

def fn_13_get_dataset_metadata_bases(event: dict) -> APIGatewayResponse:
    try:
        
        ds = DataStore(db_config=DB_CONFIG, region=REGION)
        
        select_query = """
        SELECT
            scan_id,            
            name,
            parameters,
            start_time,
            end_time,
            status,
            message,
            resources
        FROM
            tbprocess
        WHERE            
            type = %s
        ORDER BY
            scan_id DESC
        LIMIT
            %s
        
        """    
        
        parameters = (event['type'],100,)
        rows = ds.execute_select(select_query, parameters)
        
        processes  = []
        for row in rows:
            processes.append({
                         "scan_id" : row[0], 
                         "name" : row[1], 
                         "parameters" : row[2], 
                         "start_time" : row[3], 
                         "end_time" : row[4], 
                         "status" : row[5], 
                         "message" : row[6], 
                         "resources" : row[7]                     
                         }
            )
          
        

        return create_response(200, { 
                                        "response" : { "processes" : processes  }
                                    }
        )
       

    except Exception as e:
        logger.error(f"Error in fn_13_get_dataset_metadata_bases: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )



###
###-- Get resources for specific filter - metadata bases
###


def fn_14_get_metadata_search(event: dict) -> APIGatewayResponse:
    try:

        filter = event['filter'] 
        if not isinstance(filter, str) or not filter.strip():
            filter = 'true'
    

        resources = []
        select_query = f"""
        SELECT * FROM (
                        SELECT
                            scan_id,            
                            seq,
                            account_id, 
                            region, 
                            service,
                            resource_type, 
                            resource_id, 
                            name,
                            creation_date,
                            tags,  
                            tags_number,          
                            arn,
                            case  when ( {filter} ) then 1 else 0 end as filtered
                        FROM
                            tbresources
                        WHERE
                            scan_id = %s     
        ) results       
        WHERE
            filtered = 1    
        ORDER BY
            resource_id ASC
        """
        print(select_query)

        parameters = (event['scanId'],)

        ds = DataStore(db_config=DB_CONFIG, region=REGION)
        rows = ds.execute_select(select_query,parameters)
        for row in rows:
            resources.append({
                'scan_id' : row[0],
                'seq' : row[1],
                'account' : row[2],
                'region' : row[3],
                'service' : row[4],
                'type' : row[5],
                'identifier' : row[6],
                'name' : row[7],
                'creation' : row[8],
                'tags_list' : row[9],
                'tags_number' : row[10],                
                'arn' : row[11]
            })

        return create_response(200, { 
                                        "response" :  { "resources" : resources}
                                    }
        )

    except Exception as e:
        logger.error(f"Error in fn_14_get_metadata_search: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )


###
###-- Get information for specif metadata base
###


def fn_15_get_dataset_metadata_information(event: dict) -> APIGatewayResponse:
    try:
        
        ds = DataStore(db_config=DB_CONFIG, region=REGION)
        
        select_query = """
        SELECT
            scan_id,        
            name,    
            parameters,
            start_time,
            end_time,
            status,
            message,
            resources
        FROM
            tbprocess
        WHERE            
            scan_id = %s

        """
        
        parameters = (event['scanId'],)
        rows = ds.execute_select(select_query, parameters)
        
        processes  = {}
        for row in rows:
            processes={
                         "scan_id" : row[0], 
                         "name" : row[1], 
                         "parameters" : row[2], 
                         "start_time" : row[3], 
                         "end_time" : row[4], 
                         "status" : row[5], 
                         "message" : row[6], 
                         "resources" : row[7]                     
                         }
        
          
        

        return create_response(200, { 
                                        "response" : { "processes" : processes  }
                                    }
        )
       

    except Exception as e:
        logger.error(f"Error in fn_15_get_dataset_metadata_information: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )




###
###-- Delete a metadata base
###

def fn_16_delete_metadata_base(event: dict) -> APIGatewayResponse:
    try:
        
        ds = DataStore(db_config=DB_CONFIG, region=REGION)
        parameters = (event['scanId'],)                       

        delete_query = """
        DELETE FROM tbprocess
        WHERE scan_id = %s
        """      
        ds.execute_dml(delete_query, parameters)

        delete_query = """
        DELETE FROM tbresources
        WHERE scan_id = %s
        """        
        ds.execute_dml(delete_query, parameters)


        return create_response(200, { 
                                        "response" :  { "status" : "success" }
                                    }
        )
       

    except Exception as e:
        logger.error(f"Error in fn_16_delete_metadata_base: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )



###
###-- List modules
###

def fn_17_get_list_modules_from_s3(event: dict) -> APIGatewayResponse:
    try:
        
        s3 = boto3.client('s3',region_name=REGION)
        response = s3.list_objects_v2(Bucket=S3_BUCKET_MODULES)
    
        modules = [
            {
                'name': item['Key'][:-3],
                'size': item['Size'],
                'lastModified': item['LastModified'].isoformat()
            }
            for item in response.get('Contents', [])
            if item['Key'].endswith('.py') 
        ]


        return create_response(200, { 
                                        "response" :  { "modules" : modules }
                                    }
        )
       

    except Exception as e:
        logger.error(f"Error in 17-get-list-modules: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )





###
###-- Get Module content
###

def fn_18_get_module_content_from_s3(event: dict) -> APIGatewayResponse:
    try:
        
        s3 = boto3.client('s3',region_name=REGION)    
        response = s3.get_object(Bucket=S3_BUCKET_MODULES, Key=event['fileName']+ ".py")        
        content = response['Body'].read().decode('utf-8')
      
        return create_response(200, { 
                                        "response" :  { "content" : content }
                                    }
        )
       

    except Exception as e:
        logger.error(f"Error in fn_18_get_module_content_from_s3: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )



###
###-- Save module content
###

def fn_19_save_module_content_to_s3(event: dict) -> APIGatewayResponse:
    try:
        
        s3 = boto3.client('s3',region_name=REGION)
    
        s3.put_object(
            Bucket=S3_BUCKET_MODULES,
            Key=event['fileName'] + ".py",
            Body=event['content'],
            ContentType='text/plain'
        )      
        
        return create_response(200, { 
                                        "response" :  { "status" : "success" }
                                    }
        )
       
    except Exception as e:
        logger.error(f"Error in fn_19_save_module_content_to_s3: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )



###
###-- Delete module content
###

def fn_20_delete_module_content_fom_s3(event: dict) -> APIGatewayResponse:
    try:
        s3 = boto3.client('s3',region_name=REGION)
   
        s3.delete_object(
            Bucket=S3_BUCKET_MODULES,
            Key=event['fileName'] + ".py"
        )      

        return create_response(200, { 
                                        "response" :  { "status" : "success" }
                                    }
        )
    except Exception as e:
        logger.error(f"Error in fn_20_delete_module_content_fom_s3: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )




###
###-- Validate module content
###

def fn_21_validate_module_content(event: dict) -> APIGatewayResponse:
    try:
        

        account_id = event['accountId']
        region = event['region']
        file_name = event['fileName'] + ".py"
        service = event['fileName']
        
        s3 = boto3.client('s3',region_name=REGION)    
        response = s3.get_object(Bucket=S3_BUCKET_MODULES, Key=file_name)        
        code = response['Body'].read().decode('utf-8')        
        
        #def assume_role(self, account_id):
        sts_client = boto3.client('sts')
        role_arn = f'arn:aws:iam::{account_id}:role/{IAM_SCAN_ROLE}'
            
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f'MultiAccountTagCollection-{account_id}'
        )
        
        session = boto3.Session(
            aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
            aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
            aws_session_token=assumed_role['Credentials']['SessionToken']
        )    
        

        # Create a module name (can be any valid string)
        module_name = "dynamic_module"

        # Create a module spec
        spec = importlib.util.spec_from_loader(module_name, loader=None)

        # Create a module based on the spec
        module = importlib.util.module_from_spec(spec)

        # Add the module to sys.modules
        sys.modules[module_name] = module

        # Execute the code string in the module's namespace
        exec(code, module.__dict__)

        # Now you can use the imported code                
        service_list = (module.get_service_types(None,None,None,None)).keys()        

        
        all_resources = [] 
        all_services = [] 

        # Parallel account and region processing
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # Prepare futures for all accounts, regions, and services
            futures = []                
            for srv in service_list:                
                futures.append(executor.submit(module.discovery, None, session, account_id, region, service, srv, logger))
                    
            
            # Process results
            for future in concurrent.futures.as_completed(futures):
                try:
                    service_name, status, message, resources = future.result()       
                    resources = [{k: v for k, v in obj.items() if k not in ['metadata']} for obj in resources]    
                    print(service_name, status, message)
                    all_services.extend([{ "service" : service_name, "status" : status, "message"  : message }])                             
                    all_resources.extend(resources)

                except Exception as e:
                    self.logger.error(f"Error processing future: {e}")          
        
        return create_response(200, { 
                                        "response" :  { "status" : "success", "services" : all_services, "resources" :  json.dumps(all_resources,default=str) }
                                    }
        )

    except Exception as e:
        logger.error(f"Error in fn_21_validate_module_content: {str(e)}")
        return create_error_response(
            500,
            f'Internal server error : {e}',
            ERROR_CODES["INTERNAL_ERROR"]
        )





###
###-- Get compliance scores
###

def fn_22_get_compliance_score(event: dict) -> APIGatewayResponse:
    try:
        
        ds = DataStore(db_config=DB_CONFIG, region=REGION)
        

        ## Summary

        select_query = """
        SELECT
            SUM(case when action = 2 then 1 else 0 end) in_compliance,
            SUM(case when action = 1 then 1 else 0 end) out_compliance,
            COUNT(*) total
        FROM
            tbresources
        WHERE
            scan_id = %s
        """
        
        parameters = (event['scanId'],)
        rows = ds.execute_select(select_query, parameters)
        
        summary  = {}
        for row in rows:
            summary = {
                         "in_compliance" : row[0], 
                         "out_compliance" : row[1], 
                         "total" : row[2]
            }


        ### In-Compliance 

        select_query = """
        SELECT
            service,
            COUNT(*) total
        FROM
            tbresources
        WHERE
            scan_id = %s
            AND 
            action = 2
        GROUP BY service
        """

        parameters = (event['scanId'],)
        rows = ds.execute_select(select_query, parameters)

        resources_in_compliance  = []
        for row in rows:
            resources_in_compliance.append({
                          "title" : row[0],
                          "value" : row[1]
                         }
            )
          
        
        ### Out-Compliance 

        select_query = """
        SELECT
            service,
            COUNT(*) total
        FROM
            tbresources
        WHERE
            scan_id = %s
            AND 
            action = 1
        GROUP BY service
        """

        parameters = (event['scanId'],)
        rows = ds.execute_select(select_query, parameters)

        resources_out_compliance  = []
        for row in rows:
            resources_out_compliance.append({
                          "title" : row[0],
                          "value" : row[1]
                         }
            )
        

        return create_response(200, { 
                                        "response" : { 
                                                        "summary" : summary, 
                                                        "in_compliance" : resources_in_compliance, 
                                                        "out_compliance"  : resources_out_compliance 
                                                    }
                                    }
        )
       

    except Exception as e:
        logger.error(f"Error in fn_22_get_compliance_score: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )



###
###-- Get tagging information
###


def fn_23_get_tagging_errors(event: dict) -> APIGatewayResponse:
    try:
        
        ds = DataStore(db_config=DB_CONFIG, region=REGION)
        
        select_query = """
        SELECT
            account_id,
            region,
            service,
            resource_id,
            arn,
            status,
            error
        FROM
            tbtag_errors
        WHERE            
            scan_id = %s

        """
        
        parameters = (event['scanId'],)
        rows = ds.execute_select(select_query, parameters)
        
        resources  = []
        for row in rows:
            resources.append({
                         "account_id" : row[0], 
                         "region" : row[1], 
                         "service" : row[2], 
                         "resource_id" : row[3], 
                         "arn" : row[4], 
                         "status" : row[5], 
                         "error" : row[6]                  
            })
        
          
        

        return create_response(200, { 
                                        "response" : { "resources" : resources  }
                                    }
        )
       

    except Exception as e:
        logger.error(f"Error in fn_23_get_tagging_errors: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )



###
###-- Validate module content
###

def fn_24_get_profile_catalog(event: dict) -> APIGatewayResponse:
    try:
        

        region = os.environ['REGION']
        bucket_name = os.environ['S3_BUCKET_MODULES']
        
        s3 = boto3.client('s3',region_name=region)

        # Get regions        
        response = s3.get_object(Bucket=bucket_name, Key="regions.json")        
        regions = json.loads(response['Body'].read().decode('utf-8'))                    


        # Get list of modules
        response = s3.list_objects_v2(Bucket=bucket_name)    
        modules = [
            {
                'name': item['Key'],
                'size': item['Size'],
                'lastModified': item['LastModified'].isoformat()
            }
            for item in response.get('Contents', [])  
            if item['Key'].endswith('.py')           
        ]
        

        # Get resources modules
        all_services = []        
        for module_item in modules:

            response = s3.get_object(Bucket=bucket_name, Key=module_item['name'])        
            code = response['Body'].read().decode('utf-8')                    

            # Create a module name (can be any valid string)
            module_name = "dynamic_module"
            
            # Create a module spec
            spec = importlib.util.spec_from_loader(module_name, loader=None)

            # Create a module based on the spec
            module = importlib.util.module_from_spec(spec)

            # Add the module to sys.modules
            sys.modules[module_name] = module

                
            # Execute the code string in the module's namespace
            exec(code, module.__dict__)

            # Now you can use the imported code                
            service_list = (module.get_service_types(None,None,None,None)).keys()               
            
            for service in service_list:                                               
                all_services.append( f'{module_item["name"][:-3]}::{service}')     
               
            
            
        all_services.sort()    

        return create_response(200, { 
                                        "response" :  { "services" : all_services , "regions" :  regions }
                                    }
        )

    except Exception as e:
        logger.error(f"Error in fn_24_get_profile_catalog: {str(e)}")
        return create_error_response(
            500,
            f'Internal server error : {e}',
            ERROR_CODES["INTERNAL_ERROR"]
        )





######################################################
######################################################
###
###--------- Main : lambda_handler
###
######################################################
######################################################


def lambda_handler(event, context):  
    
    try:
        
        parameters = json.loads(event['body'])['parameters']        
        logger.info(f'Parameters :{parameters}')  

        logger.info(f'Parameters :{parameters}')  

        if parameters['processId'] == '01-get-metadata-results':
            response = fn_01_get_metadata_results(parameters)
        
        elif parameters['processId'] == '02-create-metadata-search':
            response = fn_02_create_metadata_search(parameters)
        
        elif parameters['processId'] == '03-get-metadata-search-status':
            response = fn_03_get_metadata_search_status(parameters)

        elif parameters['processId'] == '04-update-resource-action':
            response = fn_04_update_resource_action(parameters)
        
        elif parameters['processId'] == '05-create-tagging-process':
            response = fn_05_create_tagging_process(parameters)  

        elif parameters['processId'] == '06-get-tagging-process-status':
            response = fn_06_get_tagging_process_status(parameters)  
        
        elif parameters['processId'] == '07-get-resource-metadata':
            response = fn_07_get_resource_metadata(parameters)  
            
        elif parameters['processId'] == '08-get-dataset-tagging':
            response = fn_08_get_dataset_tagging(parameters)  
        
        elif parameters['processId'] == '09-create-profile':
            response = fn_09_create_profile(parameters) 
        
        elif parameters['processId'] == '10-update-profile':
            response = fn_10_update_profile(parameters) 

        elif parameters['processId'] == '11-delete-profile':
            response = fn_11_delete_profile(parameters) 

        elif parameters['processId'] == '12-get-profiles':
            response = fn_12_get_profiles(parameters) 
        
        elif parameters['processId'] == '13-get-dataset-metadata-bases':
            response = fn_13_get_dataset_metadata_bases(parameters) 

        elif parameters['processId'] == '14-get-metadata-search':
            response = fn_14_get_metadata_search(parameters) 

        elif parameters['processId'] == '15-get-dataset-metadata-information':
            response = fn_15_get_dataset_metadata_information(parameters) 

        elif parameters['processId'] == '16-delete-metadata-base':
            response = fn_16_delete_metadata_base(parameters) 

        elif parameters['processId'] == '17-get-list-modules':
            response = fn_17_get_list_modules_from_s3(parameters) 

        elif parameters['processId'] == '18-get-module-content':
            response = fn_18_get_module_content_from_s3(parameters) 
    
        elif parameters['processId'] == '19-save-module-content':
            response = fn_19_save_module_content_to_s3(parameters) 

        elif parameters['processId'] == '20-delete-module-content':
            response = fn_20_delete_module_content_fom_s3(parameters) 

        elif parameters['processId'] == '21-validate-module-content':
            response = fn_21_validate_module_content(parameters)         

        elif parameters['processId'] == '22-compliance-score':
            response = fn_22_get_compliance_score(parameters)         

        elif parameters['processId'] == '23-get-tagging-errors':
            response = fn_23_get_tagging_errors(parameters)         

        elif parameters['processId'] == '24-get-profile-catalog':
            response = fn_24_get_profile_catalog(parameters)         




        else:
            response = create_error_response(
                404,
                "Route not found",
                ERROR_CODES["NOT_FOUND"]
            )
    
        
        logger.info(f"Response: {json.dumps(response)}")
        return response

    except Exception as e:
        logger.error(f"Error in main handler: {str(e)}")
        return create_error_response(
            500,
            "Internal server error",
            ERROR_CODES["INTERNAL_ERROR"]
        )  


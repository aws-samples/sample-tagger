import json
import psycopg2
from psycopg2 import pool
import boto3
import logging
import os

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



######################################################
######################################################
###
###--------- Main : lambda_handler
###
######################################################
######################################################



def lambda_handler(event, context):

    try:

        REGION = os.environ['REGION']
        S3_BUCKET_MODULES = os.environ['S3_BUCKET_MODULES']

        DB_CONFIG = {        
        'host': os.environ['DBHOST'],
        'database': os.environ['DBNAME'],
        'user': os.environ['DBUSER'],       
        'port': os.environ['DBPORT'],
        'sslmode': 'require'
        }


        print('Database setup started.')
        ds = DataStore(db_config=DB_CONFIG, region=REGION)       
        
        # Get SQL file from S3
        s3 = boto3.client('s3',region_name=REGION)
        response = s3.get_object(Bucket=S3_BUCKET_MODULES, Key="database.setup.sql")
        sql_content = response['Body'].read().decode('utf-8')       
        
        sql_statements = sql_content.split(';')
        for statement in sql_statements:
            try:
                print(statement)
                if statement.strip():  # Skip empty statements
                    ds.execute_command(statement)        
            except Exception as e:
                print(e)

        print('Database setup completed.')                    
    
    except Exception as e:
        print(e)
        
    
    return {
        'statusCode': 200,
        'body': json.dumps('Initialization completed.')
    }

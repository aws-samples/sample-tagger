#!/bin/bash 


#######
####### STEP 1 - Load configuration
#######

source ./variables.env


start_time=$(date +%s)
echo "`date '+%H:%M:%S'` -  ## Creating AWS Cloudformation StackID : $STACK_ID-backend "



#######
####### STEP 2 - Creating artifacts
#######



echo -e "\n|--#### (1/5) - Creating artifacts ...\n\n"
mkdir -p artifacts/functions
cd artifacts/lambda.api/ && zip -r ../functions/lambda.api.zip lambda_function.py && cd ../../
cd artifacts/lambda.discovery/ && zip -r ../functions/lambda.discovery.zip lambda_function.py  && cd ../../
cd artifacts/lambda.tagger/ && zip -r ../functions/lambda.tagger.zip lambda_function.py  && cd ../../
cd artifacts/lambda.initdb/ && zip -r ../functions/lambda.initdb.zip lambda_function.py  && cd ../../

cd artifacts
mkdir layers
mkdir python
pip3.11 --version
pip3.11 install psycopg2-binary -t python/
pip3.11 install boto3 -t python/
zip -q -r layers/lambda.layer.zip python/
ls -lha layers/
cd ..

aws s3 mb s3://$STACK_ID
aws s3 cp artifacts/functions/. s3://$STACK_ID/functions/ --recursive
aws s3 cp artifacts/layers/. s3://$STACK_ID/layers/ --recursive




#######
####### STEP 3 - Creating AWS Resources
#######

echo -e "\n|--#### (2/5) - Creating AWS Resources  ...\n\n"
aws cloudformation create-stack --stack-name "$STACK_NAME-backend" --parameters ParameterKey=Username,ParameterValue=$APP_USER ParameterKey=S3Artifacts,ParameterValue=$STACK_ID --template-body file://cloudformation.backend.yaml --region $AWS_REGION --capabilities CAPABILITY_NAMED_IAM
#aws cloudformation create-stack --stack-name "$STACK_NAME-backend" --parameters ParameterKey=Username,ParameterValue=$APP_USER ParameterKey=S3Artifacts,ParameterValue=$STACK_ID ParameterKey=DSQLCluster,ParameterValue=$dsql_cluster_endpoint ParameterKey=DSQLClusterId,ParameterValue=$dsql_cluster_identifier --template-body file://cloudformation.backend.yaml --region $AWS_REGION --capabilities CAPABILITY_NAMED_IAM
aws cloudformation wait stack-create-complete --stack-name "$STACK_NAME-backend" --region $AWS_REGION


echo -e "\n|--#### (4/7) -  Removing artifacts ...\n\n"
aws s3 rm s3://$STACK_ID/ --recursive
aws s3 rb s3://$STACK_ID

export $(aws cloudformation describe-stacks --stack-name "$STACK_NAME-backend" --output text --query 'Stacks[0].Outputs[].join(`=`, [join(`_`, [`CF`, `OUT`, OutputKey]), OutputValue ])' --region $AWS_REGION)





#######
####### STEP 4 - Building Frontend Application
#######

echo -e "\n|--#### (3/5) -  Building Frontend Application  ...\n\n"

echo -e "\n|--CognitoUserPool :  $CF_OUT_CognitoUserPool"
echo -e "\n|--CognitoUserPoolClient :  $CF_OUT_CognitoUserPoolClient"
echo -e "\n|--ApiURL :  $CF_OUT_ApiURL"


cat << EOF > frontend/public/aws-exports.json
{ "aws_region": "$AWS_REGION",  "aws_cognito_user_pool_id": "$CF_OUT_CognitoUserPool",  "aws_cognito_user_pool_web_client_id": "$CF_OUT_CognitoUserPoolClient",  "aws_api_port": 3000,  "aws_token_expiration": 24 }
EOF

cat << EOF > frontend/src/pages/Api.js
export const api = { "url" : "$CF_OUT_ApiURL" };
EOF

mkdir -p $BUILD_PATH
pwd
ls -la
cd frontend
npm install 
npm run build
cd .. 
aws s3 cp  ./modules/. s3://$CF_OUT_S3PluginBucket/ --recursive 

echo -e "\n Listing the artifacts locations ...\n\n"
aws s3 ls s3://$CF_OUT_S3PluginBucket/


#######
####### STEP 5 - Configuring database store
#######

echo -e "\n|--#### (4/5) - Configuring database store  ...\n\n"
aws lambda invoke --function-name tagger-mng-lambda-initdb --cli-binary-format raw-in-base64-out --region $CF_OUT_Region response.json




#######
####### STEP 6 - AWS Resources created
#######

echo -e "\n|--#### (5/5) -  AWS Resources created.\n\n"
echo " "
echo " ApiURL   : $CF_OUT_ApiURL"
echo " CognitoUserPool   : $CF_OUT_CognitoUserPool"
echo " CognitoUserPoolClient   : $CF_OUT_CognitoUserPoolClient"
echo " S3PluginBucket   : $CF_OUT_S3PluginBucket"
echo " IAMRoleTaggerSolution   : $CF_OUT_IAMRoleTaggerSolution"

echo -e "\n|--#### Clean up commands."
echo -e "\naws cloudformation delete-stack --stack-name $STACK_ID-backend --region $AWS_REGION"


end_time=$(date +%s)
elapsed=$(( end_time - start_time ))
eval "echo Elapsed time: $(date -ud "@$elapsed" +'$((%s/3600/24)) days %H hr %M min %S sec')"

#!/bin/bash

source ./variables.env

set -e

# Variables
IMAGE_TAG="$APP_ID"

echo "--## Listing build directory"
mkdir build
cp -r $BUILD_PATH/* build/
ls -la build


echo "--## Creating AWS ECR repository: $ECR_REPO_NAME"
aws ecr create-repository --repository-name $ECR_REPO_NAME --region $AWS_REGION || echo "Repository already exists"

AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ECR_REPO_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO_NAME}"


echo "--## Logging into AWS ECR : $ECR_REPO_URI"
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com




# Create a temporary Dockerfile
cat > Dockerfile << EOF
FROM public.ecr.aws/amazonlinux/amazonlinux:2023
RUN dnf update -y && \
    dnf install -y nginx procps shadow-utils && \
    dnf clean all

COPY ./server.conf /etc/nginx/conf.d/

RUN rm -rf /usr/share/nginx/html/*
COPY ./build/ /usr/share/nginx/html/
EXPOSE 80
ENTRYPOINT ["nginx", "-g", "daemon off;"]
EOF

echo "--## Building Docker image"
docker build -t $ECR_REPO_NAME:$IMAGE_TAG .


echo "--## Tagging Docker image for ECR"
docker tag $ECR_REPO_NAME:$IMAGE_TAG $ECR_REPO_URI:$IMAGE_TAG


echo "--## Pushing Docker image to ECR"
docker push $ECR_REPO_URI:$IMAGE_TAG
DOCKER_IMAGE="$ECR_REPO_URI:$IMAGE_TAG"


echo "--## Docker image completed."
echo "----------------------------------------------------------------"
echo "New Docker image available at: $DOCKER_IMAGE"
echo "----------------------------------------------------------------"

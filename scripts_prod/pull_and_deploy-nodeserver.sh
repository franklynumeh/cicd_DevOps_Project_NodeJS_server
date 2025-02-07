#!/bin/bash

# Fetch the raw JSON output from ECR describe-images
RAW_IMAGES=$(aws ecr describe-images --repository-name docker-images --output json)

# Print the raw output to debug
echo "Raw images output:"
echo "$RAW_IMAGES"

# Get the most recent image tag that contains '-latest' in any of the tags
IMAGE_TAG=$(echo "$RAW_IMAGES" | jq -r '.imageDetails[] | select(.imageTags != null) | .imageTags[] | select(contains("-latest"))' | sort | tail -n 1)

# Check if we have a valid image tag
if [ -z "$IMAGE_TAG" ]; then
    echo "No images found with '-latest' tag in the repository."
    exit 1
fi

# Define the full image URI with the most recent image tag
IMAGE_URI="577638372446.dkr.ecr.us-east-2.amazonaws.com/docker-images:$IMAGE_TAG"
# CONTAINER_NAME="my-app-container-node_$IMAGE_TAG" 
CONTAINER_NAME="my-app-container-node" 

# Log in to ECR
aws ecr get-login-password --region us-east-2 | docker login --username AWS --password-stdin 577638372446.dkr.ecr.us-east-2.amazonaws.com

# Stop and remove the old container (if running)
if [ "$(docker ps -q -f name=$CONTAINER_NAME)" ]; then
    docker stop $CONTAINER_NAME
    docker rm $CONTAINER_NAME
fi

# Pull the most recent image
docker pull $IMAGE_URI

# Run the container
docker run -d --name $CONTAINER_NAME -p 4000:4000 $IMAGE_URI

echo $IMAGE_TAG
echo $CONTAINER_NAME
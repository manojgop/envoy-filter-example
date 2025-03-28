#!/bin/bash

# Variables
IMAGE_NAME="http-post-server-img"
CONTAINER_NAME="http-post-server"
DOCKERFILE_PATH="."

# Build the Docker image
echo "Building Docker image..."
docker build -t $IMAGE_NAME $DOCKERFILE_PATH

# Check if the image was built successfully
if [ $? -eq 0 ]; then
    echo "Http post server docker image built successfully."

    # Check if the container is already running
    if [ $(docker ps -q -f name=$CONTAINER_NAME) ]; then
        echo "removing existing container..."
        docker kill $CONTAINER_NAME
        docker rm $CONTAINER_NAME
    fi

    # Run the Docker container with port binding
    docker run --name $CONTAINER_NAME -d -p 5000:80 $IMAGE_NAME

    # Check if the container is running
    if [ $? -eq 0 ]; then
        echo "Http post server container is running on port 5000."
    else
        echo "Failed to run Docker container."
    fi
else
    echo "Failed to build Http post docker image."
fi

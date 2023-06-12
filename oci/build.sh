#!/bin/bash

# $DOCKER_LOGIN and $DOCKER_PASSWORD are used for the build cache
echo "$DOCKER_PASSWORD" | docker login -u $DOCKER_LOGIN --password-stdin

# $REGISTRY_SERVER : target registry
# $IMAGE_NAME : target image name
# $IMAGE_TAG : target tag
echo "$REGISTRY_PASSWORD" | docker login -u $REGISTRY_LOGIN --password-stdin $REGISTRY

# docker rmi $REGISTRY_SERVER/$IMAGE_NAME:$IMAGE_TAG

docker buildx build --platform linux/amd64,linux/arm64 \
    --cache-from=type=registry,ref=$DOCKER_LOGIN/$IMAGE_NAME:cache \
    --cache-to=type=registry,ref=$DOCKER_LOGIN/$IMAGE_NAME:cache,mode=max \
    --push -t $REGISTRY_SERVER/$IMAGE_NAME:$IMAGE_TAG -f Dockerfile ../.

#docker pull $REGISTRY_SERVER/$IMAGE_NAME:$IMAGE_TAG
#!/bin/bash
IMAGE_NAME="lracz/traefik-forward-auth"
TAG="latest"

# Enable Docker BuildKit
export DOCKER_BUILDKIT=1

# Build and push for multiple architectures
docker buildx create --use
docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 -t ${IMAGE_NAME}:${TAG} --push .

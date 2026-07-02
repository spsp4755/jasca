#!/bin/bash

# Create trivy-db directory if it doesn't exist (for environments without offline DB)
mkdir -p trivy-db

TARGET_PLATFORM="${TARGET_PLATFORM:-linux/amd64}"
docker build --no-cache --platform "$TARGET_PLATFORM" -f docker/monolith/Dockerfile -t jasca-offline .

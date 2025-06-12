#!/bin/bash

set -e

COMMIT_ID="49f909d9d01cfb3c85cf723ac60a17a9370a6627"

APP_NAME="security"
GO_MAIN="jfrogclisecurity.go"

ARTIFACTORY_PATH="security-cli/${COMMIT_ID}"

# List of OS/ARCH combinations
builds=(
  "linux-amd64"
  "linux-arm64"
  "darwin-amd64"
  "darwin-arm64"
  "windows-amd64"
)

jf c use bnpp
for build in "${builds[@]}"; do
  IFS="-" read -r os arch <<< "$build"
  output="${APP_NAME}"
  ext=""
  if [ "$os" = "windows" ]; then
    ext=".exe"
  fi
  output_dir="build/${os}-${arch}"
  mkdir -p "$output_dir"
  output_path="${output_dir}/${APP_NAME}${ext}"

  echo "Building for $os/$arch..."
  GOOS=$os GOARCH=$arch go build -o "$output_path" -ldflags "-w -extldflags -static'" "$GO_MAIN"

  # Upload to Artifactory
  jf rt upload "$output_path" "${ARTIFACTORY_PATH}/${build}/${APP_NAME}${ext}"
done

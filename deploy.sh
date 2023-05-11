#!/bin/bash

set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd $SCRIPT_DIR

# Make ADB configurable via environment variable
ADB=${ADB_COMMAND:-adb}

# Usage: ./deploy.sh <app_name> [debug|release]

APP_NAME=$1
BUILD_TYPE=${2:-release}

if [ -z "$APP_NAME" ]; then
	echo "Usage: ./deploy.sh <app_name> [debug|release]"
	exit 1
fi

# Get device architecture
ARCH=$($ADB shell getprop ro.product.cpu.abi)

# Copy file to /data/local/tmp
$ADB push runtime_cpp/build/intermediates/merged_native_libs/${BUILD_TYPE}/out/lib/${ARCH}/libcoverage_instrumenting_agent.so /data/local/tmp

# Create startup_agents directory
$ADB shell run-as $APP_NAME "mkdir -p code_cache/startup_agents"

# Copy file to startup_agents directory
$ADB shell run-as $APP_NAME "cp /data/local/tmp/libcoverage_instrumenting_agent.so code_cache/startup_agents"

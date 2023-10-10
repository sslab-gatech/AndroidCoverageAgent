#!/bin/bash

set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd $SCRIPT_DIR

# Make ADB configurable via environment variable
ADB=${ADB_COMMAND:-adb}

# Usage: ./launch_app.sh <app_name>

PACKAGE_NAME=$1

if [ -z "$PACKAGE_NAME" ]; then
	echo "Usage: ./launch_app.sh <app_name>"
	exit 1
fi

# Check if the application is installed on the device
if ! adb shell pm list packages | grep -q "$PACKAGE_NAME"; then
  echo "Application $PACKAGE_NAME is not installed on the device"
  exit 1
fi

# Check if the coverage agent is installed for the app
COVERAGE_AGENT="/data/data/${PACKAGE_NAME}/code_cache/startup_agents/libcoverage_instrumenting_agent.so"
if ! adb shell ls "$COVERAGE_AGENT" > /dev/null 2>&1; then
  echo "Coverage agent is not installed for the application"
  exit 1
fi

# Extract main activity name
MAIN_ACTIVITY=$(adb shell cmd package resolve-activity --brief "$PACKAGE_NAME" | tail -n 1)

# Stop the app
$ADB shell am force-stop ${PACKAGE_NAME}

# Create startup_agents directory
$ADB shell am start-activity --attach-agent /data/user/0/${PACKAGE_NAME}/code_cache/startup_agents/libcoverage_instrumenting_agent.so ${MAIN_ACTIVITY}

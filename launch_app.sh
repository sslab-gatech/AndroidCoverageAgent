#!/bin/bash

set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd $SCRIPT_DIR

# Make ADB configurable via environment variable
ADB=${ADB_COMMAND:-adb}

# Usage: ./launch_app.sh <app_name>

ACTIVITY=$1

if [ -z "$ACTIVITY" ]; then
	echo "Usage: ./deploy.sh <app_name>"
	exit 1
fi

# Get the app name from the activity name
APP_NAME=$(echo $ACTIVITY | cut -d '/' -f 1)

# Create startup_agents directory
$ADB shell am start-activity --attach-agent /data/user/0/${APP_NAME}/code_cache/startup_agents/libcoverage_instrumenting_agent.so ${ACTIVITY}

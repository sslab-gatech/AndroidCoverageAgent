#!/bin/bash
# This script identifies classes that the ART verifier rejects and
# adds them to the ".ignored_classes" file in the data directory
# of the application on the adb device.
# The script takes the package name as the single argument and assumes that the
# application is already installed on the device.
# 
# Example usage:
# ./find_ignored_classes.sh com.example.app
#
# The script will create a file called ".ignored_classes" in the data
# directory of the application on the adb device. The file will contain the
# list of classes that the ART verifier rejects.
#
# This script iteratively runs the application on the device and checks the
# logcat output for the "Verifier rejected class" message. The script then
# extracts the class name from the message and adds it to the
# ".ignored_classes" file.
# The script repeats this process until the application runs without any
# verifier errors (aka the logcat output contains the "Reporting idle of
# ActivityRecord" message).

PACKAGE_NAME=$1

# Check if the package name is provided
if [ -z "$PACKAGE_NAME" ]; then
  echo "Usage: $0 <package_name>"
  exit 1
fi

# Check if the application is installed on the device
if ! adb shell pm list packages | grep -q "$PACKAGE_NAME"; then
  echo "Application $PACKAGE_NAME is not installed on the device"
  exit 1
fi

# Extract main activity name
MAIN_ACTIVITY=$(adb shell cmd package resolve-activity --brief "$PACKAGE_NAME" | tail -n 1)

# Infinite loop
while true; do
  # Stop application if it is already running
  adb shell am force-stop "$PACKAGE_NAME"

  # Clear logcat
  adb logcat -c

  # Start application with coverage agent
  adb shell am start-activity --attach-agent /data/data/"$PACKAGE_NAME"/code_cache/startup_agents/libcoverage_instrumenting_agent.so "$MAIN_ACTIVITY"

  # Poll logcat for verifier errors or idle message
  while true; do
    sleep 1
    rejected_classes=$(adb logcat -d | grep "Verifier rejected class" | grep "$PACKAGE_NAME" | sed -e "s/.*Verifier rejected class \([^:]*\): \(.*\)/\1/")
    anr_message=$(adb logcat -d | grep "ANR in $PACKAGE_NAME")
    idle_message=$(adb logcat -d | grep "Reporting idle of ActivityRecord" | grep "$PACKAGE_NAME")
    if [ -n "$rejected_classes" ]; then
      echo "Found rejected classes: $rejected_classes"
      # Extract class name from the message
      echo "$rejected_classes" | while read -r class_name; do
        # Add class name to the ".ignored_classes" file
        adb shell "echo '$class_name' >> /data/data/$PACKAGE_NAME/.ignored_classes"
        echo "Added $class_name to .ignored_classes"
      done
      break
    elif [ -n "$anr_message" ]; then
      echo "ANR detected, restarting application"
      break
    elif [ -n "$idle_message" ]; then
      echo "Found idle message: $idle_message"
      # Application started without verifier errors
      echo "Application started without verifier errors"
      break 2
    fi
  done
done

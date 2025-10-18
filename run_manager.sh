#!/bin/bash

# Define the root of your project
PROJECT_ROOT="/Users/mjrlee/Documents/MyFiles/CodingDirectories/gmail-manager-script"

# Activate the virtual environment
source "$PROJECT_ROOT/.venv/bin/activate"

# Change directory to the script's location
cd "$PROJECT_ROOT"

# Execute your Python script
# The `exec` command replaces the shell process with the python process,
# ensuring the launchd log files correctly capture all Python output.
echo "INFO: Starting gmail-manager.py at $(date)"
exec python3 main.py

# Deactivation is not strictly needed after 'exec' but can be placed here if you
# remove 'exec' for debugging: deactivate
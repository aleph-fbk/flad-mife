#!/bin/bash

# Path to main 
PYTHON_SCRIPT="flad_main.py"

# Specifying the arguments 

ARG1="--clients sample_clients/  "
ARG2="--protocol DDH"
ARG3="--max_workers 15"

# Log file for output 
LOG_FILE="output.log"

# Ensure the script is executable
chmod +x $PYTHON_SCRIPT

# Run the script in the background, independent of the terminal
nohup python3 $PYTHON_SCRIPT  $ARG1 $ARG2 $ARG3> $LOG_FILE 2>&1 &

# Output the process ID for tracking
echo "Running $PYTHON_SCRIPT in the background. PID: $!"

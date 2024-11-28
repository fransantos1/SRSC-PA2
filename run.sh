#!/bin/bash
# Clear the screen
clear

# Compile all Java files in the src/DSTP directory
javac ./*.java

# Check if the compilation was successful
if [ $? -ne 0 ]; then
    echo "Compilation failed."
    exit 1
fi

# Run the main class
java DSTP 0

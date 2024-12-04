#!/bin/bash

# Default behavior: Compile Java files with the necessary classpath

# Compile the Java files
echo "Compiling Java files..."
javac -cp .:bcprov-jdk18on-1.78.1.jar ./src/*.java

# If 'c' or 's' is provided as a parameter, run the respective Java command
elif [ "$1" == "c" ] || [ "$1" == "s" ]; then
    echo "Running Java program with parameter $1..."
    java -cp .:bcprov-jdk18on-1.78.1.jar ./testSHP.java "$1"

else
    echo "Invalid argument. Please provide either 'c' or 's'."
    exit 1
fi

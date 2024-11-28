@echo off
cls
REM Compile all Java files in the current directory
javac src/DSTP/*.java

REM Check if the compilation was successful
if %errorlevel% neq 0 (
    echo Compilation failed.
    exit /b
)

REM Run the main class
java src/DSTP/DSTP.java

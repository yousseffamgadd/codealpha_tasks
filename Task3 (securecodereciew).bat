@echo off
echo this batch will help you see vulnerabilities of any python application

REM Check if an argument is provided
if "%1"=="" (
    echo Usage: %0 directory_path
    exit /b 1
) else (
    REM Run Bandit on Python files within the specified directory
    bandit -r %1
)



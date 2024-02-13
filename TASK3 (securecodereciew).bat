@echo off
echo This batch script will help identify vulnerabilities in any Python application.

REM Check if an argument is provided
if "%~1"=="" (
    echo Usage: %0 [directory_path_or_file_path]
    exit /b 1
) else (
    REM Run Bandit on Python files within the specified directory or directly on the provided Python file
    if exist %~1 (
        bandit -r %~1
    ) else (
        bandit %~1
    )
)



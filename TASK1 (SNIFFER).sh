#!/bin/bash
sudo_path=$(which sudo)

read -p "Enter Result's PATH: " PATH


if [ ! -d "$PATH" ]; then
    echo "Directory Does not exist"  # Debugging output
else
    if [  -f "$PATH/result.txt" ]; then
       $sudo_path rm $PATH/result.txt 
     fi         
        $sudo_path python3 Sniffer.py >> "$PATH/result.txt"
fi


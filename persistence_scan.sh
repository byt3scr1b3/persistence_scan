#!/bin/bash

log_file="persistence_scan.log"

# array for common persistence locations
persistence_locations=(
    "/etc/rc.local"
    "/etc/cron.d/"
    "/etc/crontab"
    "/etc/profile"
    "/etc/profile.d/"
    "/etc/systemd/system/"
    "/home/*/.*rc"
    "/root/.*rc"
    "/var/spool/cron/crontabs/"
    "/var/spool/anacron/"
)

> "$log_file"

# Function to check for potential indicators of persistence or malware
check_for_malware() {
    local file="$1"
    local patterns=("base64 -d" "curl" "wget" "nc" "netcat" "sh -c" "bash -c" "python -c" "perl -e")
    local suspicious_found=false

    for pattern in "${patterns[@]}"; do
        if grep -q "$pattern" "$file"; then
            echo -e "\e[91m[Potential Indicator] Suspicious pattern detected in $file:\e[0m"
            grep -n "$pattern" "$file" | sed -E "s/^/    Line /"
            echo -e "\e[0m-------------------"
            echo -e "[Potential Indicator] Suspicious pattern detected in $file:" >> "$log_file"
            grep -n "$pattern" "$file" | sed -E "s/^/    Line /" >> "$log_file"
            echo "-------------------" >> "$log_file"
            suspicious_found=true
        fi
    done

    if [ "$suspicious_found" = false ]; then
        echo "No suspicious patterns found in $file"
        echo "-------------------"
        echo "No suspicious patterns found in $file" >> "$log_file"
        echo "-------------------" >> "$log_file"
    fi
}

# Concatenate and scan the persistence locations
echo "Searching for potential indicators of persistence or malware..."
echo "Searching for potential indicators of persistence or malware..." >> "$log_file"
for location in "${persistence_locations[@]}"; do
    if [ -d "$location" ]; then
        for file in "$location"*; do
            if [ -f "$file" ]; then
                echo "Checking $file..."
                echo "Checking $file..." >> "$log_file"
                check_for_malware "$file"
            fi
        done
    elif [ -f "$location" ]; then
        echo "Checking $location..."
        echo "Checking $location..." >> "$log_file"
        check_for_malware "$location"
    fi
done

echo "Finished scanning persistence locations."
echo "Finished scanning persistence locations." >> "$log_file"


#!/bin/bash


set -euo pipefail


CUSTOM_REPORT_FILE="custom_security_check_report.txt"

CONFIG_FILE="custom_checks.conf"


# Initialize custom report file

echo "=== Custom Security Checks Report ===" > "$CUSTOM_REPORT_FILE"


if [ -f "$CONFIG_FILE" ]; then

    echo "Loading custom checks from $CONFIG_FILE" >> "$CUSTOM_REPORT_FILE"


    while IFS= read -r line || [ -n "$line" ]; do

        # Skip empty lines and comments

        [[ -z "${line// }" ]] && continue

        [[ "${line:0:1}" == "#" ]] && continue

        [[ "$line" != *"="* ]] && continue


        # Split into check name and command, trim whitespace

        check_name="${line%%=*}"

        command="${line#*=}"

        check_name="$(echo "$check_name" | xargs)"

        command="$(echo "$command" | xargs)"


        echo -e "\n=== $check_name ===" >> "$CUSTOM_REPORT_FILE"


        # Run the check, capture output and exit status

        output=$({ eval "$command"; } 2>&1)

        status=$?

        echo "$output" >> "$CUSTOM_REPORT_FILE"

        echo "Exit status: $status" >> "$CUSTOM_REPORT_FILE"

    done < "$CONFIG_FILE"

else

    echo "Configuration file $CONFIG_FILE not found." >> "$CUSTOM_REPORT_FILE"

fi


echo -e "\nCustom security checks completed. See $CUSTOM_REPORT_FILE for details."


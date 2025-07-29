#!/bin/bash


# Load configuration file

if [ -f config.conf ]; then

    . ./config.conf

else

    echo "Configuration file config.conf not found. Exiting."

    exit 1

fi


REPORT_FILE="${REPORT_FILE:-security_audit_report.txt}"

echo "=== Security Audit and Hardening Report ===" > "$REPORT_FILE"

echo "Audit date: $(date)" >> "$REPORT_FILE"

echo "" >> "$REPORT_FILE"


# 1. User and Group Audits

echo "=== User and Group Audits ===" >> "$REPORT_FILE"

echo "Listing all users on the server:" >> "$REPORT_FILE"

getent passwd >> "$REPORT_FILE"


echo "Listing all groups on the server:" >> "$REPORT_FILE"

getent group >> "$REPORT_FILE"


echo "Checking for users with UID 0:" >> "$REPORT_FILE"

awk -F: '($3 == 0) {print "User with UID 0: " $1}' /etc/passwd >> "$REPORT_FILE"


echo "Checking for users without passwords or with weak passwords:" >> "$REPORT_FILE"

while IFS=: read -r user _; do

    password=$(sudo grep "^$user:" /etc/shadow | cut -d: -f2)

    if [ -z "$password" ] || [ "$password" = "!" ] || [ "$password" = "*" ] || [ "$password" = "!!" ]; then

        echo "User $user has no password set or a weak password." >> "$REPORT_FILE"

    fi

done < /etc/passwd


# Sudoers/privileged users check

echo "=== Sudoers and Admin Users ===" >> "$REPORT_FILE"

echo "Members of 'sudo' group:" >> "$REPORT_FILE"

getent group sudo 2>/dev/null | cut -d: -f4 >> "$REPORT_FILE"

echo "Members of 'wheel' group:" >> "$REPORT_FILE"

getent group wheel 2>/dev/null | cut -d: -f4 >> "$REPORT_FILE"

echo "Custom /etc/sudoers entries:" >> "$REPORT_FILE"

grep -vE '^#|^$|^Defaults|^root' /etc/sudoers 2>/dev/null >> "$REPORT_FILE"


# 2. File and Directory Permissions

echo "=== File and Directory Permissions ===" >> "$REPORT_FILE"

echo "Searching for world writable files and directories:" >> "$REPORT_FILE"

find / -path /proc -prune -o -path /sys -prune -o -path /run -prune -o -path /dev -prune -o -perm -022 -type f -exec ls -la {} \; >> "$REPORT_FILE"

find / -path /proc -prune -o -path /sys -prune -o -path /run -prune -o -path /dev -prune -o -perm -002 -type d -exec ls -la {} \; >> "$REPORT_FILE"


echo "Checking for .ssh directories with secure permissions:" >> "$REPORT_FILE"

find / -name '.ssh' -type d -exec ls -ld {} \; >> "$REPORT_FILE"


echo "Checking for files with SUID/SGID bits set:" >> "$REPORT_FILE"

find / -perm /6000 -type f -exec ls -la {} \; >> "$REPORT_FILE"


# 3. Service Audits

echo "=== Service Audits ===" >> "$REPORT_FILE"

echo "Listing all running services:" >> "$REPORT_FILE"

if command -v systemctl >/dev/null; then

    systemctl list-units --type=service --state=running >> "$REPORT_FILE"

else

    service --status-all 2>&1 >> "$REPORT_FILE"

fi


echo "Checking for critical services configuration:" >> "$REPORT_FILE"

for service in sshd iptables; do

    if systemctl status "$service" >/dev/null 2>&1; then

        systemctl status "$service" >> "$REPORT_FILE"

    else

        echo "$service service is not found or not installed." >> "$REPORT_FILE"

    fi

done


echo "Checking for services listening on non-standard ports:" >> "$REPORT_FILE"

if command -v ss >/dev/null; then

    ss -tuln | grep -v '127.0.0.1' >> "$REPORT_FILE"

else

    netstat -tuln | grep -v '127.0.0.1' >> "$REPORT_FILE"

fi


# 4. Firewall and Network Security

echo "=== Firewall and Network Security ===" >> "$REPORT_FILE"

echo "Checking if a firewall is active:" >> "$REPORT_FILE"

if command -v ufw >/dev/null 2>&1; then

    sudo ufw status verbose >> "$REPORT_FILE"

elif command -v iptables >/dev/null 2>&1; then

    sudo iptables -L -v -n >> "$REPORT_FILE"

else

    echo "No firewall service found." >> "$REPORT_FILE"

fi


echo "Checking for open ports and associated services:" >> "$REPORT_FILE"

if command -v ss >/dev/null; then

    ss -tuln >> "$REPORT_FILE"

else

    netstat -tuln >> "$REPORT_FILE"

fi


echo "Checking IP forwarding and other network configurations:" >> "$REPORT_FILE"

sysctl net.ipv4.ip_forward >> "$REPORT_FILE"

sysctl net.ipv6.conf.all.forwarding >> "$REPORT_FILE"


# 5. IP and Network Configuration Checks

echo "=== IP and Network Configuration Checks ===" >> "$REPORT_FILE"

echo "Listing all IP addresses and identifying public vs. private:" >> "$REPORT_FILE"

ip -o -4 addr show | awk '{print $2": "$4}' >> "$REPORT_FILE"

ip -o -6 addr show | awk '{print $2": "$4}' >> "$REPORT_FILE"


echo "Identifying public vs. private IPv4 addresses:" >> "$REPORT_FILE"

ip -o -4 addr show | awk '{print $4}' | while read ip; do

    ip=${ip%%/*}

    if echo "$ip" | grep -E '^10\.' >/dev/null ||

       echo "$ip" | grep -E '^172\.(1[6-9]|2[0-9]|3[0-1])\.' >/dev/null ||

       echo "$ip" | grep -E '^192\.168\.' >/dev/null; then

        echo "$ip is a private IP address." >> "$REPORT_FILE"

    else

        echo "$ip is a public IP address." >> "$REPORT_FILE"

    fi

done


echo "=== /etc/hosts Entries ===" >> "$REPORT_FILE"

cat /etc/hosts >> "$REPORT_FILE"


echo "=== DNS Resolvers (/etc/resolv.conf) ===" >> "$REPORT_FILE"

grep -E '^nameserver' /etc/resolv.conf >> "$REPORT_FILE"


# 6. Security Updates and Patching

echo "=== Security Updates and Patching ===" >> "$REPORT_FILE"

echo "Checking for available security updates:" >> "$REPORT_FILE"

if command -v apt-get >/dev/null 2>&1; then

    sudo apt-get -s upgrade | grep "^Inst" >> "$REPORT_FILE"

elif command -v yum >/dev/null 2>&1; then

    sudo yum check-update >> "$REPORT_FILE"

elif command -v dnf >/dev/null 2>&1; then

    sudo dnf check-update >> "$REPORT_FILE"

else

    echo "No known package manager found." >> "$REPORT_FILE"

fi


# 7. Log Monitoring

echo "=== Log Monitoring ===" >> "$REPORT_FILE"

if [ -f /var/log/auth.log ]; then

    grep "Failed password" /var/log/auth.log >> "$REPORT_FILE"

elif [ -f /var/log/secure ]; then

    grep "Failed password" /var/log/secure >> "$REPORT_FILE"

fi


# 8. Server Hardening Steps

echo "=== Server Hardening Steps ===" >> "$REPORT_FILE"

echo "Configuring SSH for key-based authentication and disabling root password login:" >> "$REPORT_FILE"

echo "Disabling root password login in /etc/ssh/sshd_config:" >> "$REPORT_FILE"

if grep -q "^PermitRootLogin" /etc/ssh/sshd_config; then

    sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config

else

    echo "PermitRootLogin prohibit-password" | sudo tee -a /etc/ssh/sshd_config

fi


echo "Disabling IPv6 if not required:" >> "$REPORT_FILE"

sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1 >> "$REPORT_FILE"


# 9. Custom Security Checks

echo "=== Custom Security Checks ===" >> "$REPORT_FILE"

CUSTOM_CHECK_SCRIPT="./customcheck.sh"

if [ -f "$CUSTOM_CHECK_SCRIPT" ]; then

    echo "Running custom security checks..." >> "$REPORT_FILE"

    bash "$CUSTOM_CHECK_SCRIPT" >> "$REPORT_FILE"

else

    echo "Custom check script $CUSTOM_CHECK_SCRIPT not found." >> "$REPORT_FILE"

fi


# 10. Endpoint Security & SIEM Checks

echo "=== Endpoint Security and SIEM Checks ===" >> "$REPORT_FILE"


# CrowdStrike Falcon

echo "Checking for CrowdStrike Falcon installation:" >> "$REPORT_FILE"

if systemctl list-units 2>/dev/null | grep -q falcon-sensor; then

    echo "CrowdStrike Falcon sensor is installed and running." >> "$REPORT_FILE"

elif [ -d /opt/CrowdStrike ]; then

    echo "CrowdStrike Falcon files found in /opt/CrowdStrike." >> "$REPORT_FILE"

elif rpm -qa 2>/dev/null | grep -qi falcon-sensor; then

    echo "CrowdStrike Falcon package installed (rpm detected)." >> "$REPORT_FILE"

elif dpkg -l 2>/dev/null | grep -qi falcon-sensor; then

    echo "CrowdStrike Falcon package installed (dpkg detected)." >> "$REPORT_FILE"

else

    echo "CrowdStrike Falcon sensor is NOT installed." >> "$REPORT_FILE"

fi


# Nessus Agent

echo "Checking for Nessus Agent installation:" >> "$REPORT_FILE"

if systemctl list-units 2>/dev/null | grep -q nessus-agent; then

    echo "Nessus Agent is installed and running." >> "$REPORT_FILE"

elif rpm -qa 2>/dev/null | grep -qi nessus-agent; then

    echo "Nessus Agent package installed (rpm detected)." >> "$REPORT_FILE"

elif dpkg -l 2>/dev/null | grep -qi nessus-agent; then

    echo "Nessus Agent package installed (dpkg detected)." >> "$REPORT_FILE"

elif [ -d /opt/nessus_agent ]; then

    echo "Nessus agent directory found." >> "$REPORT_FILE"

else

    echo "Nessus Agent is NOT installed." >> "$REPORT_FILE"

fi


# SIEM forwarding (Rsyslog)

echo "Checking for SIEM forwarding in /etc/rsyslog.conf and /etc/rsyslog.d/*:" >> "$REPORT_FILE"

if grep -E '@@?([0-9]{1,3}\.){3}[0-9]{1,3}' /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null; then

    echo "RSYSLOG is configured to forward logs (potential SIEM forwarding detected)." >> "$REPORT_FILE"

else

    echo "No rsyslog forwarding to remote SIEM detected." >> "$REPORT_FILE"

fi


# 11. Cron Jobs Audit

echo "=== Cron Jobs Audit ===" >> "$REPORT_FILE"


# Per-user crontabs

echo "Listing per-user cron jobs:" >> "$REPORT_FILE"

for user in $(cut -f1 -d: /etc/passwd); do

    echo "Crontab for $user:" >> "$REPORT_FILE"

    sudo crontab -l -u "$user" 2>/dev/null >> "$REPORT_FILE"

    echo "" >> "$REPORT_FILE"

done


# System crontab

echo "System crontab (/etc/crontab):" >> "$REPORT_FILE"

if [ -f /etc/crontab ]; then

    cat /etc/crontab >> "$REPORT_FILE"

    echo "" >> "$REPORT_FILE"

fi


# Cron directories

for cron_dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly; do

    if [ -d "$cron_dir" ]; then

        echo "Contents of $cron_dir:" >> "$REPORT_FILE"

        ls -lA "$cron_dir" >> "$REPORT_FILE"

        echo "" >> "$REPORT_FILE"

    fi

done


# 12. ELF file audit

echo "=== ELF Files Outside Standard Linux Directories ===" >> "$REPORT_FILE"


std_dirs="^/bin/|^/sbin/|^/usr/bin/|^/usr/sbin/|^/lib|^/lib64/|^/usr/lib|^/usr/local/"


find / -type f -executable 2>/dev/null | grep -Ev "$std_dirs" | while read file; do

    if file "$file" | grep -q 'ELF'; then

        echo "$file: $(file "$file")" >> "$REPORT_FILE"

    fi

done


echo "=== Running ELF Processes from Non-standard Directories ===" >> "$REPORT_FILE"

ps -eo pid,comm,args | while read pid comm args; do

    exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)

    if [ -n "$exe" ] && [[ "$exe" =~ ^/.* ]] && ! [[ "$exe" =~ $std_dirs ]]; then

        if file "$exe" | grep -q ELF; then

            echo "PID: $pid, Executable: $exe, CMD: $args" >> "$REPORT_FILE"

        fi

    fi

done


echo "Security audit and hardening completed. See $REPORT_FILE for details."


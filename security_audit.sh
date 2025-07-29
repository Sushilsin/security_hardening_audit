#!/bin/bash


##############################################################################

#            Linux Security Audit and Hardening Script (HTML Output)         #

#        Includes hostname, IP address, and date at top of report           #

##############################################################################


# Load config if present

if [ -f config.conf ]; then

    . ./config.conf

fi


# Output HTML report file

REPORT_FILE="${REPORT_FILE:-security_audit_report.html}"


# Collect system information

HOSTNAME=$(hostname)

DATE=$(date)

# Get all IPv4 addresses except 127.0.0.1, space separated

IP_ADDRESSES=$(hostname -I | tr ' ' '\n' | grep -v '^127\.' | xargs)


# HTML header

cat << EOF > "$REPORT_FILE"

<!DOCTYPE html>

<html>

<head>

<title>Security Audit and Hardening Report</title>

<meta charset="utf-8">

<style>

body { font-family: Arial, sans-serif; margin: 30px; }

h1, h2 { color: #2c3e50; }

pre { background: #f4f4f4; padding: 10px; border-radius: 6px; font-size: 14px; }

.section { margin-bottom: 40px; }

.meta { background: #e8f4fc; border: 1px solid #bce0fd; padding: 15px; margin-bottom: 25px; }

</style>

</head>

<body>

<h1>Security Audit and Hardening Report</h1>

<div class="meta">

<strong>Date:</strong> $DATE <br>

<strong>Hostname:</strong> $HOSTNAME <br>

<strong>IP Address(es):</strong> $IP_ADDRESSES <br>

</div>

EOF



# Function to write a section

write_section() {

    local title="$1"

    echo "<div class=\"section\"><h2>$title</h2><pre>" >> "$REPORT_FILE"

    cat >> "$REPORT_FILE"

    echo "</pre></div>" >> "$REPORT_FILE"

}


##############################################################################

# 1. User and Group Audits

##############################################################################

{

echo "Listing all users on the server:"

getent passwd

echo ""

echo "Listing all groups on the server:"

getent group

echo ""

echo "Checking for users with UID 0:"

awk -F: '($3 == 0) {print "User with UID 0: " $1}' /etc/passwd

echo ""

echo "Checking for users without passwords or with weak passwords:"

while IFS=: read -r user _; do

    password=$(sudo grep "^$user:" /etc/shadow | cut -d: -f2)

    if [ -z "$password" ] || [ "$password" = "!" ] || [ "$password" = "*" ] || [ "$password" = "!!" ]; then

        echo "User $user has no password set or a weak password."

    fi

done < /etc/passwd

} | write_section "User and Group Audits"


# Sudoers/Admin Users

{

echo "Members of 'sudo' group:"

getent group sudo 2>/dev/null | cut -d: -f4

echo ""

echo "Members of 'wheel' group:"

getent group wheel 2>/dev/null | cut -d: -f4

echo ""

echo "Custom /etc/sudoers entries:"

grep -vE '^#|^$|^Defaults|^root' /etc/sudoers 2>/dev/null

} | write_section "Sudoers and Admin Users"




##############################################################################

# 2. File and Directory Permissions

##############################################################################

{

echo "Searching for world writable files and directories:"

find / -path /proc -prune -o -path /sys -prune -o -path /run -prune -o -path /dev -prune -o -perm -022 -type f -exec ls -la {} \; 2>/dev/null

find / -path /proc -prune -o -path /sys -prune -o -path /run -prune -o -path /dev -prune -o -perm -002 -type d -exec ls -la {} \; 2>/dev/null

echo ""

echo "Checking for .ssh directories with secure permissions:"

find / -name '.ssh' -type d -exec ls -ld {} \; 2>/dev/null

echo ""

echo "Checking for files with SUID/SGID bits set:"

find / -perm /6000 -type f -exec ls -la {} \; 2>/dev/null

} | write_section "File and Directory Permissions"



##############################################################################

# 3. Service Audits

##############################################################################

{

echo "Listing all running services:"

if command -v systemctl >/dev/null; then

    systemctl list-units --type=service --state=running

else

    service --status-all 2>&1

fi

echo ""

echo "Checking for critical services configuration:"

for service in sshd iptables; do

    if systemctl status "$service" >/dev/null 2>&1; then

        systemctl status "$service"

    else

        echo "$service service is not found or not installed."

    fi

done

echo ""

echo "Checking for services listening on non-standard ports:"

if command -v ss >/dev/null; then

    ss -tuln | grep -v '127.0.0.1'

else

    netstat -tuln | grep -v '127.0.0.1'

fi

} | write_section "Service Audits"



##############################################################################

# 4. Firewall and Network Security

##############################################################################

{

echo "Checking if a firewall is active:"

if command -v ufw >/dev/null 2>&1; then

    sudo ufw status verbose

elif command -v iptables >/dev/null 2>&1; then

    sudo iptables -L -v -n

else

    echo "No firewall service found."

fi

echo ""

echo "Checking for open ports and associated services:"

if command -v ss >/dev/null; then

    ss -tuln

else

    netstat -tuln

fi

echo ""

echo "Checking IP forwarding and other network configurations:"

sysctl net.ipv4.ip_forward

sysctl net.ipv6.conf.all.forwarding

} | write_section "Firewall and Network Security"



##############################################################################

# 5. IP and Network Configuration Checks

##############################################################################

{

echo "Listing all IP addresses and identifying public vs. private:"

ip -o -4 addr show | awk '{print $2": "$4}'

ip -o -6 addr show | awk '{print $2": "$4}'

echo ""

echo "Identifying public vs. private IPv4 addresses:"

ip -o -4 addr show | awk '{print $4}' | while read ip; do

    ip=${ip%%/*}

    if echo "$ip" | grep -E '^10\.' >/dev/null ||

       echo "$ip" | grep -E '^172\.(1[6-9]|2[0-9]|3[0-1])\.' >/dev/null ||

       echo "$ip" | grep -E '^192\.168\.' >/dev/null; then

        echo "$ip is a private IP address."

    else

        echo "$ip is a public IP address."

    fi

done

echo ""

echo "/etc/hosts Entries:"

cat /etc/hosts

echo ""

echo "DNS Resolvers (/etc/resolv.conf):"

grep -E '^nameserver' /etc/resolv.conf

} | write_section "IP and Network Configuration Checks"



##############################################################################

# 6. Security Updates and Patching

##############################################################################

{

echo "Checking for available security updates:"

if command -v apt-get >/dev/null 2>&1; then

    sudo apt-get -s upgrade | grep "^Inst"

elif command -v yum >/dev/null 2>&1; then

    sudo yum check-update

elif command -v dnf >/dev/null 2>&1; then

    sudo dnf check-update

else

    echo "No known package manager found."

fi

} | write_section "Security Updates and Patching"



##############################################################################

# 7. Log Monitoring

##############################################################################

{

if [ -f /var/log/auth.log ]; then

    grep "Failed password" /var/log/auth.log

elif [ -f /var/log/secure ]; then

    grep "Failed password" /var/log/secure

else

    echo "No relevant authentication log found."

fi

} | write_section "Log Monitoring"



##############################################################################

# 8. Server Hardening Steps

##############################################################################

{

echo "Configuring SSH for key-based authentication and disabling root password login:"

echo "Disabling root password login in /etc/ssh/sshd_config:"

if grep -q "^PermitRootLogin" /etc/ssh/sshd_config; then

    sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config

else

    echo "PermitRootLogin prohibit-password" | sudo tee -a /etc/ssh/sshd_config

fi

echo ""

echo "Disabling IPv6 if not required:"

sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1

} | write_section "Server Hardening Steps"



##############################################################################

# 9. Custom Security Checks

##############################################################################

CUSTOM_CHECK_SCRIPT="./customcheck.sh"

{

if [ -f "$CUSTOM_CHECK_SCRIPT" ]; then

    echo "Running custom security checks..."

    bash "$CUSTOM_CHECK_SCRIPT"

else

    echo "Custom check script $CUSTOM_CHECK_SCRIPT not found."

fi

} | write_section "Custom Security Checks"



##############################################################################

# 10. Endpoint Security and SIEM Checks

##############################################################################

{

echo "Checking for CrowdStrike Falcon installation:"

if systemctl list-units 2>/dev/null | grep -q falcon-sensor; then

    echo "CrowdStrike Falcon sensor is installed and running."

elif [ -d /opt/CrowdStrike ]; then

    echo "CrowdStrike Falcon files found in /opt/CrowdStrike."

elif rpm -qa 2>/dev/null | grep -qi falcon-sensor; then

    echo "CrowdStrike Falcon package installed (rpm detected)."

elif dpkg -l 2>/dev/null | grep -qi falcon-sensor; then

    echo "CrowdStrike Falcon package installed (dpkg detected)."

else

    echo "CrowdStrike Falcon sensor is NOT installed."

fi

echo ""

echo "Checking for Nessus Agent installation:"

if systemctl list-units 2>/dev/null | grep -q nessus-agent; then

    echo "Nessus Agent is installed and running."

elif rpm -qa 2>/dev/null | grep -qi nessus-agent; then

    echo "Nessus Agent package installed (rpm detected)."

elif dpkg -l 2>/dev/null | grep -qi nessus-agent; then

    echo "Nessus Agent package installed (dpkg detected)."

elif [ -d /opt/nessus_agent ]; then

    echo "Nessus agent directory found."

else

    echo "Nessus Agent is NOT installed."

fi

echo ""

echo "Checking for SIEM forwarding in /etc/rsyslog.conf and /etc/rsyslog.d/*:"

if grep -E '@@?([0-9]{1,3}\.){3}[0-9]{1,3}' /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null; then

    echo "RSYSLOG is configured to forward logs (potential SIEM forwarding detected)."

else

    echo "No rsyslog forwarding to remote SIEM detected."

fi

} | write_section "Endpoint Security and SIEM Checks"



##############################################################################

# 11. Cron Jobs Audit

##############################################################################

{

echo "Listing per-user cron jobs:"

for user in $(cut -f1 -d: /etc/passwd); do

    echo "Crontab for $user:"

    sudo crontab -l -u "$user" 2>/dev/null

    echo ""

done

echo ""

echo "System crontab (/etc/crontab):"

if [ -f /etc/crontab ]; then

    cat /etc/crontab

    echo ""

fi

for cron_dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly; do

    if [ -d "$cron_dir" ]; then

        echo "Contents of $cron_dir:"

        ls -lA "$cron_dir"

        echo ""

    fi

done

} | write_section "Cron Jobs Audit"



##############################################################################

# 12. ELF file audit

##############################################################################

{

echo "ELF Files Outside Standard Linux Directories:"

std_dirs="^/bin/|^/sbin/|^/usr/bin/|^/usr/sbin/|^/lib|^/lib64/|^/usr/lib|^/usr/local/"

find / -type f -executable 2>/dev/null | grep -Ev "$std_dirs" | while read file; do

    if file "$file" | grep -q 'ELF'; then

        echo "$file: $(file "$file")"

    fi

done

echo ""

echo "Running ELF Processes from Non-standard Directories:"

ps -eo pid,comm,args | while read pid comm args; do

    exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)

    if [ -n "$exe" ] && [[ "$exe" =~ ^/.* ]] && ! [[ "$exe" =~ $std_dirs ]]; then

        if file "$exe" | grep -q ELF; then

            echo "PID: $pid, Executable: $exe, CMD: $args"

        fi

    fi

done

} | write_section "ELF Files and Process Audit"



##############################################################################

# End Report

##############################################################################

echo "<p><em>Security audit and hardening completed. See details above.</em></p>" >> "$REPORT_FILE"

echo "</body></html>" >> "$REPORT_FILE"


echo "Security audit and hardening completed. See $REPORT_FILE for details."


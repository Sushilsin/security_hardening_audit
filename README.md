# security_hardening_audit
Linux security hardening audit

# Security Hardening Audit

## Overview
Security Hardening Audit is intended as a toolkit for automating the security assessment and basic hardening of Linux servers. It is designed for Linux system administrators, DevOps, and IT security professionals who want to quickly evaluate and enhance their server’s security posture using best practices. The toolkit provides automated checks, reports on system configurations, and optionally applies security hardening steps.

## Features
User & Group Audits: Checks for users with root privileges, passwordless accounts, and weak passwords.

File & Directory Permissions: Scans for world-writable files/directories, SUID/SGID bits, and improper permission settings.

Service Audits: Lists all enabled/running services, flags unnecessary or suspicious services.

Firewall & Network Security: Validates firewall status and open ports, and checks for insecure network services.

SSH & Remote Access Controls: Reviews SSH settings for best practices (root login, authentication type), disables unused protocols.

System & Security Updates: Checks for pending security patches and reporting on outdated packages.

Log Monitoring: Highlights anomalous log activity and authentication failures.

Hardening Steps: Applies optional server hardening such as disabling IPv6, enforcing SSH key-based authentication, and enabling automatic updates.

Custom Checks: Supports extensibility for organization-specific security checks.

## Prerequisites
Operating System: Linux (tested on Ubuntu/Debian/CentOS/RHEL).

Privileges: Must be executed with sudo or root privileges for complete system checks and hardening.

Required Tools: Basic Unix/Linux utilities (awk, grep, find, netstat), plus any package manager (apt or yum).

Mail utility (optional): For report/alert delivery.

## Installation
Clone the repository:

bash
git clone https://github.com/Sushilsin/security_hardening_audit.git
cd security_hardening_audit
chmod +x *.sh

Usage
To perform a full security audit and basic hardening:

bash
sudo ./security_audit.sh
The script produces a report (e.g., /var/log/security_audit_report.txt), summarizing the findings.

For custom checks, adjust the configuration file or edit the script to add new validation logic.

## Customization
You can extend the audit and hardening checks by editing the script, or by creating config files (if supported by the script’s design).
Examples:

Add new security modules for organization-specific compliance.

Set notification thresholds or recipients for alerts.

## Reporting & Alerts
The toolkit generates a structured html report with all findings. 

## Security Guidance & References
Builds upon Linux security hardening best practices including CIS Linux Benchmarks, Red Hat, and SUSE security recommendations.

The checks can be adjusted for deployment-specific policies and compliance requirements (PCI-DSS, ISO27001, etc.).

## Contributing
Contributions via pull requests, bug reports, and feature requests are welcome!

## License
This project is released under an open-source license (see LICENSE file in the repository, if available).

## Disclaimer
Always review hardening changes before application in production, as some security measures might impact system functionality or block legitimate access. Test on non-production systems if possible.

## Acknowledgements
This script is inspired by and borrows approaches from the broader security community, including CIS Benchmarks, Linux Foundation, SUSE, Red Hat, and numerous other open-source security audit projects.

For issues or queries, please open a GitHub issue in the repository.

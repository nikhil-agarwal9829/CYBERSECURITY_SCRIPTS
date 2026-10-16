#!/usr/bin/env bash
# clean-lab.sh - remove the fixtures created by make-lab.sh
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }

rm -rf /tmp/suid-lab /tmp/update-check /var/www/lab
rm -f /etc/cron.d/lab-backup /etc/cron.d/lab-cleanup /etc/cron.d/lab-report.cron \
      /etc/cron.d/lab-tmp /etc/cron.d/lab-ghost /etc/cron.daily/lab-rotate.sh
id labuser >/dev/null 2>&1 && userdel -r labuser 2>/dev/null
echo "Lab fixtures removed."

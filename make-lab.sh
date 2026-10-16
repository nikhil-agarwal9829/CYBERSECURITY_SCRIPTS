#!/usr/bin/env bash
# make-lab.sh - create HARMLESS test fixtures for suid-sgid-audit.sh and
# automation-audit.sh. Use ONLY in a disposable VM or a snapshot you can roll
# back. Remove everything again with clean-lab.sh.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo in a disposable lab VM." >&2; exit 1; }

LAB=/tmp/suid-lab
mkdir -p "$LAB"

# --- SUID/SGID fixtures: every "program" is a copy of /bin/true ------------
install -m 4755 /bin/true "$LAB/helper"                    # unpackaged SUID file in /tmp
install -m 4755 /bin/true "$LAB/find"                      # only *named* like a GTFOBins program
install -m 4777 /bin/true "$LAB/ww-helper"                 # world-writable SUID file
printf '#!/bin/sh\nexit 0\n' > "$LAB/script.sh"
chmod 4755 "$LAB/script.sh"                                # SUID bit on a script
install -m 4755 -o nobody /bin/true "$LAB/nobody-helper"   # SUID file owned by a non-root user
install -d -m 2777 "$LAB/shared"                           # world-writable SGID dir, no sticky bit

# --- automation fixtures: no-op jobs scheduled for 31 February (never run) --
id labuser >/dev/null 2>&1 || useradd -m labuser
printf '#!/bin/sh\nexit 0\n' > /home/labuser/backup.sh
chown labuser:labuser /home/labuser/backup.sh && chmod 755 /home/labuser/backup.sh

mkdir -p /var/www/lab
printf '#!/bin/sh\nexit 0\n' > /var/www/lab/report.sh
chown -R daemon /var/www/lab && chmod 755 /var/www/lab/report.sh

printf '#!/bin/sh\nexit 0\n' > /tmp/update-check && chmod 777 /tmp/update-check

mkdir -p /etc/cron.d
echo '0 0 31 2 * root /home/labuser/backup.sh'        > /etc/cron.d/lab-backup
echo '0 0 31 2 * root /opt/legacy/cleanup.sh'         > /etc/cron.d/lab-cleanup
echo '0 0 31 2 * root /bin/sh /var/www/lab/report.sh' > /etc/cron.d/lab-report.cron
echo '0 0 31 2 * root /tmp/update-check'              > /etc/cron.d/lab-tmp
echo '0 0 31 2 * olduser /bin/true'                   > /etc/cron.d/lab-ghost
chmod 644 /etc/cron.d/lab-*

mkdir -p /etc/cron.daily
printf '#!/bin/sh\nexit 0\n' > /etc/cron.daily/lab-rotate.sh && chmod 755 /etc/cron.daily/lab-rotate.sh

echo "Lab fixtures created. Run clean-lab.sh when you are finished."

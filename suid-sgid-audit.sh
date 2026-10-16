#!/usr/bin/env bash
# =============================================================================
# suid-sgid-audit.sh  -  SUID/SGID permission audit for Linux
#
# Reference implementation written for the article
# "Automated Linux Security Auditing Using Custom SUID/SGID and Process
#  Monitoring Scripts with Lynis".
#
# AUDIT-ONLY: this script reads file metadata and writes a report. It never
# changes permissions, ownership, packages or any file it inspects.
#
# Requirements : bash 4+, GNU findutils, GNU coreutils (stat, date, head)
# Optional     : dpkg (Debian/Ubuntu) or rpm (Fedora/RHEL/SUSE) for package
#                ownership and integrity checks
# Privileges   : run as root (sudo) for complete results
#
# Exit codes   : 0 = no CRITICAL/HIGH findings
#                1 = at least one CRITICAL or HIGH finding
#                2 = usage or runtime error
# =============================================================================

set -u
set -o pipefail
export LC_ALL=C
umask 077

readonly VERSION="1.0.0"
readonly PROG="${0##*/}"

# ----------------------------- defaults --------------------------------------
SCAN_ROOT="/"
REPORT=""
BASELINE_IN=""
BASELINE_OUT=""
RECENT_DAYS=30
XDEV=0
PKG_CHECKS=1
MACHINE=0
QUIET=0

# Virtual and network filesystem types that are never descended into.
PRUNE_FSTYPES=(proc sysfs cgroup cgroup2 devpts securityfs debugfs tracefs
               pstore bpf configfs fusectl mqueue binfmt_misc efivarfs autofs
               nfs nfs4 cifs smb3 fuse.sshfs 9p)

# ----------------------------- state -----------------------------------------
declare -a INV_TYPE=() INV_MODE=() INV_OWNER=() INV_PKG=() INV_PATH=()
declare -a F_SEV=() F_RULE=() F_PATH=() F_MSG=() F_NEXT=()
declare -A SEV_COUNT=([CRITICAL]=0 [HIGH]=0 [MEDIUM]=0 [LOW]=0 [INFO]=0)
declare -A CURRENT=()          # path -> "mode owner:group" (for baselines)
declare -A VERIFY_CACHE=()     # package -> verify output
PKG_MGR="none"
N_SUID=0 N_SGID=0 N_DIRS=0
WORKDIR="" ERR_LOG=""

# ----------------------------- helpers ---------------------------------------
die()  { printf '%s: error: %s\n' "$PROG" "$*" >&2; exit 2; }
warn() { printf '%s: warning: %s\n' "$PROG" "$*" >&2; }

usage() {
    cat <<EOF
$PROG $VERSION - audit SUID/SGID files and set-ID directories (read-only)

Usage: sudo ./$PROG [options]

  -r DIR    Directory to scan (default: /)
  -o FILE   Report file (default: ./suid-sgid-report-<host>-<timestamp>.txt)
  -w FILE   Write the current inventory to FILE as a baseline
  -b FILE   Compare the current inventory against a baseline written with -w
  -m DAYS   Flag set-ID files modified in the last DAYS days (default: 30, 0 = off)
  -x        Do not cross into other mounted filesystems (find -xdev)
  -n        Skip package ownership and integrity checks (faster)
  -M        Machine-readable findings on stdout: SEVERITY|RULE|PATH|MESSAGE
  -q        Quiet: no console summary (the report is still written)
  -h        Show this help

Findings are candidates for manual review, not proof of a vulnerability.
EOF
}

# Replace control characters so odd file names cannot break the report.
clean() {
    local s=$1
    s=${s//$'\n'/?}; s=${s//$'\r'/?}; s=${s//$'\t'/ }
    printf '%s' "$s"
}

add_finding() {   # severity rule path message next-step
    F_SEV+=("$1"); F_RULE+=("$2"); F_PATH+=("$(clean "$3")")
    F_MSG+=("$4"); F_NEXT+=("$5")
    SEV_COUNT[$1]=$(( SEV_COUNT[$1] + 1 ))
}

# Programs that can run commands, spawn shells or overwrite files. A set-ID
# bit on any of these is almost always a privilege escalation path
# (see https://gtfobins.github.io/).
is_general_purpose_binary() {
    case "$1" in
        bash|sh|dash|zsh|ksh|mksh|csh|tcsh|fish|busybox) return 0 ;;
        python|python[0-9]*|perl|perl[0-9]*|ruby|ruby[0-9]*|lua|lua[0-9]*) return 0 ;;
        php|php[0-9]*|node|nodejs) return 0 ;;
        awk|gawk|mawk|nawk|sed|find|xargs|env|vi|vim|vim.*|nano|ed|less|more|man) return 0 ;;
        cp|mv|dd|tee|tar|zip|unzip|rsync|chmod|chown|install) return 0 ;;
        nc|ncat|netcat|socat|nmap|wget|curl|gdb|strace|docker) return 0 ;;
        *) return 1 ;;
    esac
}

# On merged-/usr systems the package database may record /bin/x while the
# file is found as /usr/bin/x (or the reverse). Return the other spelling.
alt_path() {
    case "$1" in
        /usr/bin/*|/usr/sbin/*|/usr/lib/*|/usr/lib64/*) printf '%s' "${1#/usr}" ;;
        /bin/*|/sbin/*|/lib/*|/lib64/*) printf '/usr%s' "$1" ;;
        *) printf '' ;;
    esac
}

detect_pkg_mgr() {
    if [[ $PKG_CHECKS -eq 0 ]]; then PKG_MGR="disabled"; return; fi
    if command -v dpkg-query >/dev/null 2>&1 && [[ -s /var/lib/dpkg/status ]]; then
        PKG_MGR="dpkg"
    elif command -v rpm >/dev/null 2>&1 && rpm -q rpm >/dev/null 2>&1; then
        PKG_MGR="rpm"
    fi
}

package_of() {    # path -> prints owning package name(s); returns 1 if none
    local cand out
    for cand in "$1" "$(alt_path "$1")"; do
        [[ -n $cand ]] || continue
        case $PKG_MGR in
            dpkg)
                out=$(dpkg-query -S "$cand" 2>/dev/null | grep -v '^diversion' | head -n 1) || out=""
                if [[ -n $out ]]; then printf '%s' "${out%%: /*}"; return 0; fi ;;
            rpm)
                out=$(rpm -qf --qf '%{NAME}\n' "$cand" 2>/dev/null | head -n 1) || out=""
                if [[ -n $out && $out != *"not owned"* ]]; then printf '%s' "$out"; return 0; fi ;;
        esac
    done
    return 1
}

verify_flags() {  # package path -> prints the verify flag field for that file
    local pkg=$1 p=$2 alt
    alt=$(alt_path "$p")
    if [[ -z ${VERIFY_CACHE[$pkg]+set} ]]; then
        case $PKG_MGR in
            dpkg) VERIFY_CACHE[$pkg]=$(dpkg --verify "$pkg" 2>/dev/null) ;;
            rpm)  VERIFY_CACHE[$pkg]=$(rpm -V "$pkg" 2>/dev/null) ;;
        esac
    fi
    printf '%s\n' "${VERIFY_CACHE[$pkg]}" |
        awk -v a="$p" -v b="$alt" '$NF==a || (b!="" && $NF==b) {print $1; exit}'
}

describe_verify() {   # verify flags -> human description (rc 1 if nothing)
    local f=$1 d=""
    [[ -z $f || $f == missing ]] && return 1
    [[ ${f:2:1} == 5 ]] && d+="content checksum differs; "
    if [[ $PKG_MGR == rpm ]]; then
        [[ ${f:1:1} == M ]] && d+="mode differs (set-ID bit may have been added or changed); "
        [[ ${f:5:1} == U ]] && d+="owner differs; "
        [[ ${f:6:1} == G ]] && d+="group differs; "
    fi
    [[ -n $d ]] || return 1
    printf '%s' "${d%; }"
}

# ----------------------------- checks ----------------------------------------
check_temp_mounts() {
    local mp opts
    for mp in /tmp /var/tmp /dev/shm; do
        [[ -d $mp ]] || continue
        opts=$(awk -v m="$mp" '$2==m {o=$4} END {print o}' /proc/self/mounts 2>/dev/null)
        if [[ -z $opts ]]; then
            add_finding INFO R14 "$mp" \
                "not a separate mount, so the nosuid mount option cannot be applied to it" \
                "Consider a dedicated mount (for example tmpfs) with nosuid,nodev for $mp"
        elif [[ ",$opts," != *",nosuid,"* ]]; then
            add_finding LOW R14 "$mp" \
                "mounted without the nosuid option (options: $opts)" \
                "Add nosuid to its /etc/fstab entry or systemd .mount unit, then test applications that use $mp"
        fi
    done
}

check_file() {    # path octal-mode owner group uid gid mtime
    local path=$1 mode=$2 owner=$3 group=$4 uid=$5 gid=$6 mtime=$7
    local m=$((8#$mode)) base=${path##*/} pkg="" flags desc
    local now; now=$(date +%s)

    if (( m & 8#0002 )); then
        add_finding CRITICAL R01 "$path" \
            "world-writable set-ID file: any local user can alter a program that runs with elevated privileges" \
            "Confirm with stat; restore the packaged file or remove the write bit (chmod o-w) after review"
    elif (( m & 8#0020 )); then
        add_finding HIGH R02 "$path" \
            "group-writable set-ID file: members of group '$group' can alter it" \
            "List members with 'getent group $group'; remove the group write bit (chmod g-w) if not required"
    fi
    case $path in
        /tmp/*|/var/tmp/*|/dev/shm/*|/run/user/*|/home/*)
            add_finding HIGH R03 "$path" \
                "set-ID file in a temporary or user-writable location" \
                "Identify who created it (stat, file, sha256sum) and why; legitimate set-ID programs live in system directories" ;;
        /media/*|/mnt/*)
            add_finding MEDIUM R03 "$path" \
                "set-ID file on removable or manually mounted media" \
                "Mount removable media with nosuid unless set-ID programs are explicitly required" ;;
    esac
    if is_general_purpose_binary "$base"; then
        add_finding HIGH R04 "$path" \
            "general-purpose program '$base' carries a set-ID bit; such programs can usually be made to run commands with elevated privileges" \
            "Check GTFOBins for '$base'; remove the bit (chmod u-s / g-s) unless a documented requirement exists"
    fi
    if [[ $owner == UNKNOWN || $group == UNKNOWN ]]; then
        add_finding HIGH R08 "$path" \
            "owner or group has no matching account (uid $uid, gid $gid): possibly left behind by a deleted user or an extracted archive" \
            "Find the origin of the file; assign correct ownership or remove it after review"
    elif (( m & 8#4000 )) && [[ $uid -ne 0 ]]; then
        add_finding MEDIUM R07 "$path" \
            "SUID file owned by non-root user '$owner': it runs with that account's privileges" \
            "Confirm the package or vendor intends this; such files are uncommon"
    fi
    if [[ $(head -c 2 -- "$path" 2>/dev/null | tr -d '\0') == '#!' ]]; then
        add_finding MEDIUM R09 "$path" \
            "interpreted script with a set-ID bit; Linux ignores set-ID bits on scripts, so this indicates a misconfiguration" \
            "Remove the bit; if the task needs privileges, use sudo rules or a systemd service instead"
    fi
    if [[ $PKG_MGR == dpkg || $PKG_MGR == rpm ]]; then
        if pkg=$(package_of "$path"); then
            flags=$(verify_flags "${pkg%%,*}" "$path")
            if desc=$(describe_verify "$flags"); then
                add_finding HIGH R05 "$path" \
                    "differs from package '$pkg': $desc (verify flags: $flags)" \
                    "Reinstall the package from a trusted repository and investigate how the change happened"
            fi
        else
            add_finding MEDIUM R06 "$path" \
                "not owned by any installed package (manual or third-party installation)" \
                "Identify the vendor or installer; keep a record if legitimate, otherwise remove the set-ID bit"
        fi
    fi
    if (( RECENT_DAYS > 0 && mtime >= now - RECENT_DAYS * 86400 )); then
        add_finding MEDIUM R10 "$path" \
            "modified within the last $RECENT_DAYS days ($(date -d "@$mtime" '+%Y-%m-%d %H:%M'))" \
            "Correlate with package updates (apt/dnf history) and change records"
    fi
    CHECK_PKG=${pkg:-}     # returned through a global so findings stay in this shell
}

check_directory() {   # path octal-mode
    local path=$1 m=$((8#$2))
    if (( m & 8#4000 )); then
        add_finding INFO R13 "$path" \
            "SUID bit on a directory has no effect on Linux file ownership and is usually set by mistake" \
            "Remove it (chmod u-s) after confirming no application expects it"
    fi
    if (( (m & 8#2000) && (m & 8#0002) )); then
        if (( m & 8#1000 )); then
            add_finding LOW R12 "$path" \
                "world-writable SGID directory (sticky bit set): any user can create files that inherit the directory group" \
                "Confirm the shared directory is intended and its group grants nothing sensitive"
        else
            add_finding HIGH R12 "$path" \
                "world-writable SGID directory without the sticky bit: any user can create, rename or delete other users' files" \
                "Restrict write access (chmod o-w) or add the sticky bit (chmod +t) after review"
        fi
    fi
}

process_entry() {
    local path=$1 meta mode owner group uid gid mtime ftype type pkg="-"
    # %a octal mode, %U/%G owner/group names, %u/%g numeric ids, %Y mtime, %F type
    meta=$(stat -c '%a|%U|%G|%u|%g|%Y|%F' -- "$path" 2>/dev/null) || {
        printf 'stat failed: %s\n' "$(clean "$path")" >>"$ERR_LOG"; return; }
    IFS='|' read -r mode owner group uid gid mtime ftype <<<"$meta"
    local m=$((8#$mode))

    if [[ $ftype == directory ]]; then
        type="DIR"; (( N_DIRS++ ))
        (( m & 8#4000 )) && type+="-SUID"
        (( m & 8#2000 )) && type+="-SGID"
        check_directory "$path" "$mode"
    else
        type=""
        (( m & 8#4000 )) && { type="SUID"; (( N_SUID++ )); }
        (( m & 8#2000 )) && { type="${type:+$type+}SGID"; (( N_SGID++ )); }
        check_file "$path" "$mode" "$owner" "$group" "$uid" "$gid" "$mtime"
        pkg=$CHECK_PKG
        if [[ $PKG_MGR == dpkg || $PKG_MGR == rpm ]]; then pkg=${pkg:-"(none)"}; else pkg="n/a"; fi
    fi

    INV_TYPE+=("$type"); INV_MODE+=("$mode"); INV_OWNER+=("$owner:$group")
    INV_PKG+=("$pkg"); INV_PATH+=("$(clean "$path")")
    CURRENT[$path]="$mode $owner:$group"
}

compare_baseline() {
    local mode og path
    declare -A base=()
    while IFS=$'\t' read -r mode og path; do
        [[ -n ${path:-} && ${mode:0:1} != "#" ]] || continue
        base[$path]="$mode $og"
    done <"$BASELINE_IN"
    for path in "${!CURRENT[@]}"; do
        if [[ -z ${base[$path]+set} ]]; then
            add_finding MEDIUM R11 "$path" "new since baseline (${CURRENT[$path]})" \
                "Confirm the change was planned (package install, vendor software) and update the baseline"
        elif [[ ${base[$path]} != "${CURRENT[$path]}" ]]; then
            add_finding MEDIUM R11 "$path" "changed since baseline: was '${base[$path]}', now '${CURRENT[$path]}'" \
                "Confirm the change was planned and update the baseline"
        fi
    done
    for path in "${!base[@]}"; do
        [[ -n ${CURRENT[$path]+set} ]] || add_finding INFO R11 "$path" \
            "in baseline but no longer found (removed, or set-ID bit cleared)" \
            "Confirm the removal was intended"
    done
}

write_baseline() {
    local path
    {
        printf '# suid-sgid-audit baseline %s host=%s root=%s\n' "$(date '+%F %T')" "$(hostname)" "$SCAN_ROOT"
        for path in "${!CURRENT[@]}"; do
            printf '%s\t%s\t%s\n' "${CURRENT[$path]% *}" "${CURRENT[$path]#* }" "$(clean "$path")"
        done | sort -t $'\t' -k3
    } >"$BASELINE_OUT" || die "cannot write baseline $BASELINE_OUT"
}

# ----------------------------- report ----------------------------------------
sorted_indices() {    # severity -> finding indices ordered by path, then rule
    local i
    for i in "${!F_SEV[@]}"; do
        [[ ${F_SEV[$i]} == "$1" ]] && printf '%s\t%s\t%s\n' "${F_PATH[$i]}" "${F_RULE[$i]}" "$i"
    done | sort -t $'\t' -k1,1 -k2,2 | cut -f3
}

write_report() {
    local i sev os errs
    os=$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release 2>/dev/null | tr -d '"')
    os=${os:-unknown}
    errs=$(wc -l <"$ERR_LOG")
    {
        printf '%s\n' "=============================================================================="
        printf ' SUID/SGID PERMISSION AUDIT REPORT  (%s %s)\n' "$PROG" "$VERSION"
        printf '%s\n' "=============================================================================="
        printf ' Host            : %s\n' "$(hostname)"
        printf ' OS / kernel     : %s / %s\n' "$os" "$(uname -r)"
        printf ' Scan root       : %s%s\n' "$SCAN_ROOT" "$([[ $XDEV -eq 1 ]] && printf ' (single filesystem)')"
        printf ' Started         : %s\n' "$START_TIME"
        printf ' Run as          : %s (uid %s)\n' "$(id -un)" "$EUID"
        printf ' Package checks  : %s\n' "$PKG_MGR"
        printf ' Recent window   : %s days\n' "$RECENT_DAYS"
        printf '%s\n' "------------------------------------------------------------------------------"
        printf ' INVENTORY: %d SUID file(s), %d SGID file(s), %d set-ID director(ies)\n\n' "$N_SUID" "$N_SGID" "$N_DIRS"
        printf ' %-10s %-5s %-22s %-18s %s\n' "TYPE" "MODE" "OWNER:GROUP" "PACKAGE" "PATH"
        for i in "${!INV_PATH[@]}"; do
            printf ' %-10s %-5s %-22s %-18s %s\n' "${INV_TYPE[$i]}" "${INV_MODE[$i]}" \
                "${INV_OWNER[$i]}" "${INV_PKG[$i]//, /,}" "${INV_PATH[$i]}"
        done | sort -b -k5
        printf '%s\n' "------------------------------------------------------------------------------"
        printf ' FINDINGS (candidates for review, ordered by severity)\n\n'
        if (( ${#F_SEV[@]} == 0 )); then printf ' No findings.\n'; fi
        for sev in CRITICAL HIGH MEDIUM LOW INFO; do
            for i in $(sorted_indices "$sev"); do
                printf ' [%s] %s  %s\n' "$sev" "${F_RULE[$i]}" "${F_PATH[$i]}"
                printf '        Why : %s\n' "${F_MSG[$i]}"
                printf '        Next: %s\n\n' "${F_NEXT[$i]}"
            done
        done
        printf '%s\n' "------------------------------------------------------------------------------"
        printf ' HOW TO VALIDATE A FINDING\n'
        printf '   ls -l -- PATH ; stat -- PATH ; file -- PATH ; sha256sum -- PATH\n'
        printf '   Debian/Ubuntu : dpkg -S PATH  then  dpkg --verify PACKAGE\n'
        printf '   Fedora/RHEL   : rpm -qf PATH  then  rpm -Vf PATH\n'
        printf '%s\n' "------------------------------------------------------------------------------"
        printf ' SUMMARY: CRITICAL %d | HIGH %d | MEDIUM %d | LOW %d | INFO %d\n' \
            "${SEV_COUNT[CRITICAL]}" "${SEV_COUNT[HIGH]}" "${SEV_COUNT[MEDIUM]}" "${SEV_COUNT[LOW]}" "${SEV_COUNT[INFO]}"
        printf ' Paths that could not be read (permission or race): %s\n' "$errs"
        printf ' Finished: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
        printf ' Note: a set-ID bit is not a vulnerability by itself. Every finding needs\n'
        printf ' contextual verification before any change is made.\n'
    } >"$REPORT" || die "cannot write report $REPORT"
}

print_machine() {
    local sev i
    for sev in CRITICAL HIGH MEDIUM LOW INFO; do
        for i in $(sorted_indices "$sev"); do
            printf '%s|%s|%s|%s\n' "$sev" "${F_RULE[$i]}" "${F_PATH[$i]//|/!}" "${F_MSG[$i]//|/!}"
        done
    done
}

print_summary() {
    local red="" yel="" grn="" rst=""
    if [[ -t 1 ]]; then red=$'\e[31m'; yel=$'\e[33m'; grn=$'\e[32m'; rst=$'\e[0m'; fi
    printf '\n[*] Scanned %s: %d SUID, %d SGID files, %d set-ID directories\n' "$SCAN_ROOT" "$N_SUID" "$N_SGID" "$N_DIRS"
    printf '[*] Findings: %sCRITICAL %d  HIGH %d%s  %sMEDIUM %d%s  LOW %d  INFO %d\n' \
        "$red" "${SEV_COUNT[CRITICAL]}" "${SEV_COUNT[HIGH]}" "$rst" "$yel" "${SEV_COUNT[MEDIUM]}" "$rst" \
        "${SEV_COUNT[LOW]}" "${SEV_COUNT[INFO]}"
    if (( SEV_COUNT[CRITICAL] + SEV_COUNT[HIGH] == 0 )); then
        printf '[*] %sNo critical or high findings.%s\n' "$grn" "$rst"
    fi
    printf '[*] Report written to %s\n' "$REPORT"
}

# ----------------------------- main ------------------------------------------
parse_args() {
    local opt
    while getopts ":r:o:w:b:m:xnMqh" opt; do
        case $opt in
            r) SCAN_ROOT=$OPTARG ;;
            o) REPORT=$OPTARG ;;
            w) BASELINE_OUT=$OPTARG ;;
            b) BASELINE_IN=$OPTARG ;;
            m) RECENT_DAYS=$OPTARG ;;
            x) XDEV=1 ;;
            n) PKG_CHECKS=0 ;;
            M) MACHINE=1; QUIET=1 ;;
            q) QUIET=1 ;;
            h) usage; exit 0 ;;
            :) die "option -$OPTARG needs a value (see -h)" ;;
            *) die "unknown option -$OPTARG (see -h)" ;;
        esac
    done
    shift $((OPTIND - 1))
    (( $# == 0 )) || die "unexpected argument: $1 (see -h)"

    [[ -d $SCAN_ROOT ]] || die "scan root '$SCAN_ROOT' is not a directory"
    [[ $RECENT_DAYS =~ ^[0-9]+$ ]] || die "-m expects a whole number of days"
    [[ -z $BASELINE_IN || -r $BASELINE_IN ]] || die "baseline '$BASELINE_IN' is not readable"
    [[ -n $REPORT ]] || REPORT="./suid-sgid-report-$(hostname -s)-$(date +%Y%m%d-%H%M%S).txt"
    local f
    for f in "$REPORT" "$BASELINE_OUT"; do
        [[ -n $f && -L $f ]] && die "refusing to write through symbolic link: $f"
    done
    return 0
}

main() {
    parse_args "$@"
    (( BASH_VERSINFO[0] >= 4 )) || die "bash 4 or newer is required"
    local tool
    for tool in find stat date awk; do
        command -v "$tool" >/dev/null || die "required command not found: $tool"
    done
    [[ $EUID -eq 0 ]] || warn "not running as root: unreadable directories will be skipped and results will be incomplete"

    WORKDIR=$(mktemp -d) || die "cannot create a temporary directory"
    trap 'rm -rf -- "$WORKDIR"' EXIT
    ERR_LOG="$WORKDIR/errors.log"; : >"$ERR_LOG"
    START_TIME=$(date '+%Y-%m-%d %H:%M:%S %z')
    detect_pkg_mgr

    # Build: find -P ROOT [-xdev] ( -fstype a -o -fstype b ... ) -prune -o
    #        ( -type f -o -type d ) ( -perm -4000 -o -perm -2000 ) -print0
    local -a args=(-P "$SCAN_ROOT")
    (( XDEV )) && args+=(-xdev)
    args+=('(')
    local t first=1
    for t in "${PRUNE_FSTYPES[@]}"; do
        (( first )) && first=0 || args+=(-o)
        args+=(-fstype "$t")
    done
    args+=(')' -prune -o '(' -type f -o -type d ')' '(' -perm -4000 -o -perm -2000 ')' -print0)

    local path
    while IFS= read -r -d '' path; do
        process_entry "$path"
    done < <(find "${args[@]}" 2>>"$ERR_LOG")

    [[ $SCAN_ROOT == / ]] && check_temp_mounts
    [[ -n $BASELINE_IN ]] && compare_baseline
    [[ -n $BASELINE_OUT ]] && write_baseline
    write_report
    (( MACHINE )) && print_machine
    (( QUIET )) || print_summary

    (( SEV_COUNT[CRITICAL] + SEV_COUNT[HIGH] > 0 )) && exit 1
    exit 0
}

main "$@"

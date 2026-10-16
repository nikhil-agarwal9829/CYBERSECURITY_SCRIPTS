#!/usr/bin/env bash
# =============================================================================
# automation-audit.sh  -  scheduled task, auto-start and privilege audit
#
# Reference implementation written for the article
# "Automated Linux Security Auditing Using Custom SUID/SGID and Process
#  Monitoring Scripts with Lynis".
#
# AUDIT-ONLY: the script never kills processes, stops or disables services,
# edits or deletes cron jobs, or changes permissions. It reads configuration
# and process metadata and writes a report with recommendations.
#
# Scope (what is inspected):
#   * cron: /etc/crontab, /etc/cron.d/*, user crontabs in the cron spool,
#     /etc/cron.{hourly,daily,weekly,monthly}/ and /etc/anacrontab
#   * systemd: enabled and running services, timers and the services they start
#   * startup: /etc/rc.local, /etc/init.d/, XDG autostart entries, at jobs,
#     /etc/ld.so.preload
#   * a snapshot of running processes (identity, executable, starting unit)
# Out of scope: per-user systemd units, shell start-up files (.bashrc etc.),
# udev rules, PAM, kernel modules, container runtimes and anything not listed.
#
# Requirements : bash 4+, coreutils, procps (ps), findutils, awk, sed
# Optional     : systemctl (systemd), dpkg or rpm (package ownership), atq
# Privileges   : run as root (sudo) for complete results
# Exit codes   : 0 = no CRITICAL/HIGH findings, 1 = CRITICAL/HIGH present,
#                2 = usage or runtime error
# =============================================================================

set -u
set -o pipefail
export LC_ALL=C
umask 077

readonly VERSION="1.0.0"
readonly PROG="${0##*/}"

# ----------------------------- defaults --------------------------------------
REPORT=""
MACHINE=0
QUIET=0
DO_PROCS=1
LD_PRELOAD_FILE="/etc/ld.so.preload"
CRON_SPOOLS=(/var/spool/cron/crontabs /var/spool/cron)   # Debian/Ubuntu, Fedora/RHEL
RUNPARTS_DIRS=(/etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly)

# ----------------------------- state -----------------------------------------
declare -a T_TYPE=() T_SOURCE=() T_SCHED=() T_IDENT=() T_CMD=()
declare -a F_SEV=() F_RULE=() F_ITEM=() F_MSG=() F_NEXT=()
declare -A SEV_COUNT=([CRITICAL]=0 [HIGH]=0 [MEDIUM]=0 [LOW]=0 [INFO]=0)
declare -A PKG_CACHE=() USER_CACHE=() SEEN=()
declare -a PROC_ROWS=() SYSV_SCRIPTS=()
declare -A PROC_BY_USER=()
PKG_MGR="none" DEBIAN_FAMILY=0 SYSTEMD=0 WORKDIR=""

# ----------------------------- helpers ---------------------------------------
die()  { printf '%s: error: %s\n' "$PROG" "$*" >&2; exit 2; }
warn() { printf '%s: warning: %s\n' "$PROG" "$*" >&2; }

usage() {
    cat <<EOF
$PROG $VERSION - audit scheduled tasks, auto-started services and their privileges

Usage: sudo ./$PROG [options]

  -o FILE   Report file (default: ./automation-audit-report-<host>-<timestamp>.txt)
  -P        Skip the running-process snapshot
  -M        Machine-readable findings on stdout: SEVERITY|RULE|ITEM|MESSAGE
  -q        Quiet: no console summary (the report is still written)
  -h        Show this help

Audit-only: nothing on the system is stopped, disabled, deleted or changed.
Findings are candidates for manual review, not automatic verdicts.
EOF
}

clean() {
    local s=$1
    s=${s//$'\n'/ }; s=${s//$'\r'/ }; s=${s//$'\t'/ }
    printf '%s' "$s"
}

trunc() {   # string max-length
    local s=$1 n=$2
    (( ${#s} > n )) && s="${s:0:n-3}..."
    printf '%s' "$s"
}

add_finding() {   # severity rule item message next-step
    local key="$1|$2|$3|$4"
    [[ -n ${SEEN[$key]+set} ]] && return 0       # identical finding already recorded
    SEEN[$key]=1
    F_SEV+=("$1"); F_RULE+=("$2"); F_ITEM+=("$(clean "$3")")
    F_MSG+=("$(clean "$4")"); F_NEXT+=("$5")
    SEV_COUNT[$1]=$(( SEV_COUNT[$1] + 1 ))
}

add_task() {      # type source schedule identity command
    T_TYPE+=("$1"); T_SOURCE+=("$(clean "$2")"); T_SCHED+=("$(clean "$3")")
    T_IDENT+=("$(clean "$4")"); T_CMD+=("$(clean "$5")")
}

is_root_identity() { [[ $1 == root || $1 == 0 ]]; }

user_name() {     # uid -> name (cached)
    if [[ -z ${USER_CACHE[$1]+set} ]]; then
        USER_CACHE[$1]=$(getent passwd "$1" | cut -d: -f1)
        [[ -n ${USER_CACHE[$1]} ]] || USER_CACHE[$1]="uid:$1"
    fi
    printf '%s' "${USER_CACHE[$1]}"
}

detect_platform() {
    [[ -f /etc/debian_version ]] && DEBIAN_FAMILY=1
    if command -v dpkg-query >/dev/null 2>&1 && [[ -s /var/lib/dpkg/status ]]; then
        PKG_MGR="dpkg"
    elif command -v rpm >/dev/null 2>&1 && rpm -q rpm >/dev/null 2>&1; then
        PKG_MGR="rpm"
    fi
    if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
        SYSTEMD=1      # systemd is the running init system
    fi
}

alt_path() {
    case "$1" in
        /usr/bin/*|/usr/sbin/*|/usr/lib/*|/usr/lib64/*) printf '%s' "${1#/usr}" ;;
        /bin/*|/sbin/*|/lib/*|/lib64/*) printf '/usr%s' "$1" ;;
        *) printf '' ;;
    esac
}

is_packaged() {   # path -> 0 if owned by an installed package (cached)
    local p=$1 cand rc=1
    [[ $PKG_MGR == none ]] && return 0          # cannot tell; do not flag
    if [[ -z ${PKG_CACHE[$p]+set} ]]; then
        for cand in "$p" "$(alt_path "$p")"; do
            [[ -n $cand ]] || continue
            case $PKG_MGR in
                dpkg) dpkg-query -S "$cand" >/dev/null 2>&1 && { rc=0; break; } ;;
                rpm)  rpm -qf "$cand" >/dev/null 2>&1 && { rc=0; break; } ;;
            esac
        done
        PKG_CACHE[$p]=$rc
    fi
    return "${PKG_CACHE[$p]}"
}

# Describe why a file or directory can be changed by a non-root account.
# Prints a reason and returns 0, or returns 1 if only root can change it.
nonroot_writable() {   # octal-mode uid gid owner-name group-name type
    local m=$((8#$1)) uid=$2 gid=$3 owner=$4 group=$5 ftype=$6
    if (( uid != 0 )); then printf "owned by '%s'" "$owner"; return 0; fi
    if (( (m & 8#0020) && gid != 0 )); then printf "group-writable by '%s'" "$group"; return 0; fi
    if (( m & 8#0002 )); then
        if [[ $ftype == directory ]] && (( m & 8#1000 )); then return 1; fi
        printf 'world-writable'; return 0
    fi
    return 1
}

# ----------------------------- core checks -----------------------------------
# Check a file or directory that a task executes or depends on.
#   role: exec   = the program the task runs
#         script = a script handed to an interpreter (bash x.sh, python y.py)
#         dir    = a directory argument (for example run-parts /etc/cron.daily)
check_target() {      # path identity context role
    local path=$1 ident=$2 ctx=$3 role=$4 real meta mode uid gid owner group ftype reason
    local parent pmeta pmode puid pgid powner pgroup pftype m pm

    if [[ ! -e $path ]]; then
        if [[ $role != dir ]]; then
            add_finding MEDIUM A05 "$path" \
                "referenced by $ctx but not found: the task may be obsolete or broken" \
                "Confirm whether the task is still needed; remove or fix it through change control"
        fi
        return
    fi
    real=$(readlink -f -- "$path") || real=$path
    meta=$(stat -c '%a|%u|%g|%U|%G|%F' -- "$real" 2>/dev/null) || return
    IFS='|' read -r mode uid gid owner group ftype <<<"$meta"
    m=$((8#$mode))

    local ww=0      # world-writable (a directory with the sticky bit is not counted)
    if (( m & 8#0002 )) && { [[ $ftype != directory ]] || (( !(m & 8#1000) )); }; then ww=1; fi
    if (( ww )); then
        add_finding HIGH A02 "$real" \
            "world-writable $ftype used by $ctx (runs as $ident): any local user can change what is executed" \
            "Restrict permissions after confirming ownership (for example chmod o-w); investigate whether it was modified"
    elif is_root_identity "$ident" && reason=$(nonroot_writable "$mode" "$uid" "$gid" "$owner" "$group" "$ftype"); then
        add_finding HIGH A01 "$real" \
            "$ftype used by $ctx runs as root but is $reason: that account can make root execute its code" \
            "Make it root-owned and not writable by others, or run the task as the owning account instead of root"
    fi

    parent=$(dirname -- "$real")
    pmeta=$(stat -c '%a|%u|%g|%U|%G|%F' -- "$parent" 2>/dev/null) || pmeta=""
    if [[ -n $pmeta && $role != dir ]]; then
        IFS='|' read -r pmode puid pgid powner pgroup pftype <<<"$pmeta"
        pm=$((8#$pmode))
        if (( (pm & 8#0002) && !(pm & 8#1000) )); then
            add_finding HIGH A02 "$real" \
                "parent directory $parent is world-writable without the sticky bit: the file can be replaced" \
                "Fix the directory permissions or move the program to a protected location"
        elif is_root_identity "$ident" && reason=$(nonroot_writable "$pmode" "$puid" "$pgid" "$powner" "$pgroup" "$pftype"); then
            add_finding HIGH A01 "$real" \
                "parent directory $parent is $reason: the file run as root can be replaced" \
                "Move the program to a root-owned directory such as /usr/local/sbin"
        fi
    fi

    case $real in
        /tmp/*|/var/tmp/*|/dev/shm/*)
            add_finding HIGH A03 "$real" \
                "$ctx executes or uses a path in a temporary directory" \
                "Temporary directories are shared and often cleaned; move the program to a protected location" ;;
        /home/*)
            if is_root_identity "$ident"; then
                add_finding MEDIUM A04 "$real" \
                    "$ctx runs as root but uses a path inside a user's home directory" \
                    "Move the program to a root-owned location, or run the task as that user"
            fi ;;
    esac

    if [[ $role != dir && $ftype == "regular file" ]] && is_root_identity "$ident" && ! is_packaged "$real"; then
        add_finding LOW A07 "$real" \
            "custom (not package-owned) program run as root by $ctx" \
            "Confirm the owner and purpose; consider a dedicated service account and least privilege"
    fi
}

check_config() {      # path context  -> files that define tasks must be root-controlled
    local path=$1 ctx=$2 meta mode uid gid owner group ftype reason
    [[ -e $path ]] || return
    meta=$(stat -c '%a|%u|%g|%U|%G|%F' -- "$path" 2>/dev/null) || return
    IFS='|' read -r mode uid gid owner group ftype <<<"$meta"
    if reason=$(nonroot_writable "$mode" "$uid" "$gid" "$owner" "$group" "$ftype"); then
        add_finding HIGH A08 "$path" \
            "$ctx is $reason: a non-root account can add or change tasks that may run as root" \
            "Restore root ownership and remove group/other write access, then review the content for changes"
    fi
}

check_identity() {    # account context
    local acct=$1 ctx=$2
    case $acct in
        ""|root|0|dynamic*|desktop-user|session-user) return ;;
    esac
    if ! getent passwd "$acct" >/dev/null 2>&1; then
        add_finding MEDIUM A06 "$acct" \
            "$ctx runs as an account that does not exist (removed user or obsolete task)" \
            "Remove or reassign the task after confirming it is no longer needed"
    fi
}

is_interpreter() {
    case "${1##*/}" in
        sh|bash|dash|zsh|ksh|python|python[0-9]*|perl|perl[0-9]*|php|php[0-9]*|ruby|ruby[0-9]*|node|nodejs|lua|lua[0-9]*) return 0 ;;
        *) return 1 ;;
    esac
}

# Lightweight command analysis. This is not a full shell parser: it finds the
# programs a command line runs (words in command position) and the script an
# interpreter is given, then checks those paths. Complex commands may be only
# partially analysed.
analyze_command() {   # command identity context
    local cmd=$1 ident=$2 ctx=$3 s w wbase cmdpos=1 wrapper=0 interp=0 script_done=0 resolved
    s=$(sed -E -e 's/(^|[^\\])%.*$/\1/' \
               -e 's/[0-9]*>&[0-9-]+//g' \
               -e 's/[0-9&]*[<>]{1,2}[[:space:]]*[^[:space:];&|]+//g' <<<"$cmd")
    s=${s//[;&|()\`\{\}]/ ; }      # shell operators become a ';' separator token
    local -a words
    read -ra words <<<"$s"
    for w in "${words[@]}"; do
        w=${w//[\"\']/}
        [[ -n $w ]] || continue
        if [[ $w == ";" ]]; then cmdpos=1; wrapper=0; interp=0; script_done=0; continue; fi
        if (( cmdpos )); then
            case $w in
                if|then|else|elif|do|while|until|'!'|exec|command) continue ;;
                nice|ionice|nohup|timeout|chronic|setsid|stdbuf|flock|sudo|env) wrapper=1; continue ;;
            esac
            if (( wrapper )) && [[ $w == -* || $w =~ ^[0-9.]+[smhd]?$ ]]; then continue; fi
            if [[ $w =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then continue; fi     # VAR=value prefix
            cmdpos=0; wrapper=0
            wbase=${w##*/}
            case $wbase in '['|'[['|test|cd|true|false|:|echo|printf|fi|done) continue ;; esac
            if [[ $w == /* ]]; then
                check_target "$w" "$ident" "$ctx" exec
            elif [[ $w != *'$'* ]]; then
                resolved=$(type -P -- "$w" 2>/dev/null) || resolved=""
                [[ -n $resolved ]] && check_target "$resolved" "$ident" "$ctx" exec
            fi
            is_interpreter "$w" && interp=1
        elif [[ $w == /* ]]; then
            if (( interp && !script_done )); then
                check_target "$w" "$ident" "$ctx" script; script_done=1
            elif [[ -d $w ]]; then
                check_target "$w" "$ident" "$ctx" dir
            fi
        fi
    done
}

# ----------------------------- collectors ------------------------------------
parse_crontab() {     # file format(system|user) default-identity
    local file=$1 fmt=$2 defid=$3 line n=0 sched who cmd m h dom mon dow ctx
    while IFS= read -r line || [[ -n $line ]]; do
        n=$((n + 1))
        line=${line#"${line%%[![:space:]]*}"}
        [[ -z $line || $line == \#* ]] && continue
        [[ $line =~ ^[A-Za-z_][A-Za-z0-9_]*[[:space:]]*= ]] && continue    # variable
        if [[ $line == @* ]]; then
            if [[ $fmt == system ]]; then read -r sched who cmd <<<"$line"
            else read -r sched cmd <<<"$line"; who=$defid; fi
        else
            if [[ $fmt == system ]]; then read -r m h dom mon dow who cmd <<<"$line"
            else read -r m h dom mon dow cmd <<<"$line"; who=$defid; fi
            sched="$m $h $dom $mon $dow"
        fi
        ctx="cron entry $file:$n"
        if [[ -z ${cmd:-} ]]; then
            add_finding LOW A09 "$file:$n" "malformed cron line (no command found)" "Correct or remove the line"
            continue
        fi
        add_task cron "$file:$n" "$sched" "$who" "$cmd"
        check_identity "$who" "$ctx"
        [[ $sched == @reboot ]] && add_finding INFO A15 "$file:$n" \
            "runs at every boot as $who: $(trunc "$cmd" 80)" "Confirm the boot-time task is still required"
        analyze_command "$cmd" "$who" "$ctx"
    done <"$file"
}

valid_runparts_name() { [[ $1 =~ ^[A-Za-z0-9_-]+$ ]]; }

collect_cron() {
    local f d base spool
    if [[ -f /etc/crontab ]]; then
        check_config /etc/crontab "/etc/crontab"
        parse_crontab /etc/crontab system root
    fi
    if [[ -d /etc/cron.d ]]; then
        check_config /etc/cron.d "directory /etc/cron.d"
        for f in /etc/cron.d/*; do
            [[ -f $f ]] || continue
            base=${f##*/}
            check_config "$f" "cron file $f"
            if (( DEBIAN_FAMILY )) && ! valid_runparts_name "$base"; then
                add_finding LOW A09 "$f" \
                    "Debian/Ubuntu cron ignores /etc/cron.d files whose names contain characters such as dots, so this file may never run" \
                    "Rename it (letters, digits, '_' and '-' only) or remove it if obsolete"
            fi
            parse_crontab "$f" system root
        done
    fi
    for spool in "${CRON_SPOOLS[@]}"; do
        [[ -d $spool ]] || continue
        for f in "$spool"/*; do
            [[ -f $f && ! -L $f ]] || continue
            base=${f##*/}
            local meta mode
            meta=$(stat -c '%a' -- "$f" 2>/dev/null) || continue
            mode=$((8#$meta))
            if (( mode & 8#0022 )); then
                add_finding HIGH A08 "$f" "user crontab is writable by group or others" \
                    "Reset permissions (crontab files are normally mode 600) and review the content"
            fi
            parse_crontab "$f" user "$base"
        done
    done
    for d in "${RUNPARTS_DIRS[@]}"; do
        [[ -d $d ]] || continue
        check_config "$d" "directory $d"
        for f in "$d"/*; do
            [[ -f $f ]] || continue
            base=${f##*/}
            [[ $base == .placeholder ]] && continue
            check_config "$f" "periodic script $f"
            if [[ ! -x $f ]]; then
                add_finding LOW A09 "$f" "not executable, so run-parts skips it (possibly obsolete)" \
                    "Make it executable if it should run, otherwise remove it"
            elif (( DEBIAN_FAMILY )) && ! valid_runparts_name "$base"; then
                add_finding LOW A09 "$f" \
                    "Debian/Ubuntu run-parts skips files whose names contain dots or other characters, so this script may never run" \
                    "Rename it (letters, digits, '_' and '-' only) or remove it if obsolete"
            fi
            add_task cron "$f" "${d#/etc/cron.}" root "$f"
            check_target "$f" root "periodic script $f" exec
        done
    done
    if [[ -f /etc/anacrontab ]]; then
        local line n=0 period delay jobid cmd
        check_config /etc/anacrontab "/etc/anacrontab"
        while IFS= read -r line || [[ -n $line ]]; do
            n=$((n + 1))
            line=${line#"${line%%[![:space:]]*}"}
            [[ -z $line || $line == \#* || $line =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] && continue
            read -r period delay jobid cmd <<<"$line"
            [[ -n ${cmd:-} ]] || continue
            add_task anacron "/etc/anacrontab:$n" "every $period day(s), delay ${delay}m ($jobid)" root "$cmd"
            analyze_command "$cmd" root "anacron job $jobid"
        done </etc/anacrontab
    fi
}

sd_prop() {           # property-name  (reads $SD_OUT)
    sed -n "s/^$1=//p" <<<"$SD_OUT" | head -n 1
}

collect_systemd() {
    (( SYSTEMD )) || return 0
    local u t ident origins exec argv unitfile dropins state nnp load trig sched
    declare -A ORIGIN=()

    while read -r u _; do
        [[ $u == *.service && $u != *@.service ]] && ORIGIN[$u]+="enabled "
    done < <(systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager 2>/dev/null)
    while read -r u _; do
        [[ $u == *.service ]] && ORIGIN[$u]+="running "
    done < <(systemctl list-units --type=service --state=running --no-legend --no-pager --plain 2>/dev/null)

    # Timers and the units they trigger
    while read -r t state _; do
        [[ $t == *.timer && $state != masked ]] || continue
        SD_OUT=$(systemctl show -p Triggers -p UnitFileState -p ActiveState -p TimersCalendar \
                 -p TimersMonotonic -p FragmentPath -- "$t" 2>/dev/null) || continue
        trig=$(sd_prop Triggers); trig=${trig%% *}
        sched=$(sd_prop TimersCalendar)
        [[ -n $sched ]] || sched=$(sd_prop TimersMonotonic)
        sched=$(sed -E 's/^\{ *//; s/ *; *next_elapse.*$//; s/ *\}$//' <<<"$sched")
        add_task systemd-timer "$t" "$sched [$(sd_prop UnitFileState)/$(sd_prop ActiveState)]" "-" "triggers ${trig:-?}"
        check_config "$(sd_prop FragmentPath)" "unit file of $t"
        [[ -n $trig ]] && ORIGIN[$trig]+="timer:$t "
    done < <(systemctl list-unit-files --type=timer --no-legend --no-pager 2>/dev/null)

    for u in $(printf '%s\n' "${!ORIGIN[@]}" | sort); do
        origins=${ORIGIN[$u]% }
        SD_OUT=$(systemctl show -p LoadState -p User -p DynamicUser -p ExecStart -p FragmentPath \
                 -p DropInPaths -p NoNewPrivileges -- "$u" 2>/dev/null) || continue
        load=$(sd_prop LoadState)
        if [[ $load != loaded ]]; then
            [[ $origins == *timer:* ]] && add_finding MEDIUM A11 "$u" \
                "started by ${origins} but the unit is '$load': the timer is probably obsolete" \
                "Disable the timer or restore the missing unit after review"
            continue
        fi
        ident=$(sd_prop User)
        if [[ $(sd_prop DynamicUser) == yes ]]; then ident="dynamic (DynamicUser=yes)"
        elif [[ -z $ident ]]; then ident="root"
        elif [[ $ident =~ ^[0-9]+$ ]]; then ident=$(user_name "$ident"); fi
        exec=$(sd_prop ExecStart)
        argv=$(grep -oE 'argv\[\]=[^;]*' <<<"$exec" | sed -e 's/^argv\[\]=//' -e 's/ *$//' | paste -sd '|' -)
        add_task systemd-service "$u" "$origins" "$ident" "${argv:-?}"
        check_identity "$ident" "service $u"
        unitfile=$(sd_prop FragmentPath)
        [[ -n $unitfile ]] && check_config "$unitfile" "unit file of $u"
        dropins=$(sd_prop DropInPaths)
        for t in $dropins; do check_config "$t" "drop-in for $u"; done
        local a
        while IFS= read -r a; do
            [[ -n $a ]] && analyze_command "$a" "$ident" "service $u"
        done < <(tr '|' '\n' <<<"$argv")
        nnp=$(sd_prop NoNewPrivileges)
        if [[ $unitfile == /etc/systemd/system/* ]] && is_root_identity "$ident" && [[ $nnp != yes ]]; then
            add_finding INFO A12 "$u" \
                "locally defined service runs as root without NoNewPrivileges=yes" \
                "Review with 'systemd-analyze security $u' and consider User=, NoNewPrivileges= and sandboxing options"
        fi
    done

    while read -r u _; do
        [[ -n $u ]] || continue
        add_finding LOW A10 "$u" "unit is in the failed state: it may be broken or obsolete" \
            "Inspect with 'systemctl status $u' and 'journalctl -u $u'; fix or disable it after review"
    done < <(systemctl list-units --state=failed --no-legend --no-pager --plain 2>/dev/null)
}

collect_startup() {
    local f line n=0 exe home owner
    if [[ -f /etc/rc.local ]]; then
        check_config /etc/rc.local "/etc/rc.local"
        if [[ -x /etc/rc.local ]]; then
            while IFS= read -r line || [[ -n $line ]]; do
                n=$((n + 1))
                line=${line#"${line%%[![:space:]]*}"}
                [[ -z $line || $line == \#* || $line == "exit 0" ]] && continue
                add_task startup "/etc/rc.local:$n" "boot" root "$line"
                analyze_command "$line" root "/etc/rc.local line $n"
            done </etc/rc.local
        else
            add_finding INFO A15 /etc/rc.local "present but not executable, so it is not run at boot" \
                "Remove it if obsolete"
        fi
    fi
    if [[ -d /etc/init.d ]]; then
        check_config /etc/init.d "directory /etc/init.d"
        for f in /etc/init.d/*; do
            [[ -f $f ]] || continue
            SYSV_SCRIPTS+=("${f##*/}")
            check_config "$f" "init script $f"
        done
    fi
    for f in /etc/xdg/autostart/*.desktop /root/.config/autostart/*.desktop /home/*/.config/autostart/*.desktop; do
        [[ -f $f ]] || continue
        exe=$(sed -n 's/^Exec=//p' "$f" | head -n 1)
        [[ -n $exe ]] || continue
        case $f in
            /etc/xdg/*) owner="desktop-user" ;;
            /root/*)    owner="root" ;;
            *)          home=${f#/home/}; owner=${home%%/*} ;;
        esac
        if grep -qi '^Hidden=true' "$f"; then continue; fi
        add_task autostart "$f" "desktop login" "$owner" "$exe"
        [[ $f == /etc/xdg/* ]] && check_config "$f" "autostart entry $f"
        analyze_command "$exe" "$owner" "autostart entry $f"
    done
    if command -v atq >/dev/null 2>&1; then
        local id rest who
        while read -r id rest; do
            [[ -n $id ]] || continue
            who=${rest##* }
            add_task at "atq job $id" "${rest% * *}" "$who" "(inspect with: at -c $id)"
            check_identity "$who" "at job $id"
        done < <(atq 2>/dev/null)
    fi
    if [[ -s $LD_PRELOAD_FILE ]]; then
        check_config "$LD_PRELOAD_FILE" "$LD_PRELOAD_FILE"
        local lib
        while read -r lib; do
            [[ -z $lib || $lib == \#* ]] && continue
            add_finding HIGH A13 "$lib" \
                "listed in $LD_PRELOAD_FILE: loaded into every dynamically linked program, including root services (a known persistence technique)" \
                "Verify the library's origin (dpkg -S / rpm -qf, sha256sum) and why it is preloaded"
        done < <(tr -s '[:space:]' '\n' <"$LD_PRELOAD_FILE")
    fi
}

origin_of_pid() {     # pid -> unit or session that started the process
    local cg
    cg=$(awk -F: '$1=="0" {print $3; exit} $2=="name=systemd" {s=$3} END {if (s!="") print s}' \
         "/proc/$1/cgroup" 2>/dev/null | head -n 1)
    case $cg in
        */session-*.scope) printf 'login session' ;;
        *.service*) grep -oE '[^/]+\.service' <<<"$cg" | tail -n 1 ;;
        */init.scope) printf 'systemd (PID 1)' ;;
        *.scope) printf '%s' "${cg##*/}" ;;
        ""|/) printf 'unknown (no cgroup data)' ;;
        *) printf '%s' "$cg" ;;
    esac
}

collect_processes() {
    (( DO_PROCS )) || return 0
    local pid ppid uid comm exe name origin key
    declare -A ROOT_SEEN=()
    while read -r pid ppid uid comm; do
        [[ $pid == "$$" || $ppid == "$$" || $pid == 2 || $ppid == 2 ]] && continue   # self, kernel threads
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
        name=$(user_name "$uid")
        PROC_BY_USER[$name]=$(( ${PROC_BY_USER[$name]:-0} + 1 ))
        origin=$(origin_of_pid "$pid")
        if [[ $uid == 0 ]]; then
            key="$exe|$origin"
            ROOT_SEEN[$key]=$(( ${ROOT_SEEN[$key]:-0} + 1 ))
        fi
        case $exe in
            /memfd:*)
                add_finding MEDIUM A14 "pid $pid ($comm)" \
                    "running as $name from an anonymous in-memory file ($exe): used by some runtimes and sandboxes, but also by fileless malware" \
                    "Identify the parent process and its package before deciding (ps -o ppid= -p $pid; cat /proc/$pid/cmdline)" ;;
            *" (deleted)")
                add_finding MEDIUM A14 "pid $pid ($comm)" \
                    "running as $name from an executable that was deleted from disk: $exe" \
                    "Common after package upgrades until a restart; otherwise investigate (ls -l /proc/$pid/exe)" ;;
        esac
        case $exe in
            /tmp/*|/var/tmp/*|/dev/shm/*)
                add_finding HIGH A14 "pid $pid ($comm)" \
                    "running as $name from a temporary directory: $exe (started by: $origin)" \
                    "Investigate before acting: capture /proc/$pid/{cmdline,environ,cgroup} and the parent process ($ppid)" ;;
            /home/*)
                [[ $uid == 0 ]] && add_finding MEDIUM A14 "pid $pid ($comm)" \
                    "root process running from a home directory: $exe (started by: $origin)" \
                    "Confirm what started it and whether it needs root" ;;
        esac
    done < <(ps -eo pid=,ppid=,uid=,comm= 2>/dev/null)
    for key in "${!ROOT_SEEN[@]}"; do
        PROC_ROWS+=("${ROOT_SEEN[$key]}|${key%%|*}|${key#*|}")
    done
}

# ----------------------------- report ----------------------------------------
sorted_indices() {
    local i
    for i in "${!F_SEV[@]}"; do
        [[ ${F_SEV[$i]} == "$1" ]] && printf '%s\t%s\t%s\n' "${F_RULE[$i]}" "${F_ITEM[$i]}" "$i"
    done | sort -t $'\t' -k1,1 -k2,2 | cut -f3
}

write_report() {
    local i sev os type row cnt exe origin u
    os=$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release 2>/dev/null | tr -d '"'); os=${os:-unknown}
    {
        printf '%s\n' "=============================================================================="
        printf ' AUTOMATION & PRIVILEGE AUDIT REPORT  (%s %s)\n' "$PROG" "$VERSION"
        printf '%s\n' "=============================================================================="
        printf ' Host           : %s\n' "$(hostname)"
        printf ' OS / kernel    : %s / %s\n' "$os" "$(uname -r)"
        printf ' Started        : %s\n' "$START_TIME"
        printf ' Run as         : %s (uid %s)\n' "$(id -un)" "$EUID"
        printf ' systemd active : %s\n' "$( (( SYSTEMD )) && echo yes || echo 'no (systemd checks skipped)')"
        printf ' Package checks : %s\n' "$PKG_MGR"
        printf ' Mode           : audit-only (nothing was stopped, disabled or modified)\n'
        for type in cron anacron systemd-timer systemd-service startup autostart at; do
            local header=0
            for i in "${!T_TYPE[@]}"; do
                [[ ${T_TYPE[$i]} == "$type" ]] || continue
                if (( !header )); then
                    printf '%s\n' "------------------------------------------------------------------------------"
                    printf ' TASKS: %s\n\n' "$type"
                    printf ' %-34s %-28s %-14s %s\n' "SOURCE" "SCHEDULE / ORIGIN" "RUNS AS" "COMMAND"
                    header=1
                fi
                printf ' %-34s %-28s %-14s %s\n' "$(trunc "${T_SOURCE[$i]}" 34)" "$(trunc "${T_SCHED[$i]}" 28)" \
                    "$(trunc "${T_IDENT[$i]}" 14)" "$(trunc "${T_CMD[$i]}" 70)"
            done
        done
        if (( ${#SYSV_SCRIPTS[@]} )); then
            printf '%s\n' "------------------------------------------------------------------------------"
            printf ' SysV init scripts present in /etc/init.d (run only if enabled): %s\n' "${SYSV_SCRIPTS[*]}"
        fi
        if (( DO_PROCS )); then
            printf '%s\n' "------------------------------------------------------------------------------"
            printf ' RUNNING PROCESS SNAPSHOT (a process is not the same as the task that started it)\n\n'
            printf ' Processes per account:'
            for u in "${!PROC_BY_USER[@]}"; do printf ' %s=%s' "$u" "${PROC_BY_USER[$u]}"; done
            printf '\n\n %-6s %-46s %s\n' "COUNT" "ROOT-OWNED EXECUTABLE" "STARTED BY (cgroup)"
            for row in "${PROC_ROWS[@]}"; do
                IFS='|' read -r cnt exe origin <<<"$row"
                printf ' %-6s %-46s %s\n' "$cnt" "$(trunc "$exe" 46)" "$origin"
            done | sort -k2
        fi
        printf '%s\n' "------------------------------------------------------------------------------"
        printf ' FINDINGS (candidates for review, ordered by severity)\n\n'
        (( ${#F_SEV[@]} )) || printf ' No findings.\n'
        for sev in CRITICAL HIGH MEDIUM LOW INFO; do
            for i in $(sorted_indices "$sev"); do
                printf ' [%s] %s  %s\n' "$sev" "${F_RULE[$i]}" "${F_ITEM[$i]}"
                printf '        Why : %s\n' "${F_MSG[$i]}"
                printf '        Next: %s\n\n' "${F_NEXT[$i]}"
            done
        done
        printf '%s\n' "------------------------------------------------------------------------------"
        printf ' SUMMARY: %d task(s) inventoried | CRITICAL %d | HIGH %d | MEDIUM %d | LOW %d | INFO %d\n' \
            "${#T_TYPE[@]}" "${SEV_COUNT[CRITICAL]}" "${SEV_COUNT[HIGH]}" "${SEV_COUNT[MEDIUM]}" \
            "${SEV_COUNT[LOW]}" "${SEV_COUNT[INFO]}"
        printf ' Finished: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
        printf ' Note: running as root, being disabled or having an unfamiliar name does not\n'
        printf ' make a task unnecessary. Verify each finding with its owner before changing it.\n'
    } >"$REPORT" || die "cannot write report $REPORT"
}

print_machine() {
    local sev i
    for sev in CRITICAL HIGH MEDIUM LOW INFO; do
        for i in $(sorted_indices "$sev"); do
            printf '%s|%s|%s|%s\n' "$sev" "${F_RULE[$i]}" "${F_ITEM[$i]//|/!}" "${F_MSG[$i]//|/!}"
        done
    done
}

print_summary() {
    local red="" yel="" grn="" rst=""
    if [[ -t 1 ]]; then red=$'\e[31m'; yel=$'\e[33m'; grn=$'\e[32m'; rst=$'\e[0m'; fi
    printf '\n[*] Inventoried %d automated task(s); systemd checks: %s\n' "${#T_TYPE[@]}" \
        "$( (( SYSTEMD )) && echo on || echo skipped)"
    printf '[*] Findings: %sCRITICAL %d  HIGH %d%s  %sMEDIUM %d%s  LOW %d  INFO %d\n' \
        "$red" "${SEV_COUNT[CRITICAL]}" "${SEV_COUNT[HIGH]}" "$rst" "$yel" "${SEV_COUNT[MEDIUM]}" "$rst" \
        "${SEV_COUNT[LOW]}" "${SEV_COUNT[INFO]}"
    (( SEV_COUNT[CRITICAL] + SEV_COUNT[HIGH] )) || printf '[*] %sNo critical or high findings.%s\n' "$grn" "$rst"
    printf '[*] Report written to %s\n' "$REPORT"
}

# ----------------------------- main ------------------------------------------
parse_args() {
    local opt f
    while getopts ":o:PMqh" opt; do
        case $opt in
            o) REPORT=$OPTARG ;;
            P) DO_PROCS=0 ;;
            M) MACHINE=1; QUIET=1 ;;
            q) QUIET=1 ;;
            h) usage; exit 0 ;;
            :) die "option -$OPTARG needs a value (see -h)" ;;
            *) die "unknown option -$OPTARG (see -h)" ;;
        esac
    done
    shift $((OPTIND - 1))
    (( $# == 0 )) || die "unexpected argument: $1 (see -h)"
    [[ -n $REPORT ]] || REPORT="./automation-audit-report-$(hostname -s)-$(date +%Y%m%d-%H%M%S).txt"
    f=$REPORT
    [[ -L $f ]] && die "refusing to write through symbolic link: $f"
    return 0
}

main() {
    parse_args "$@"
    (( BASH_VERSINFO[0] >= 4 )) || die "bash 4 or newer is required"
    local tool
    for tool in ps stat awk sed readlink getent; do
        command -v "$tool" >/dev/null || die "required command not found: $tool"
    done
    [[ $EUID -eq 0 ]] || warn "not running as root: user crontabs and other users' processes cannot be read; results will be incomplete"
    WORKDIR=$(mktemp -d) || die "cannot create a temporary directory"
    trap 'rm -rf -- "$WORKDIR"' EXIT
    START_TIME=$(date '+%Y-%m-%d %H:%M:%S %z')

    detect_platform
    collect_cron
    collect_systemd
    collect_startup
    collect_processes
    write_report
    (( MACHINE )) && print_machine
    (( QUIET )) || print_summary
    (( SEV_COUNT[CRITICAL] + SEV_COUNT[HIGH] > 0 )) && exit 1
    exit 0
}

main "$@"

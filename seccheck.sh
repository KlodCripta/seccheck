#!/usr/bin/env bash
# SecCheck 2.0 — Klod Cripta — MIT
# Standalone, read-only security assistant for Arch Linux and derivatives.
# Sourcing this file defines functions only: no traps, privilege changes or I/O.

SC_VERSION=2.0.0
SC_RULESET=2026.09.27
SC_RULESET_DATE=2026-09-27
SC_ALL_MODULES='rkhunter lynis integrity aur aur-health'

# ---- Evidence model ---------------------------------------------------------
sc_text() {
    local value=${1-}
    value=${value//$'\n'/ }
    printf '%s' "$value" | LC_ALL=C tr '\000-\037\177' '?'
}

sc_reset() {
    SC_LANG=${SC_LANG:-en}
    declare -ga SC_SELECTED=()
    declare -ga SC_F_MODULE=() SC_F_KIND=() SC_F_PRIORITY=() SC_F_CONFIDENCE=()
    declare -ga SC_F_OBJECT=() SC_F_KEY=() SC_F_EVIDENCE=()
    declare -ga SC_D_MODULE=() SC_D_KEY=() SC_D_EVIDENCE=()
    declare -gA SC_MODULE_STATUS=() SC_MODULE_REASON=() SC_MODULE_RC=() SC_MODULE_VERSION=()
    declare -ga SC_SCOPE=()
    local module
    for module in $SC_ALL_MODULES; do
        SC_MODULE_STATUS[$module]=not-run
        SC_MODULE_REASON[$module]=''
        SC_MODULE_RC[$module]=''
        SC_MODULE_VERSION[$module]=''
    done
    for module in ${1:-$SC_ALL_MODULES}; do
        case $module in rkhunter|lynis|integrity|aur|aur-health) SC_SELECTED+=("$module");; *) return 2;; esac
    done
    SC_INCOMPLETE=1 SC_COMPLETED=0 SC_URGENT=0 SC_REVIEW=0 SC_SUGGESTIONS=0
    SC_ASSESSMENT=unknown
    SC_HEALTH_NOTE=''
}

sc_module_set() {
    local module=$1 status=$2 reason=${3-}
    case $module in rkhunter|lynis|integrity|aur|aur-health) ;; *) return 2;; esac
    case $status in not-run|running|completed|partial|failed|skipped) ;; *) return 2;; esac
    SC_MODULE_STATUS[$module]=$status
    SC_MODULE_REASON[$module]=$reason
}

sc_add_diagnostic() {
    local module=$1 key=$2 evidence i
    evidence=$(sc_text "${3-}")
    for ((i=0; i<${#SC_D_MODULE[@]}; i++)); do
        [[ ${SC_D_MODULE[i]} == "$module" && ${SC_D_KEY[i]} == "$key" &&
           ${SC_D_EVIDENCE[i]} == "$evidence" ]] && return 0
    done
    SC_D_MODULE+=("$module") SC_D_KEY+=("$key") SC_D_EVIDENCE+=("$evidence")
}

sc_add_finding() {
    local module=$1 kind=$2 priority=$3 confidence=$4 object=$5 key=$6 evidence=$7 i
    case $module in rkhunter|lynis|integrity|aur|aur-health) ;; *) return 2;; esac
    case $priority in urgent|review|suggestion) ;; *) return 2;; esac
    object=$(sc_text "$object")
    evidence=$(sc_text "$evidence")
    # Compare array elements: do not evaluate untrusted associative subscripts.
    for ((i=0; i<${#SC_F_MODULE[@]}; i++)); do
        if [[ ${SC_F_MODULE[i]} == "$module" && ${SC_F_KEY[i]} == "$key" &&
              ${SC_F_OBJECT[i]} == "$object" && ${SC_F_EVIDENCE[i]} == "$evidence" ]]; then
            return 0
        fi
    done
    SC_F_MODULE+=("$module") SC_F_KIND+=("$kind") SC_F_PRIORITY+=("$priority")
    SC_F_CONFIDENCE+=("$confidence") SC_F_OBJECT+=("$object")
    SC_F_KEY+=("$key") SC_F_EVIDENCE+=("$evidence")
}

sc_assess() {
    local module priority
    SC_COMPLETED=0 SC_INCOMPLETE=0 SC_URGENT=0 SC_REVIEW=0 SC_SUGGESTIONS=0
    for module in "${SC_SELECTED[@]}"; do
        if [[ ${SC_MODULE_STATUS[$module]} == completed ]]; then
            ((SC_COMPLETED+=1))
        else
            SC_INCOMPLETE=1
        fi
    done
    ((${#SC_SELECTED[@]})) || SC_INCOMPLETE=1
    for priority in "${SC_F_PRIORITY[@]}"; do
        case $priority in urgent) ((SC_URGENT+=1));; review) ((SC_REVIEW+=1));;
            suggestion) ((SC_SUGGESTIONS+=1));; esac
    done
    if ((SC_URGENT)); then SC_ASSESSMENT=urgent
    elif ((SC_REVIEW)); then SC_ASSESSMENT=review
    elif ((SC_SUGGESTIONS)); then SC_ASSESSMENT=advice
    elif ((SC_INCOMPLETE)); then SC_ASSESSMENT=unknown
    else SC_ASSESSMENT=clear
    fi
}

# ---- Scanner boundaries: fixed locale, private output, bounded execution -----
sc_capture() {
    local output=$1 errors=$2 seconds=$3
    shift 3
    LC_ALL=C timeout --kill-after=5s "${seconds}s" "$@" <&- >"$output" 2>"$errors"
}

sc_version() {
    local value
    value=$(LC_ALL=C timeout 5 "$@" 2>/dev/null) || true
    sc_text "${value%%$'\n'*}"
}

sc_parse_rkhunter() {
    local line lower key priority object
    local -a words
    SC_PARSE_UNKNOWN=0
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line#\[??:??:??\] }
        lower=${line,,}
        # Examine findings before descriptive prefixes; [ Warning ] is significant.
        if [[ $lower == *warning:* || $lower == *'[ warning ]'* || $lower == *'[warning]'* ||
              $lower == *'[ infected ]'* || $lower == *'infected file'* ]]; then
            key=rkh_warning priority=review object=''
            case $lower in
                *'possible rootkit'*|*'rootkit found'*|*'infected file'*|*'[ infected ]'*)
                    key=rkh_signature; priority=urgent;;
                *'properties have changed'*|*'hash value'*|*'hash changed'*) key=rkh_properties;;
            esac
            # A display hint, never an executable argument or proof of file identity.
            if [[ $line =~ (/[^[:space:]]+) ]]; then object=${BASH_REMATCH[1]}; fi
            sc_add_finding rkhunter suspicious "$priority" unconfirmed "$object" "$key" "$line"
        fi
        if [[ $lower == *'test skipped'* || $lower == *'skipped due to'* || $lower == *'[ skipped ]'* ]]; then
            SC_PARSE_UNKNOWN=1
            read -r -a words <<< "$line"
            sc_add_diagnostic rkhunter rkh_skipped "${words[*]}"
        fi
    done < "$1"
}

sc_run_rkhunter() {
    if ! command -v rkhunter >/dev/null; then sc_module_set rkhunter skipped missing_rkhunter; return 0; fi
    sc_module_set rkhunter running ''
    SC_MODULE_VERSION[rkhunter]=$(sc_version rkhunter --version)
    local out="$SC_RUN_DIR/rkhunter.stdout" err="$SC_RUN_DIR/rkhunter.stderr"
    local raw="$SC_RUN_DIR/rkhunter.log" parsed rc line errors=0 unknown=0 before=${#SC_F_MODULE[@]}
    sc_capture "$out" "$err" 1200 rkhunter --check --nocolors --sk --lang en --logfile "$raw"
    rc=$?; SC_MODULE_RC[rkhunter]=$rc
    # Display execution diagnostics before the potentially long skipped-test list.
    while IFS= read -r line || [[ -n $line ]]; do
        case $line in
            '') continue;;
            'egrep: warning: egrep is obsolescent; using grep -E')
                # This exact notice states the command was forwarded to grep -E.
                # Other warnings, including regex warnings, still limit coverage.
                sc_add_diagnostic rkhunter rkh_legacy_grep "$line";;
            'grep: warning: stray '\\' before '*)
                errors=1; sc_add_diagnostic rkhunter rkh_regex "$line";;
            *) errors=1; sc_add_diagnostic rkhunter scanner_error "$line";;
        esac
    done < "$err"
    parsed=$out
    [[ -s $raw ]] && parsed=$raw
    sc_parse_rkhunter "$parsed"
    unknown=$SC_PARSE_UNKNOWN
    # Both streams can contain unique evidence. Neither may erase uncertainty.
    if [[ $parsed != "$out" ]]; then
        sc_parse_rkhunter "$out"
        SC_PARSE_UNKNOWN=$((SC_PARSE_UNKNOWN || unknown))
    fi
    if ((rc <= 1)) && grep -Eq 'System checks summary|Info: End date is' "$parsed" "$out"; then
        if ((rc == 1 && ${#SC_F_MODULE[@]} == before)); then
            errors=1; sc_add_diagnostic rkhunter rkh_unparsed 'exit=1; rkhunter.log / rkhunter.stdout'
        fi
        if ((errors || SC_PARSE_UNKNOWN)); then
            sc_module_set rkhunter partial rkh_limited
        else sc_module_set rkhunter completed ''; fi
    elif [[ -s $out || -s $raw ]]; then sc_module_set rkhunter partial unfinished
    else sc_module_set rkhunter failed command_failed
    fi
}

sc_parse_lynis() {
    local line value id description details solution _remainder priority key
    SC_PARSE_UNKNOWN=0
    while IFS= read -r line || [[ -n $line ]]; do
        case $line in
            'warning[]='*) priority=review; key=lynis_warning;;
            'suggestion[]='*) priority=suggestion; key=lynis_suggestion;;
            *) continue;;
        esac
        value=${line#*=}
        IFS='|' read -r id description details solution _remainder <<< "$value"
        if [[ -z $id || -z $description || $value != *'|'* ]]; then SC_PARSE_UNKNOWN=1; continue; fi
        sc_add_finding lynis hardening "$priority" observation "$id" "$key" \
            "$description${details:+ | $details}${solution:+ | $solution}"
    done < "$1"
}

sc_run_lynis() {
    if ! command -v lynis >/dev/null; then sc_module_set lynis skipped missing_lynis; return 0; fi
    sc_module_set lynis running ''
    SC_MODULE_VERSION[lynis]=$(sc_version lynis --version)
    local out="$SC_RUN_DIR/lynis.stdout" err="$SC_RUN_DIR/lynis.stderr"
    local report="$SC_RUN_DIR/lynis-report.dat" rc
    sc_capture "$out" "$err" 1200 lynis audit system --quick --no-colors --quiet \
        --logfile "$SC_RUN_DIR/lynis.log" --report-file "$report"
    rc=$?; SC_MODULE_RC[lynis]=$rc
    if [[ ! -s $report ]]; then sc_module_set lynis failed no_report; return 0; fi
    sc_parse_lynis "$report"
    if ((rc == 0 || rc == 78)) && ((SC_PARSE_UNKNOWN == 0)) &&
        grep -q '^lynis_version=' "$report" && grep -q '^report_datetime_start=' "$report" &&
        grep -q '^report_datetime_end=.' "$report" && [[ ! -s $err ]]; then
        sc_module_set lynis completed ''
    else sc_module_set lynis partial unfinished
    fi
}

sc_parse_integrity() {
    local line lower object detail key mode=${2:-pacman}
    local re_pacman='^(warning: |backup file: )?[^:]+: (/.+) \((.*)\)$'
    local re_paccheck="^[^:]+: '(.+)' (.*)$"
    SC_PARSE_SEEN=0 SC_PARSE_UNKNOWN=0 SC_PARSE_ERRORS=0
    while IFS= read -r line || [[ -n $line ]]; do
        [[ -z $line ]] && continue
        lower=${line,,}; object='' detail=''
        if [[ $lower == *'error:'* || $lower == *'read error'* || $lower == *'mtree data not available'* ||
              $lower == *'error reading mtree'* || $lower == *'permission denied'* ]]; then
            SC_PARSE_ERRORS=1
        fi
        if [[ $line =~ $re_pacman ]]; then
            object=${BASH_REMATCH[2]}; detail=${BASH_REMATCH[3]}
        elif [[ $line =~ $re_paccheck ]]; then
            object=${BASH_REMATCH[1]}; detail=${BASH_REMATCH[2]}
        elif [[ $line =~ ^[^:]+:\ [0-9]+\ total\ files?,\ [0-9]+\ altered\ files?$ ||
                $line == *': all files match mtree sha256sums' || $line == *': all files present and unmodified' ]]; then
            ((SC_PARSE_SEEN+=1)); continue
        else
            SC_PARSE_UNKNOWN=1; continue
        fi
        ((SC_PARSE_SEEN+=1))
        key=integrity_metadata
        case ${detail,,} in
            *'missing file'*|*'no such file'*) key=integrity_missing;;
            *'sha256sum mismatch'*) key=integrity_content;;
        esac
        sc_add_finding integrity integrity review observation "$object" "$key" "$mode: $line"
    done < "$1"
}

sc_run_integrity() {
    if ! command -v pacman >/dev/null; then sc_module_set integrity skipped missing_pacman; return 0; fi
    sc_module_set integrity running ''
    SC_MODULE_VERSION[integrity]=$(sc_version pacman --version)
    local rc partial=0 out="$SC_RUN_DIR/pacman.stdout" err="$SC_RUN_DIR/pacman.stderr"
    local before=${#SC_F_MODULE[@]} seen unknown errors
    sc_capture "$out" "$err" 1200 pacman -Qkk
    rc=$?; SC_MODULE_RC[integrity]="pacman=$rc"
    cat -- "$out" "$err" > "$SC_RUN_DIR/pacman-combined.txt"
    sc_parse_integrity "$SC_RUN_DIR/pacman-combined.txt" pacman
    seen=$SC_PARSE_SEEN unknown=$SC_PARSE_UNKNOWN errors=$SC_PARSE_ERRORS
    if ((rc > 1 || seen == 0 || unknown || errors || (rc == 1 && ${#SC_F_MODULE[@]} == before))); then partial=1; fi
    if ! command -v paccheck >/dev/null; then
        sc_module_set integrity partial missing_paccheck
        return 0
    fi
    out="$SC_RUN_DIR/paccheck.stdout" err="$SC_RUN_DIR/paccheck.stderr"
    before=${#SC_F_MODULE[@]}
    sc_capture "$out" "$err" 1800 paccheck --sha256sum --require-mtree --backup
    rc=$?; SC_MODULE_RC[integrity]+=" paccheck=$rc"
    cat -- "$out" "$err" > "$SC_RUN_DIR/paccheck-combined.txt"
    sc_parse_integrity "$SC_RUN_DIR/paccheck-combined.txt" paccheck
    if ((rc > 1 || SC_PARSE_SEEN == 0 || SC_PARSE_UNKNOWN || SC_PARSE_ERRORS ||
         (rc == 1 && ${#SC_F_MODULE[@]} == before))); then partial=1; fi
    if ((partial)); then sc_module_set integrity partial check_details
    else sc_module_set integrity completed ''; fi
    SC_SCOPE+=("integrity: pacman metadata + paccheck SHA-256 against local package MTREE; includes backup files; excludes NoExtract/NoUpgrade")
}

# ---- Atomic Arch: static, bounded inspection, no code from scanned files ------
sc_aur_init() {
    SC_AUR_PARTIAL=0 SC_AUR_COUNT=0 SC_AUR_ROOT_COUNT=0
    SC_AUR_MAX_FILES=20000 SC_AUR_TEXT_LIMIT=2097152 SC_AUR_SECONDS=180
    SC_AUR_STARTED=$SECONDS
    SC_AUR_PACKAGE_RE='(^|[^[:alnum:]_.-])(atomic-lockfile|js-digest|lockfile-js)([^[:alnum:]_.-]|$)'
    declare -ga SC_AUR_HOMES=()
}

sc_known_hash() {
    case ${1,,} in
        6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b) return 0;;
        *) return 1;;
    esac
}

sc_check_known_file() {
    local file=$1 size digest
    [[ -e $file ]] || return 0
    if [[ -L $file || ! -f $file || ! -r $file ]]; then SC_AUR_PARTIAL=1; return 0; fi
    size=$(stat -c '%s' -- "$file" 2>/dev/null) || { SC_AUR_PARTIAL=1; return 0; }
    if ((size > 67108864)); then SC_AUR_PARTIAL=1; return 0; fi
    digest=$(timeout --kill-after=1s 4s sha256sum -- "$file" 2>/dev/null) || { SC_AUR_PARTIAL=1; return 0; }
    digest=${digest%% *}
    if sc_known_hash "$digest"; then
        sc_add_finding aur suspicious urgent match "$file" aur_hash "SHA256=$digest; Atomic Arch/deps"
    fi
}

sc_inspect_aur_file() {
    local file=$1 context=${2:-cache} name=${1##*/} data size token executable='' line home candidate=0
    if [[ -L $file || ! -f $file || ! -r $file ]]; then SC_AUR_PARTIAL=1; return 0; fi
    case $name in deps|install-deps|linux) sc_check_known_file "$file";; esac
    if [[ $context == executable ]]; then sc_check_known_file "$file"; return 0; fi
    case $name in
        PKGBUILD|install|*.install|package.json|package-lock.json|npm-shrinkwrap.json|bun.lock|*.service|*.desktop|*.log) ;;
        *) [[ $file == */.npm/_cacache/index-v5/* || $context == startup ]] || return 0;;
    esac
    size=$(stat -c '%s' -- "$file" 2>/dev/null) || { SC_AUR_PARTIAL=1; return 0; }
    if ((size > SC_AUR_TEXT_LIMIT)); then SC_AUR_PARTIAL=1; fi
    data=$(set -o pipefail; timeout --kill-after=1s 3s head -c "$SC_AUR_TEXT_LIMIT" -- "$file" 2>/dev/null | tr -d '\000') || {
        SC_AUR_PARTIAL=1; return 0;
    }
    if [[ $data =~ $SC_AUR_PACKAGE_RE ]]; then
        token=${BASH_REMATCH[2]}
        # Only the token and path are retained, not potentially secret log contents.
        sc_add_finding aur exposure review observation "$file" aur_reference "$token; scope=$context"
    fi
    if [[ $name == *.service ]]; then
        while IFS= read -r line; do
            if [[ $line =~ ^[[:space:]]*ExecStart[[:space:]]*=[[:space:]]*[-:@+!]*\"([^\"]+)\" ]]; then
                executable=${BASH_REMATCH[1]}; break
            elif [[ $line =~ ^[[:space:]]*ExecStart[[:space:]]*=[[:space:]]*[-:@+!]*(/[^[:space:]]+) ]]; then
                executable=${BASH_REMATCH[1]}; break
            fi
        done <<< "$data"
        [[ $executable == /var/lib/* || $executable == /home/* || $executable == /root/* ]] && candidate=1
        for home in "${SC_AUR_HOMES[@]}"; do [[ $executable == "$home/"* ]] && candidate=1; done
        if ((candidate)); then
            if grep -Eq '^Restart[[:space:]]*=[[:space:]]*always[[:space:]]*$' <<< "$data" &&
                grep -Eq '^RestartSec[[:space:]]*=[[:space:]]*30s?[[:space:]]*$' <<< "$data"; then
                sc_add_finding aur suspicious review unconfirmed "$file" aur_service "ExecStart=$executable; Restart=always; RestartSec=30"
            fi
            sc_check_known_file "$executable"
        fi
    fi
}

sc_collect_homes() {
    local name _password uid _gid _gecos home _shell existing duplicate
    while IFS=: read -r name _password uid _gid _gecos home _shell; do
        [[ $uid =~ ^[0-9]+$ && $home == /* ]] || continue
        ((uid == 0 || (uid >= 1000 && uid < 65534))) || continue
        duplicate=0
        for existing in "${SC_AUR_HOMES[@]}"; do [[ $existing == "$home" ]] && duplicate=1; done
        ((duplicate)) || SC_AUR_HOMES+=("$home")
    done < "$1"
}

sc_scan_aur_root() {
    local root=$1 context=$2 file rc index errors depth
    [[ -e $root ]] || return 0
    if ((SC_AUR_COUNT >= SC_AUR_MAX_FILES || SECONDS - SC_AUR_STARTED >= SC_AUR_SECONDS)); then
        SC_AUR_PARTIAL=1; SC_SCOPE+=("budget exhausted: $(sc_text "$root")"); return 0
    fi
    if [[ -L $root || ! -d $root || ! -r $root || ! -x $root ]]; then
        SC_AUR_PARTIAL=1; SC_SCOPE+=("unreadable/skipped: $(sc_text "$root")"); return 0
    fi
    ((SC_AUR_ROOT_COUNT+=1))
    index="$SC_RUN_DIR/aur-files.$SC_AUR_ROOT_COUNT"
    errors="$SC_RUN_DIR/aur-find.$SC_AUR_ROOT_COUNT.stderr"
    # NUL delimiters preserve spaces/newlines. Symlinks are never followed.
    (set -o pipefail; timeout --kill-after=2s 15s find -P "$root" -maxdepth 12 -type f -print0 2>"$errors" |
        head -z -n "$((SC_AUR_MAX_FILES+1))") > "$index"
    rc=$?
    if ((rc)) || [[ -s $errors ]]; then SC_AUR_PARTIAL=1; fi
    # find succeeds when maxdepth prunes a directory. Record that bound explicitly.
    depth="$SC_RUN_DIR/aur-depth.$SC_AUR_ROOT_COUNT"
    timeout --kill-after=2s 8s find -P "$root" -mindepth 12 -maxdepth 12 -type d -print -quit > "$depth" 2>> "$errors"
    rc=$?
    if ((rc)) || [[ -s $errors || -s $depth ]]; then
        SC_AUR_PARTIAL=1
        SC_SCOPE+=("depth-bound/unreadable traversal: $(sc_text "$root")")
    fi
    SC_SCOPE+=("$context: $(sc_text "$root")")
    while IFS= read -r -d '' file; do
        if ((SC_AUR_COUNT >= SC_AUR_MAX_FILES || SECONDS - SC_AUR_STARTED >= SC_AUR_SECONDS)); then
            SC_AUR_PARTIAL=1; break
        fi
        ((SC_AUR_COUNT+=1))
        sc_inspect_aur_file "$file" "$context"
    done < "$index"
}

sc_parse_aur_history() {
    local line data size
    [[ -f $1 && -r $1 && ! -L $1 ]] || { SC_AUR_PARTIAL=1; return 0; }
    size=$(stat -c '%s' -- "$1" 2>/dev/null) || { SC_AUR_PARTIAL=1; return 0; }
    ((size > 16777216)) && SC_AUR_PARTIAL=1
    data=$(timeout --kill-after=1s 4s head -c 16777216 -- "$1") || { SC_AUR_PARTIAL=1; return 0; }
    while IFS= read -r line; do
        if [[ $line =~ ^\[2026-06-(11|12)T[^]]+\].*\[ALPM\]\ (installed|upgraded)\ (gnome-randr-rust|workbench|rtspeccy-git|exodus-wallet-bin)\  ]]; then
            sc_add_finding aur exposure review observation "${BASH_REMATCH[3]}" aur_history "$line"
        fi
    done <<< "$data"
}

sc_run_aur() {
    sc_module_set aur running ''
    sc_aur_init
    local rc root home target
    SC_MODULE_VERSION[aur]="Atomic Arch $SC_RULESET"
    if command -v pacman >/dev/null; then
        sc_capture "$SC_RUN_DIR/foreign-packages.txt" "$SC_RUN_DIR/foreign-packages.stderr" 30 pacman -Qm
        rc=$?
        ((rc <= 1)) && [[ ! -s $SC_RUN_DIR/foreign-packages.stderr ]] || SC_AUR_PARTIAL=1
    else SC_AUR_PARTIAL=1
    fi
    sc_parse_aur_history /var/log/pacman.log
    for root in /var/lib/pacman/local /usr/lib/node_modules /usr/local/lib/node_modules /tmp /var/tmp; do
        sc_scan_aur_root "$root" cache
    done
    for root in /etc/systemd/system /etc/xdg/autostart /etc/cron.d /var/spool/cron; do
        sc_scan_aur_root "$root" startup
    done
    sc_collect_homes /etc/passwd
    for home in "${SC_AUR_HOMES[@]}"; do
        for target in .cache/yay .cache/paru .cache/pikaur .cache/pacaur .cache/aura .npm .bun/install/cache .bun/install/global; do
            sc_scan_aur_root "$home/$target" cache
        done
        for target in .config/systemd/user .config/autostart; do sc_scan_aur_root "$home/$target" startup; done
        sc_scan_aur_root "$home/.local/bin" executable
    done
    for root in "${SC_EXTRA_AUR_PATHS[@]-}"; do [[ -n $root ]] && sc_scan_aur_root "$root" cache; done
    for target in hidden_pids hidden_names hidden_inodes; do
        if [[ -e /sys/fs/bpf/$target ]]; then
            sc_add_finding aur suspicious review unconfirmed "/sys/fs/bpf/$target" aur_bpf "$target"
        fi
    done
    SC_SCOPE+=("AUR rules=$SC_RULESET; files=$SC_AUR_COUNT; limit=$SC_AUR_MAX_FILES; max-depth=12; max-text=$SC_AUR_TEXT_LIMIT; time-budget=${SC_AUR_SECONDS}s")
    SC_SCOPE+=("AUR exclusions: compressed archives, arbitrary project/custom-cache paths (use --aur-path), removed history, live kernel/memory, remote/encrypted/unmounted homes; no execution can be ruled out by an absent artifact")
    if ((SC_AUR_PARTIAL)); then sc_module_set aur partial bounded_scope
    else sc_module_set aur completed ''; fi
    return 0
}

# ---- Online AUR project health: optional Python stdlib + curl ---------------
sc_run_aur_health() {
    SC_HEALTH_NOTE=''
    if [[ ${SC_OFFLINE:-0} == 1 ]]; then sc_module_set aur-health skipped offline; return 0; fi
    local tool rc priority key object evidence state note
    for tool in python3 curl pacman vercmp; do
        if ! command -v "$tool" >/dev/null; then sc_module_set aur-health skipped missing_health_tools; return 0; fi
    done
    sc_module_set aur-health running ''
    SC_MODULE_VERSION[aur-health]='AUR RPC v5 + public package page'
    # This path is internal; the CLI deliberately offers no arbitrary root-state path.
    local state_dir=${SC_STATE_DIR:-/var/lib/seccheck}
    if [[ -L $state_dir ]]; then sc_module_set aur-health failed health_state; return 0; fi
    if [[ ! -e $state_dir ]]; then (umask 077; mkdir -- "$state_dir") || { sc_module_set aur-health failed health_state; return 0; }; fi
    if [[ ! -d $state_dir || $(stat -c '%u' -- "$state_dir") != "$EUID" ]]; then
        sc_module_set aur-health failed health_state; return 0
    fi
    chmod 700 -- "$state_dir" || { sc_module_set aur-health failed health_state; return 0; }
    timeout --kill-after=5s 300s python3 -I - "$SC_RUN_DIR" "$state_dir" > "$SC_RUN_DIR/aur-health.stdout" 2> "$SC_RUN_DIR/aur-health.stderr" <<'PY'
import fcntl
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse
from html.parser import HTMLParser

run, state = map(pathlib.Path, sys.argv[1:])
os.umask(0o077)
started = time.monotonic()
now = int(time.time())
partial = False
findings = []
notes = []
diagnostics = []
baseline_note = 'health_not_updated'
package_re = re.compile(r'[A-Za-z0-9@_+.-]{1,255}\Z')
user_re = re.compile(r'[A-Za-z0-9_.+@-]{1,255}\Z')

def issue(key, name, evidence, priority='review'):
    findings.append((priority, key, name, evidence))

def load_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8388608:
        raise ValueError('invalid JSON file')
    return json.loads(path.read_text())

def text(value):
    return ''.join(c if c.isprintable() else '?' for c in str(value))

class RequestError(ValueError):
    pass

def fetch(url, stem):
    if time.monotonic() - started > 260:
        raise ValueError('request budget exhausted')
    (run / (stem + '.request.txt')).write_text(url + '\n')
    try:
        result = subprocess.run(['curl', '--disable', '--proto', '=https', '--tlsv1.2',
            '--fail', '--silent', '--show-error', '--connect-timeout', '5', '--max-time', '20',
            '--max-filesize', '2097152', '--header', 'Accept-Language: en-US',
            '--user-agent', 'SecCheck/2.0 (AUR maintenance check)', url],
            capture_output=True, timeout=23, env=dict(os.environ, LC_ALL='C'))
        output, errors, code = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as error:
        output, errors, code = error.stdout or b'', error.stderr or b'', 28
        errors += b'\nSecCheck: curl exceeded the 23-second process deadline\n'
    (run / (stem + '.raw')).write_bytes(output[:2097152])
    (run / (stem + '.stderr')).write_bytes(errors[:65536])
    if code or len(output) > 2097152:
        key = {5: 'health_dns', 6: 'health_dns', 7: 'health_connection', 22: 'health_http',
               28: 'health_timeout', 35: 'health_tls', 60: 'health_tls'}.get(code, 'health_fetch')
        detail = 'curl=' + str(code) + '; URL=' + url + '; log=' + stem + '.stderr; ' + \
                 text(errors.decode('utf-8', errors='replace').strip())[:500]
        if len(output) > 2097152: detail += '; response exceeds 2 MiB'
        diagnostics.append((key, detail))
        raise RequestError(detail)
    return output.decode('utf-8')

class MaintainerRow(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_row = self.in_cell = False
        self.parts = []
        self.rows = 0
        self.cells = self.closed_cells = self.closed_rows = 0
        self.malformed = False
    def handle_starttag(self, tag, attrs):
        if tag == 'tr' and 'pkgmaint' in dict(attrs).get('class', '').split():
            if self.in_row: self.malformed = True
            self.in_row = True
            self.rows += 1
        elif tag == 'td' and self.in_row:
            if self.in_cell: self.malformed = True
            self.in_cell = True
            self.cells += 1
    def handle_endtag(self, tag):
        if tag == 'tr':
            if self.in_row:
                if self.in_cell: self.malformed = True
                self.closed_rows += 1
            self.in_row = self.in_cell = False
        elif tag == 'td' and self.in_row:
            if not self.in_cell: self.malformed = True
            else: self.closed_cells += 1
            self.in_cell = False
    def handle_data(self, data):
        if self.in_cell: self.parts.append(data)

def co_from_page(html, maintainer):
    parser = MaintainerRow()
    parser.feed(html)
    parser.close()
    value = ' '.join(''.join(parser.parts).split())
    match = re.fullmatch(r'([^\s()]+)(?:\s*\(([^()]*)\))?', value)
    if parser.malformed or parser.rows != 1 or parser.closed_rows != 1 or parser.cells != 1 or \
            parser.closed_cells != 1 or parser.in_row or parser.in_cell or not match or match[1] != (maintainer or 'None'):
        raise ValueError('maintainer page unavailable or disagrees with RPC')
    result = [] if not match[2] else [x.strip() for x in match[2].split(',')]
    if not all(user_re.fullmatch(x) for x in result):
        raise ValueError('unknown co-maintainer format')
    return sorted(set(result))

def validate_package(pkg):
    for key in ('Name', 'PackageBase', 'Version', 'Maintainer', 'LastModified', 'OutOfDate'):
        if key not in pkg: raise ValueError('missing metadata field: ' + key)
    for key in ('Name', 'PackageBase'):
        if not isinstance(pkg[key], str) or not package_re.fullmatch(pkg[key]):
            raise ValueError('invalid package identity')
    if not isinstance(pkg['Version'], str) or not re.fullmatch(r'[^\s\x00-\x1f\x7f]{1,255}', pkg['Version']):
        raise ValueError('invalid version')
    if pkg['Maintainer'] is not None and (not isinstance(pkg['Maintainer'], str) or not user_re.fullmatch(pkg['Maintainer'])):
        raise ValueError('invalid maintainer')
    if type(pkg['LastModified']) is not int or not 0 < pkg['LastModified'] <= now + 86400:
        raise ValueError('invalid last-modified timestamp')
    if pkg['OutOfDate'] is not None and (type(pkg['OutOfDate']) is not int or not 0 < pkg['OutOfDate'] <= now + 86400):
        raise ValueError('invalid out-of-date timestamp')
    if 'CoMaintainers' in pkg and (not isinstance(pkg['CoMaintainers'], list) or
            not all(isinstance(x, str) and user_re.fullmatch(x) for x in pkg['CoMaintainers'])):
        raise ValueError('invalid co-maintainers')

def execute():
    global partial, baseline_note
    lock = os.open(state / 'aur-health.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise ValueError('another AUR health scan is updating the baseline')
    baseline_path = state / 'aur-maintainers.json'
    baseline = {'schema': 1, 'observed_at': 0, 'packages': {}}
    first = not baseline_path.exists()
    if baseline_path.is_symlink(): raise ValueError('unsafe baseline')
    if first: baseline_note = 'health_no_baseline'
    if not first:
        baseline = load_json(baseline_path)
        if baseline.get('schema') != 1 or not isinstance(baseline.get('packages'), dict):
            raise ValueError('invalid baseline schema')
        for name, previous in baseline['packages'].items():
            if not package_re.fullmatch(name) or not isinstance(previous, dict):
                raise ValueError('invalid baseline package')
            if previous.get('maintainer') is not None and not user_re.fullmatch(previous['maintainer']):
                raise ValueError('invalid baseline maintainer')
            if not isinstance(previous.get('co_maintainers'), list) or not all(
                    isinstance(x, str) and user_re.fullmatch(x) for x in previous['co_maintainers']):
                raise ValueError('invalid baseline co-maintainers')
        baseline_note = 'health_preserved'
    result = subprocess.run(['pacman', '-Qm'], capture_output=True, text=True, timeout=30,
                            env=dict(os.environ, LC_ALL='C'))
    (run / 'aur-health-inventory.txt').write_text(result.stdout)
    if result.returncode not in (0, 1) or result.stderr or (result.returncode == 1 and result.stdout.strip()):
        raise ValueError('foreign package inventory failed')
    installed = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 2 or not package_re.fullmatch(fields[0]):
            raise ValueError('unknown inventory format')
        installed[fields[0]] = fields[1]
    names = sorted(installed)
    if len(names) > 2000:
        partial = True
        notes.append('inventory exceeds 2000-package limit')
    current = dict(baseline['packages'])
    observed = {}
    page_cache = {}
    page_serial = 0
    for start in range(0, min(len(names), 2000), 50):
        batch = names[start:start+50]
        try:
            data = json.loads(fetch('https://aur.archlinux.org/rpc/v5/info?' +
                urllib.parse.urlencode([('arg[]', name) for name in batch]), 'aur-rpc.' + str(start//50)))
            if not isinstance(data, dict) or data.get('version') != 5 or data.get('type') != 'multiinfo' or \
                    not isinstance(data.get('results'), list) or data.get('resultcount') != len(data['results']):
                raise ValueError('invalid AUR RPC response')
            packages = {}
            for pkg in data['results']:
                validate_package(pkg)
                if pkg['Name'] not in batch or pkg['Name'] in packages:
                    raise ValueError('unexpected or duplicate package identity')
                packages[pkg['Name']] = pkg
        except (ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
            partial = True; notes.append(text(error))
            if not isinstance(error, RequestError):
                diagnostics.append(('health_data_error', 'AUR RPC: ' + text(error)))
            continue
        for name in batch:
            if name not in packages:
                issue('health_removed' if name in baseline['packages'] else 'health_unlisted', name,
                      'No exact match in a valid AUR RPC response',
                      'review' if name in baseline['packages'] else 'suggestion')
                continue
            pkg = packages[name]
            maintainer = pkg['Maintainer']
            if maintainer is None: issue('health_orphan', name, 'AUR Maintainer=null')
            if pkg['OutOfDate'] is not None: issue('health_flagged', name, 'AUR OutOfDate=' + str(pkg['OutOfDate']))
            days = max(0, (now - pkg['LastModified']) // 86400)
            if days >= 365: issue('health_inactive', name, 'LastModified=' + str(pkg['LastModified']) + '; days=' + str(days), 'suggestion')
            compared = subprocess.run(['vercmp', installed[name], pkg['Version']], capture_output=True, text=True, timeout=5)
            if compared.returncode or compared.stdout.strip() not in ('-1', '0', '1'):
                partial = True; notes.append('version comparison failed: ' + name)
            elif compared.stdout.strip() == '-1':
                issue('health_upgrade', name, 'installed=' + installed[name] + '; AUR=' + pkg['Version'], 'suggestion')
            previous = baseline['packages'].get(name)
            if previous and previous['maintainer'] != maintainer:
                issue('health_maintainer', name, str(previous['maintainer']) + ' -> ' + str(maintainer) +
                      '; previous observation=' + str(previous.get('seen_at', baseline.get('observed_at', '?'))))
            try:
                if 'CoMaintainers' in pkg:
                    co = sorted(set(pkg['CoMaintainers']))
                else:
                    if pkg['PackageBase'] not in page_cache:
                        # Count attempts, not successful cache entries: a failed
                        # request must never have its logs overwritten by the next.
                        stem = 'aur-page.' + str(page_serial)
                        page_serial += 1
                        page_cache[pkg['PackageBase']] = fetch('https://aur.archlinux.org/packages/' +
                            urllib.parse.quote(name, safe=''), stem)
                    co = co_from_page(page_cache[pkg['PackageBase']], maintainer)
                item = dict(base=pkg['PackageBase'], maintainer=maintainer, co_maintainers=co, seen_at=now)
                previous = baseline['packages'].get(name)
                if previous:
                    period = '; previous observation=' + str(previous.get('seen_at', baseline.get('observed_at', '?')))
                    added = sorted(set(co) - set(previous['co_maintainers']))
                    removed = sorted(set(previous['co_maintainers']) - set(co))
                    if added: issue('health_co_added', name, ', '.join(added) + period)
                    if removed: issue('health_co_removed', name, ', '.join(removed) + period)
                current[name] = observed[name] = item
            except (ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
                partial = True; notes.append(name + ': ' + text(error))
                if not isinstance(error, RequestError):
                    diagnostics.append(('health_data_error', name + ': ' + text(error)))
                observed[name] = dict(base=pkg['PackageBase'], maintainer=maintainer, co_maintainers=None, seen_at=now)
    (run / 'aur-health-observed.json').write_text(json.dumps(dict(observed_at=now, packages=observed), indent=2) + '\n')
    if not partial:
        # A complete snapshot is atomically replaced, never merged from a failed query.
        fd, temporary = tempfile.mkstemp(prefix='aur-maintainers.', suffix='.next', dir=state)
        with os.fdopen(fd, 'w') as stream:
            json.dump(dict(schema=1, observed_at=now, packages=current), stream, indent=2)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, baseline_path)
    notes.append('foreign=' + str(len(names)) + '; AUR observed=' + str(len(observed)) +
                 '; age-threshold=365 days; max-packages=2000; request-budget=260s; baseline=' +
                 (('not-created' if first else 'preserved') if partial else 'updated'))
    return baseline_note if partial else ('health_baseline' if first else 'health_compared')

try:
    note = execute()
except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
    partial = True; note = baseline_note; notes.append(text(error))
    if not isinstance(error, RequestError): diagnostics.append(('health_data_error', text(error)))
with (run / 'aur-health-findings.tsv').open('w') as stream:
    for finding in findings: stream.write('\t'.join(map(text, finding)) + '\n')
(run / 'aur-health-scope.txt').write_text('\n'.join(map(text, notes)) + '\n')
with (run / 'aur-health-diagnostics.tsv').open('w') as stream:
    for diagnostic in diagnostics: stream.write('\t'.join(map(text, diagnostic)) + '\n')
print(('partial' if partial else 'completed') + '\t' + note)
PY
    rc=$?; SC_MODULE_RC[aur-health]=$rc
    if [[ -r $SC_RUN_DIR/aur-health-diagnostics.tsv ]]; then
        while IFS=$'\t' read -r key evidence; do
            [[ -z $key ]] || sc_add_diagnostic aur-health "$key" "$evidence"
        done < "$SC_RUN_DIR/aur-health-diagnostics.tsv"
    fi
    if [[ -f $SC_RUN_DIR/aur-health-findings.tsv ]]; then
        while IFS=$'\t' read -r priority key object evidence; do
            [[ -n $key ]] && sc_add_finding aur-health maintenance "$priority" observation "$object" "$key" "$evidence"
        done < "$SC_RUN_DIR/aur-health-findings.tsv"
    fi
    if ((rc)) || [[ -s $SC_RUN_DIR/aur-health.stderr ]]; then
        sc_module_set aur-health partial health_unavailable
        SC_HEALTH_NOTE=health_not_updated
        sc_add_diagnostic aur-health scanner_error "exit=$rc; aur-health.stderr"
    else
        IFS=$'\t' read -r state note < "$SC_RUN_DIR/aur-health.stdout"
        SC_HEALTH_NOTE=$note
        if [[ $state == completed ]]; then sc_module_set aur-health completed ''
        else sc_module_set aur-health partial health_unavailable; fi
    fi
    if [[ -r $SC_RUN_DIR/aur-health-scope.txt ]]; then
        while IFS= read -r evidence; do SC_SCOPE+=("AUR health: $(sc_text "$evidence")"); done < "$SC_RUN_DIR/aur-health-scope.txt"
    fi
    return 0
}

# ---- Language: authored explanations, never translate upstream evidence -----
sc_t() {
    local en it
    case $1 in
        tagline) en='Understand the signals. Choose your next step.'; it="Comprendi i segnali. Scegli il prossimo passo.";;
        scope) en='READ-ONLY SECURITY CHECKS  /  ARCH LINUX'; it="CONTROLLI DI SICUREZZA  /  ARCH LINUX";;
        welcome) en='Choose what to check'; it="Scegli cosa controllare";;
        menu_full) en='Full scan'; it="Scansione completa";;
        menu_rkhunter) en='Rootkit indicators'; it="Indicatori di rootkit";;
        menu_lynis) en='System configuration'; it="Configurazione del sistema";;
        menu_integrity) en='Installed package files'; it="File dei pacchetti installati";;
        menu_aur) en='AUR / Atomic Arch traces'; it="Tracce AUR / Atomic Arch";;
        menu_deps) en='Check / install dependencies'; it="Verifica / installa dipendenze";;
        menu_update) en='Update rkhunter signatures'; it="Aggiorna firme di rkhunter";;
        menu_demo) en='Explore a sample result'; it="Esplora un risultato di esempio";;
        exit) en='Exit'; it="Esci";;
        choose) en='Choice'; it="Scelta";;
        invalid) en='Choose one of the listed options.'; it="Scegli una delle opzioni indicate.";;
        scanning) en='Checking'; it="Controllo";;
        wait) en='Some checks can take several minutes. Ctrl+C stops the scan and keeps its report.'; it="Alcuni controlli richiedono diversi minuti. Ctrl+C interrompe la scansione e conserva il rapporto.";;
        result) en='YOUR RESULT'; it="IL TUO RISULTATO";;
        urgent) en='URGENT'; it="URGENTE";;
        review) en='REVIEW NEEDED'; it="DA VERIFICARE";;
        advice) en='IMPROVEMENTS AVAILABLE'; it="MIGLIORAMENTI POSSIBILI";;
        unknown) en='RESULT UNDETERMINED'; it="ESITO NON DETERMINABILE";;
        clear) en='NO FINDINGS IN THESE CHECKS'; it="NESSUNA SEGNALAZIONE NEI CONTROLLI";;
        why_urgent) en='A strong indicator needs investigation. A finding alone does not establish that malware ran.'; it="Un indicatore forte richiede attenzione. Una segnalazione, da sola, non dimostra che il malware sia stato eseguito.";;
        why_review) en='There are changes or traces to explain. They may have a legitimate cause.'; it="Ci sono modifiche o tracce da chiarire. Potrebbero avere una causa legittima.";;
        why_advice) en='There are software maintenance or configuration suggestions. These are not evidence of an infection.'; it="Ci sono consigli sulla manutenzione del software o sulla configurazione. Non sono prove di infezione.";;
        why_unknown) en='Some checks could not finish. Missing results cannot establish a clean outcome.'; it="Alcuni controlli non sono terminati. I risultati mancanti non permettono di escludere problemi.";;
        why_clear) en='No signals were found within the stated scope. This is not a guarantee that the system is safe.'; it="Nessun segnale trovato nei limiti indicati. Questo non garantisce che il sistema sia sicuro.";;
        coverage) en='COVERAGE'; it="COPERTURA";;
        complete) en='COMPLETE FOR SELECTED CHECKS'; it="COMPLETA PER I CONTROLLI SCELTI";;
        incomplete) en='INCOMPLETE'; it="INCOMPLETA";;
        scope_selected) en='Selected modules only; other modules were not run.'; it="Solo i moduli selezionati; gli altri non sono stati eseguiti.";;
        scope_full) en='All five modules selected. Each has its own detection limits.'; it="Selezionati tutti e cinque i moduli. Ogni controllo ha limiti propri.";;
        coverage_note) en='Coverage describes checks completed, not a percentage of security.'; it="La copertura indica i controlli conclusi, non una percentuale di sicurezza.";;
        module) en='Module'; it="Modulo";;
        status) en='Status'; it="Stato";;
        findings) en='Findings'; it="Segnali";;
        rkhunter) en='Rootkit / rkhunter'; it="Rootkit / rkhunter";;
        lynis) en='Configuration / Lynis'; it="Configurazione / Lynis";;
        integrity) en='Package integrity'; it="Integrità pacchetti";;
        aur) en='AUR / Atomic Arch'; it="AUR / Atomic Arch";;
        aur-health) en='AUR / Project health'; it="AUR / Manutenzione";;
        health_network) en='AUR project health sends foreign package names to aur.archlinux.org. Use --offline to skip online metadata.'; it="Il controllo manutenzione invia i nomi dei pacchetti esterni ad aur.archlinux.org. Usa --offline per saltare i dati online.";;
        offline) en='Online AUR metadata skipped (--offline).'; it="Dati AUR online non consultati (--offline).";;
        missing_health_tools) en='AUR metadata requires python, curl, pacman and vercmp.'; it="I dati AUR richiedono python, curl, pacman e vercmp.";;
        health_state) en='Cannot safely open the private AUR comparison history.'; it="Impossibile aprire in sicurezza lo storico privato dei confronti AUR.";;
        health_unavailable) en='Some AUR metadata or history could not be verified. Findings collected so far are still shown; the missing checks are explained below.'; it="Alcuni dati o lo storico AUR non sono verificabili. I segnali raccolti restano disponibili; qui sotto trovi quali controlli mancano e perché.";;
        health_no_baseline) en='No AUR baseline was created: this first scan was incomplete. Maintainer changes can be compared after a complete snapshot is saved.'; it="La prima scansione AUR è incompleta: non è stata creata una base per i confronti. Per seguire i cambi di maintainer serve prima una scansione completa.";;
        health_preserved) en='The previous AUR baseline was preserved. This incomplete scan did not replace the history used to compare maintainers.'; it="La precedente base AUR è stata conservata. Questa scansione incompleta non ha sostituito lo storico usato per confrontare i maintainer.";;
        health_not_updated) en='The AUR baseline update could not be confirmed. Resolve the history or execution error before comparing maintainer changes.'; it="Non è stato possibile confermare il salvataggio della base AUR. Risolvi il problema dello storico o dell'esecuzione prima di confrontare i cambi di maintainer.";;
        health_dns) en='The AUR address could not be resolved. Check DNS and the connection; this does not mean a package was removed.'; it="Impossibile risolvere l'indirizzo di AUR. Controlla DNS e connessione; questo errore non significa che un pacchetto sia stato rimosso.";;
        health_connection) en='The connection to AUR failed. Check connectivity and any proxy settings, then repeat this module.'; it="Connessione ad AUR non riuscita. Controlla la rete e le eventuali impostazioni proxy, poi ripeti questo modulo.";;
        health_timeout) en='An AUR request timed out. Repeat this module when the service is reachable; its error log is listed below.'; it="Una richiesta AUR ha superato il tempo disponibile. Ripeti questo modulo quando il servizio è raggiungibile; sotto è indicato il log dell'errore.";;
        health_http) en='AUR returned an HTTP error. Read the code below: 429 means too many requests; 5xx indicates a server error. Repeat the module later.'; it="AUR ha risposto con un errore HTTP. Leggi il codice qui sotto: 429 indica troppe richieste; 5xx un errore del server. Ripeti il modulo più tardi.";;
        health_tls) en='The secure AUR connection could not be verified. Check the clock, certificates and proxy; do not disable certificate checks.'; it="Impossibile verificare la connessione sicura ad AUR. Controlla orologio, certificati e proxy; mantieni attiva la verifica dei certificati.";;
        health_fetch) en='An AUR request failed. The URL, command exit code and original error below identify the failed operation.'; it="Una richiesta AUR è fallita. URL, codice di uscita ed errore originale qui sotto identificano l'operazione non riuscita.";;
        health_data_error) en='Some AUR data could not be read or validated. Unknown maintainer information is not treated as a removal.'; it="Alcuni dati AUR non sono leggibili o verificabili. Un maintainer non verificato non viene considerato rimosso.";;
        health_baseline) en='First AUR snapshot recorded. Maintainer changes before this observation are unknown; comparison starts with the next complete scan.'; it="Registrata la prima fotografia AUR. I cambi di maintainer precedenti sono sconosciuti; il confronto inizia dalla prossima scansione completa.";;
        health_compared) en='AUR maintainers compared with the previous complete scan. Changes are observations, not evidence of malicious intent.'; it="Maintainer AUR confrontati con la precedente scansione completa. I cambi sono osservazioni, non prove di intenzioni malevole.";;
        health_orphan) en='AUR lists no primary maintainer: this package is orphaned. This differs from an unused local dependency. Check support and consider a maintained alternative if needed.'; it="AUR non indica un maintainer principale: il pacchetto è orfano. Non significa che sia una dipendenza locale inutilizzata. Verifica il supporto e valuta, se serve, un'alternativa mantenuta.";;
        health_flagged) en='Someone flagged the AUR recipe as out of date. This is a report by a user, not a verified vulnerability or proof that every installed version is obsolete.'; it="La ricetta AUR è segnalata come non aggiornata. È una segnalazione di un utente, non una vulnerabilità verificata o la prova che ogni versione installata sia obsoleta.";;
        health_upgrade) en='AUR advertises a newer package version than the installed one. Review the build changes before updating. VCS packages may use dynamic versions.'; it="AUR indica una versione del pacchetto più nuova di quella installata. Esamina le modifiche allo script prima di aggiornare. I pacchetti VCS possono usare versioni dinamiche.";;
        health_inactive) en='The AUR recipe has not changed for at least 365 days. This does not prove abandonment: stable software may need no packaging changes. Check upstream activity and open issues.'; it="La ricetta AUR non cambia da almeno 365 giorni. Questo non prova un abbandono: un software stabile può non richiedere modifiche al pacchetto. Controlla il progetto originale e i problemi aperti.";;
        health_unlisted) en='This foreign package has no current exact match in AUR. It may be a local/custom package or a renamed/removed package. Its previous AUR presence is unknown.'; it="Questo pacchetto esterno non ha una corrispondenza attuale in AUR. Potrebbe essere locale, personalizzato, rinominato o rimosso. Non e nota la sua eventuale presenza passata su AUR.";;
        health_removed) en='A previous scan found this package in AUR; the current valid response does not. Check whether it was renamed, merged or deleted before deciding what to do.'; it="Una scansione precedente aveva trovato il pacchetto su AUR; la risposta valida attuale non lo contiene. Verifica se è stato rinominato, unito o eliminato prima di decidere come procedere.";;
        health_maintainer) en='The primary maintainer differs from the previous observation. Adoption and handovers can be legitimate. Review the package page and recent build-script changes before the next update.'; it="Il maintainer principale è cambiato rispetto all'osservazione precedente. Adozioni e passaggi di gestione possono essere legittimi. Esamina pagina AUR e modifiche recenti allo script prima del prossimo aggiornamento.";;
        health_co_added) en='New co-maintainers appeared since the previous observation. They can help maintain the build recipe. Review the handover and recent changes; an addition alone is not a threat.'; it="Sono comparsi nuovi co-maintainer dall'osservazione precedente. Possono contribuire alla ricetta del pacchetto. Controlla il passaggio di gestione e le modifiche recenti; l'aggiunta da sola non è una minaccia.";;
        health_co_removed) en='Co-maintainers from the previous observation are no longer listed. Review the current support situation; removal alone is not malicious.'; it="Alcuni co-maintainer della precedente osservazione non risultano più presenti. Verifica la situazione del supporto; una rimozione da sola non indica un attacco.";;
        not-run) en='Not selected'; it="Non selezionato";;
        running) en='Running'; it="In corso";;
        completed) en='Completed'; it="Completato";;
        partial) en='Partial'; it="Parziale";;
        failed) en='Failed'; it="Fallito";;
        skipped) en='Unavailable'; it="Non disponibile";;
        missing_rkhunter) en='Install rkhunter to run this module.'; it="Installa rkhunter per eseguire questo modulo.";;
        missing_lynis) en='Install lynis to run this module.'; it="Installa lynis per eseguire questo modulo.";;
        missing_pacman) en='pacman is unavailable.'; it="pacman non disponibile.";;
        missing_paccheck) en='SHA-256 checks unavailable: pacutils is missing, so this part of the file-content check was not performed. Use main-menu option 6 to install the missing tool, then repeat option 4.'; it="Controllo SHA-256 non disponibile: manca pacutils, quindi questa verifica del contenuto dei file non è stata eseguita. Usa la voce 6 del menu principale per installare lo strumento mancante, poi ripeti la voce 4.";;
        rkh_limited) en='rkhunter finished, but some tests were skipped or commands reported problems. The reasons below limit coverage; they are not additional malware findings.'; it="rkhunter è arrivato alla fine, ma alcuni test sono stati saltati o alcuni comandi hanno segnalato problemi. Le cause qui sotto limitano la copertura; non sono ulteriori rilevamenti di malware.";;
        rkh_skipped) en='Tests not performed by rkhunter. They may require optional tools, services or different settings; this result does not cover them:'; it="Test non eseguiti da rkhunter. Possono dipendere da strumenti facoltativi, servizi o impostazioni; questo risultato non li copre:";;
        rkh_legacy_grep) en='Compatibility notice: rkhunter uses the obsolete egrep name, which still forwards to grep -E. This notice alone does not invalidate the scan:'; it="Avviso di compatibilità: rkhunter usa il nome obsoleto egrep, che richiama ancora grep -E. Questo avviso da solo non invalida la scansione:";;
        rkh_regex) en='grep reported a compatibility problem with search expressions used by rkhunter. Check for a distribution update; affected checks are not treated as fully verified:'; it="grep segnala un problema di compatibilità nelle espressioni usate da rkhunter. Verifica gli aggiornamenti della distribuzione; i controlli interessati non sono considerati pienamente verificati:";;
        rkh_unparsed) en='rkhunter returned a warning exit code, but no corresponding finding was recognized. Read the original logs before drawing conclusions:'; it="rkhunter ha restituito un codice di avviso, ma non è stata riconosciuta la segnalazione corrispondente. Leggi i log originali prima di trarre conclusioni:";;
        scanner_error) en='The scanner reported an execution or reading problem. Original message:'; it="Lo scanner ha segnalato un problema di esecuzione o lettura. Messaggio originale:";;
        diagnostics_more) en='Further diagnostic details are included in the full report (option 2).'; it="Altri dettagli diagnostici sono nel rapporto completo (voce 2).";;
        check_details) en='Warnings, read errors or an unknown output format reduced coverage. Read the raw logs.'; it="Avvisi, errori di lettura o un formato inatteso hanno limitato il controllo. Consulta i log originali.";;
        unfinished) en='The scanner did not report a normal completion.'; it="Lo scanner non ha comunicato una conclusione regolare.";;
        command_failed) en='The command failed without usable results.'; it="Il comando non ha prodotto risultati utilizzabili.";;
        no_report) en='The scanner did not produce a usable report.'; it="Lo scanner non ha prodotto un rapporto utilizzabile.";;
        bounded_scope) en='Some paths or history were unavailable, or a time/file limit was reached.'; it="Alcuni percorsi o lo storico non erano disponibili, oppure e stato raggiunto un limite di tempo o file.";;
        interrupted) en='Interrupted by the user.'; it="Interrotto dall'utente.";;
        next) en='WHAT TO DO NEXT'; it="COSA FARE ADESSO";;
        next_urgent) en='Review the urgent evidence first. Avoid sensitive activity on this system while a strong indicator remains unexplained. Preserve the report and seek qualified help; do not delete files blindly.'; it="Leggi prima le prove delle segnalazioni urgenti. Evita attività sensibili su questo sistema finché un indicatore forte resta da chiarire. Conserva il rapporto e chiedi aiuto qualificato; non cancellare file alla cieca.";;
        next_review) en='Open the findings and check whether the changes match software you installed or settings you changed. Investigate unexplained executable changes and startup entries before removing anything.'; it="Apri i dettagli e verifica se le modifiche corrispondono a software installati o impostazioni cambiate da te. Approfondisci i cambiamenti inspiegati agli eseguibili e gli avvii automatici prima di rimuovere qualcosa.";;
        next_advice) en='Read each package or configuration suggestion. Check project status and build changes before updating; preserve settings before editing them.'; it="Leggi i consigli sui pacchetti o sulla configurazione. Verifica lo stato dei progetti e le modifiche agli script prima di aggiornare; conserva le impostazioni prima di cambiarle.";;
        next_unknown) en='Read the module reasons below. Install missing tools or resolve read errors, then repeat the affected checks.'; it="Leggi le cause indicate per i moduli. Installa gli strumenti mancanti o risolvi gli errori di lettura, poi ripeti i controlli interessati.";;
        next_clear) en='Keep software current, review AUR build scripts before installation and keep reliable backups.'; it="Mantieni aggiornato il software, controlla gli script AUR prima di installarli e conserva copie affidabili dei tuoi dati.";;
        incomplete_next) en='Also resolve the incomplete modules: the current result does not cover them fully.'; it="Completa anche i moduli rimasti parziali: il risultato attuale non li copre interamente.";;
        signals) en='SIGNALS BY PRIORITY'; it="SEGNALI PER PRIORITÀ";;
        priority_urgent) en='Urgent'; it="Urgenti";;
        priority_review) en='To review'; it="Da verificare";;
        priority_suggestion) en='Suggestions'; it="Consigli";;
        count_note) en='Bars show counts of findings, not likelihood of infection.'; it="Le barre mostrano il numero di segnali, non la probabilità di infezione.";;
        details) en='FINDING DETAILS'; it="DETTAGLI DELLE SEGNALAZIONI";;
        none) en='No findings were recorded.'; it="Nessuna segnalazione registrata.";;
        evidence) en='Source evidence (original language)'; it="Prova dalla fonte (lingua originale)";;
        object) en='Object'; it="Elemento";;
        confidence_match) en='Known byte sequence matched'; it="Corrispondenza con byte noti";;
        confidence_unconfirmed) en='Indicator requiring verification'; it="Indicatore da confermare";;
        confidence_observation) en='Observation; cause not established'; it="Osservazione; causa da chiarire";;
        rkh_signature) en='rkhunter reported a possible rootkit signature. It remains unresolved even if package checks pass. Check the exact signature and its context with expert help.'; it="rkhunter segnala una possibile firma di rootkit. Resta da chiarire anche se i pacchetti superano il controllo. Verifica la firma precisa e il contesto con aiuto esperto.";;
        rkh_properties) en='rkhunter found changed file properties. Updates can cause this, but the change needs checking. Do not reset its baseline before investigating.'; it="rkhunter ha trovato proprietà di file cambiate. Gli aggiornamenti possono causarlo, ma occorre verificare. Non azzerare la base di confronto prima di approfondire.";;
        rkh_warning) en='rkhunter raised an alert. Read the specific evidence: hidden files and configuration warnings can have legitimate explanations.'; it="rkhunter ha prodotto un avviso. Leggi la prova specifica: file nascosti e avvisi di configurazione possono avere spiegazioni legittime.";;
        lynis_warning) en='Lynis found a configuration issue. Use its test ID and evidence to decide what to change; this does not independently confirm malware.'; it="Lynis segnala un problema di configurazione. Usa il codice del test e i dettagli per decidere cosa cambiare; questo non conferma da solo la presenza di malware.";;
        lynis_suggestion) en='Lynis suggests stronger settings. Assess compatibility and the purpose of this machine before applying the suggestion.'; it="Lynis suggerisce impostazioni più robuste. Valuta compatibilità e uso di questo computer prima di applicare il consiglio.";;
        integrity_metadata) en='Size, permissions or another file property differs from the local package record. This is not a content hash result. Explain the change, especially for executables.'; it="Dimensione, permessi o altre proprietà differiscono dai dati locali del pacchetto. Questo non è un confronto crittografico del contenuto. Chiarisci la modifica, soprattutto per gli eseguibili.";;
        integrity_content) en='File contents differ from the local package SHA-256 record. Configuration edits can be intentional; an unexplained executable change needs investigation. The package record itself is not proof of trusted provenance.'; it="Il contenuto differisce dallo SHA-256 registrato localmente dal pacchetto. Una configurazione può essere modificata volontariamente; un eseguibile cambiato senza spiegazione richiede attenzione. I dati del pacchetto non ne garantiscono la provenienza.";;
        integrity_missing) en='A packaged file is missing. Check exclusions, package state and recent changes. Missing does not by itself mean malicious.'; it="Manca un file previsto dal pacchetto. Verifica esclusioni, stato del pacchetto e modifiche recenti. Un file mancante non dimostra da solo un attacco.";;
        aur_reference) en='A documented campaign package name appears in this file. It may be a cached reference. Check the version, installation history and lifecycle scripts without executing them.'; it="In questo file compare il nome di un pacchetto associato alla campagna. Potrebbe essere un riferimento in cache. Verifica versione, storico e script di installazione senza eseguirli.";;
        aur_hash) en='This file matches the documented Atomic Arch payload SHA-256. Preserve it as evidence and seek incident-response help. Presence is established; execution is not established by this check.'; it="Questo file corrisponde allo SHA-256 del payload Atomic Arch documentato. Conservalo come prova e chiedi assistenza per analizzare l'incidente. Il controllo ne rileva la presenza, non dimostra l'esecuzione.";;
        aur_history) en='A package was installed or updated during the reported campaign dates. This is an exposure clue, not proof that this exact build was malicious.'; it="Un pacchetto è stato installato o aggiornato nelle date della campagna. È un indizio di esposizione, non la prova che quella specifica versione fosse malevola.";;
        aur_service) en='This service resembles a documented persistence pattern. Legitimate services can also match. Review the executable, its owner and installation history without running it.'; it="Questo servizio ricorda uno schema di persistenza documentato. Anche un servizio legittimo può corrispondere. Verifica eseguibile, proprietario e storico senza avviarlo.";;
        aur_bpf) en='A BPF object has a name reported in the campaign. A name alone is not a rootkit diagnosis. Have its provenance and contents examined.'; it="Un oggetto BPF ha un nome riportato nella campagna. Il nome da solo non identifica un rootkit. Fai verificare provenienza e contenuto.";;
        file_config) en='Configuration/backup path: an intentional edit is possible, but must be verified.'; it="Percorso di configurazione o backup: la modifica può essere voluta, ma va verificata.";;
        demo) en='DEMO - INVENTED RESULTS. No system scan was performed.'; it="DEMO - RISULTATI DI ESEMPIO. Nessuna scansione del sistema eseguita.";;
        report) en='Private report'; it="Rapporto privato";;
        report_info) en='Reports contain paths and technical logs. Review them before sharing. Root permission is required to read scan reports.'; it="I rapporti contengono percorsi e log tecnici. Controllali prima di condividerli. Per leggere i rapporti delle scansioni servono permessi di root.";;
        scope_report) en='TECHNICAL SCOPE / ORIGINAL LOGS'; it="AMBITO TECNICO / LOG ORIGINALI";;
        limits) en='Live checks cannot exclude hidden rootkits, past execution or data theft. AUR checks cover only bundled indicators and listed paths.'; it="I controlli dal sistema avviato non escludono rootkit nascosti, esecuzioni passate o furti di dati. Il modulo AUR copre solo gli indicatori inclusi e i percorsi indicati.";;
        result_menu) en='1  Findings   2  Full report   3  Repeat scan   0  Main menu'; it="1  Dettagli   2  Rapporto   3  Ripeti scansione   0  Menu";;
        more) en='More findings are available in the full report.'; it="Le altre segnalazioni sono disponibili nel rapporto completo.";;
        unsupported) en='Scanning requires Arch Linux or an Arch derivative with pacman.'; it="La scansione richiede Arch Linux o una derivata con pacman.";;
        root) en='This action requires root. SecCheck will request permission through sudo.'; it="Questa azione richiede root. SecCheck chiederà i permessi tramite sudo.";;
        need_root) en='Run this command with sudo to scan noninteractively.'; it="Esegui questo comando con sudo per una scansione non interattiva.";;
        storage_error) en='Cannot create a private report directory. Scan not started.'; it="Impossibile creare una cartella privata per i rapporti. Scansione non avviata.";;
        save_error) en='Report could not be saved completely. Check free space and permissions.'; it="Rapporto non salvato completamente. Controlla spazio libero e permessi.";;
        deps) en='TOOLS AND PURPOSE'; it="STRUMENTI E FUNZIONE";;
        available) en='available'; it="disponibile";;
        absent) en='missing'; it="mancante";;
        install_question) en='Install missing scanner packages with pacman? [y/N]'; it="Installare con pacman gli strumenti mancanti? [s/N]";;
        install_note) en='pacman will show its own transaction confirmation. No AUR helper is used.'; it="pacman mostrerà la propria conferma della transazione. Non viene usato un helper AUR.";;
        install_failed) en='Installation did not complete.'; it="Installazione non completata.";;
        signatures_updated) en='rkhunter signatures updated.'; it="Firme di rkhunter aggiornate.";;
        signatures_current) en='rkhunter signatures are already current.'; it="Le firme di rkhunter sono già aggiornate.";;
        signatures_failed) en='Signature update failed. Read the saved update log.'; it="Aggiornamento delle firme fallito. Consulta il log salvato.";;
        language_needed) en='Use --lang en or --lang it for noninteractive use.'; it="Usa --lang en o --lang it per l'uso non interattivo.";;
        usage) en='Usage:'; it="Uso:";;
        batch_usage) en='Batch scans: exit 0=no review/urgent findings, 1=findings, 2=incomplete; other codes=setup error.'; it="Scansioni CLI: uscita 0=nessun segnale urgente/da verificare, 1=segnali, 2=incompleta; altri codici=errore iniziale.";;
        *) en=$1; it=$1;;
    esac
    local value=$en
    [[ ${SC_LANG:-en} != it ]] || value=$it
    if [[ ${SC_ASCII:-0} == 1 ]]; then sc_ascii_text "$value"; else printf '%s' "$value"; fi
}

sc_ascii_text() {
    local value=$1
    value=${value//à/a}; value=${value//è/e}; value=${value//é/e}; value=${value//ì/i}
    value=${value//ò/o}; value=${value//ù/u}; value=${value//À/A}; value=${value//È/E}; value=${value//’/\'}
    printf '%s' "$value" | LC_ALL=C tr '\200-\377' '?'
}

# ---- Petrolio terminal rendering: no cursor tricks, real counts only --------
sc_ui_init() {
    SC_WIDTH=${COLUMNS:-80}
    if [[ -t 1 ]] && command -v tput >/dev/null; then SC_WIDTH=$(tput cols 2>/dev/null) || SC_WIDTH=80; fi
    [[ $SC_WIDTH =~ ^[0-9]{1,4}$ ]] || SC_WIDTH=80
    ((SC_WIDTH < 24)) && SC_WIDTH=24
    ((SC_WIDTH > 120)) && SC_WIDTH=120
    SC_C_PRIMARY='' SC_C_MUTED='' SC_C_RED='' SC_C_AMBER='' SC_C_GREEN='' SC_C_RESET='' SC_C_BOLD=''
    if [[ -t 1 && ${TERM:-dumb} != dumb && ${SC_NO_COLOR:-0} == 0 && ! ${NO_COLOR+x} ]]; then
        SC_C_RESET=$'\e[0m' SC_C_BOLD=$'\e[1m'
        SC_C_PRIMARY=$'\e[38;5;80m' SC_C_MUTED=$'\e[38;5;109m'
        SC_C_RED=$'\e[38;5;203m' SC_C_AMBER=$'\e[38;5;222m' SC_C_GREEN=$'\e[38;5;114m'
        if [[ ${COLORTERM:-} == truecolor || ${COLORTERM:-} == 24bit ]]; then
            SC_C_PRIMARY=$'\e[38;2;122;205;216m' SC_C_MUTED=$'\e[38;2;140;168;185m'
        fi
    fi
    SC_RULE_CHAR='─' SC_BAR_CHAR='━' SC_EMPTY_CHAR='─' SC_DOT='●'
    if [[ ${SC_ASCII:-0} == 1 || ${TERM:-} == dumb || ${LC_ALL:-${LC_CTYPE:-${LANG:-C}}} != *[Uu][Tt][Ff]* ]]; then
        SC_ASCII=1; SC_RULE_CHAR='-' SC_BAR_CHAR='#' SC_EMPTY_CHAR='.' SC_DOT='*'
    fi
}

sc_repeat() { local i; for ((i=0;i<$2;i++)); do printf '%s' "$1"; done; }

sc_line() {
    local value=${1-} color=${2-} word line='' width=$((SC_WIDTH-4))
    value=$(sc_text "$value")
    if [[ ${SC_ASCII:-0} == 1 ]]; then value=$(sc_ascii_text "$value"); fi
    local -a words=()
    read -r -a words <<< "$value"
    for word in "${words[@]}"; do
        if ((${#line}+${#word}+1 > width)) && [[ -n $line ]]; then
            printf '  %s%s%s\n' "$color" "$line" "$SC_C_RESET"; line=''
        fi
        while ((${#word} > width)); do
            printf '  %s%s%s\n' "$color" "${word:0:width}" "$SC_C_RESET"; word=${word:width}
        done
        [[ -z $word ]] || line+="${line:+ }$word"
    done
    [[ -z $line ]] || printf '  %s%s%s\n' "$color" "$line" "$SC_C_RESET"
}

sc_rule() { printf '  %s' "$SC_C_MUTED"; sc_repeat "$SC_RULE_CHAR" "$((SC_WIDTH-4))"; printf '%s\n' "$SC_C_RESET"; }
sc_cell() { printf '%s%*s' "$1" "$(( $2 - ${#1} ))" ''; }
sc_heading() { printf '\n'; sc_line "$(sc_t "$1")" "$SC_C_PRIMARY$SC_C_BOLD"; sc_rule; }
sc_header() {
    printf '\n'; sc_rule
    sc_line "S E C C H E C K   /   $SC_VERSION" "$SC_C_PRIMARY$SC_C_BOLD"
    sc_line "$(sc_t scope)" "$SC_C_MUTED"
    sc_rule; sc_line "$(sc_t tagline)"; printf '\n'
    [[ ${SC_DEMO:-0} == 0 ]] || sc_line "$(sc_t demo)" "$SC_C_AMBER"
}

sc_status_color() {
    case $1 in urgent|failed) printf '%s' "$SC_C_RED";; review|advice|partial) printf '%s' "$SC_C_AMBER";;
        clear|completed) printf '%s' "$SC_C_GREEN";; *) printf '%s' "$SC_C_MUTED";; esac
}

sc_render_diagnostics() {
    local module=$1 limit=${2:-0} i shown=0 last_key=''
    for ((i=0; i<${#SC_D_MODULE[@]}; i++)); do
        [[ ${SC_D_MODULE[i]} == "$module" ]] || continue
        if ((limit && shown >= limit)); then sc_line "$(sc_t diagnostics_more)" "$SC_C_MUTED"; return 0; fi
        ((shown+=1))
        if [[ ${SC_D_KEY[i]} != "$last_key" ]]; then
            sc_line "$(sc_t "${SC_D_KEY[i]}")" "$SC_C_MUTED"
            last_key=${SC_D_KEY[i]}
        fi
        sc_line "- ${SC_D_EVIDENCE[i]}" "$SC_C_MUTED"
    done
    return 0
}

sc_render_summary() {
    local module count i color label bar total=${#SC_SELECTED[@]}
    sc_heading result
    color=$(sc_status_color "$SC_ASSESSMENT")
    sc_line "$SC_DOT  $(sc_t "$SC_ASSESSMENT")" "$color$SC_C_BOLD"
    sc_line "$(sc_t "why_$SC_ASSESSMENT")"
    sc_heading coverage
    if ((SC_INCOMPLETE)); then label=$(sc_t incomplete); color=$SC_C_MUTED
    else label=$(sc_t complete); color=$SC_C_PRIMARY; fi
    sc_line "$SC_COMPLETED/$total  $label" "$color"
    bar="$(sc_repeat "$SC_BAR_CHAR" "$SC_COMPLETED")$(sc_repeat "$SC_EMPTY_CHAR" "$((total-SC_COMPLETED))")"
    sc_line "[$bar]" "$color"
    if ((total < 5)); then sc_line "$(sc_t scope_selected)"; else sc_line "$(sc_t scope_full)"; fi
    sc_line "$(sc_t coverage_note)" "$SC_C_MUTED"
    printf '\n'
    if ((SC_WIDTH >= 64)); then
        printf '  %s%-24s %-17s %7s%s\n' "$SC_C_MUTED" "$(sc_t module)" "$(sc_t status)" "$(sc_t findings)" "$SC_C_RESET"
        sc_rule
    fi
    for module in $SC_ALL_MODULES; do
        count=0
        for i in "${SC_F_MODULE[@]}"; do [[ $i == "$module" ]] && ((count+=1)); done
        color=$(sc_status_color "${SC_MODULE_STATUS[$module]}")
        if ((SC_WIDTH >= 64)); then
            printf '  '; sc_cell "$(sc_t "$module")" 24; printf ' %s' "$color"
            sc_cell "$(sc_t "${SC_MODULE_STATUS[$module]}")" 17; printf '%s %7d\n' "$SC_C_RESET" "$count"
        else
            sc_line "$(sc_t "$module")" "$SC_C_PRIMARY"
            sc_line "$(sc_t "${SC_MODULE_STATUS[$module]}") / $(sc_t findings): $count" "$color"
        fi
        [[ -z ${SC_MODULE_REASON[$module]} ]] || sc_line "$(sc_t "${SC_MODULE_REASON[$module]}")" "$SC_C_MUTED"
        sc_render_diagnostics "$module" 6
    done
    [[ -z ${SC_HEALTH_NOTE:-} ]] || sc_line "$(sc_t "$SC_HEALTH_NOTE")" "$SC_C_MUTED"
    sc_heading signals
    local max=$SC_URGENT slots=$((SC_WIDTH-29)) n priority
    ((SC_REVIEW > max)) && max=$SC_REVIEW; ((SC_SUGGESTIONS > max)) && max=$SC_SUGGESTIONS
    ((slots < 4)) && slots=4; ((slots > 24)) && slots=24
    for priority in urgent review suggestion; do
        case $priority in urgent) count=$SC_URGENT;; review) count=$SC_REVIEW;; suggestion) count=$SC_SUGGESTIONS;; esac
        n=0; ((max)) && n=$(((count*slots+max-1)/max))
        sc_line "$(sc_t "priority_$priority"): $count  $(sc_repeat "$SC_BAR_CHAR" "$n")" "$(sc_status_color "$priority")"
    done
    sc_line "$(sc_t count_note)" "$SC_C_MUTED"
    sc_heading next
    sc_line "$(sc_t "next_$SC_ASSESSMENT")"
    ((SC_INCOMPLETE == 0)) || sc_line "$(sc_t incomplete_next)" "$SC_C_AMBER"
    sc_line "$(sc_t limits)" "$SC_C_MUTED"
}

sc_render_details() {
    local limit=${1:-0} i shown=0 priority object
    sc_heading details
    ((${#SC_F_MODULE[@]})) || { sc_line "$(sc_t none)"; return 0; }
    for priority in urgent review suggestion; do
        for ((i=0;i<${#SC_F_MODULE[@]};i++)); do
            [[ ${SC_F_PRIORITY[i]} == "$priority" ]] || continue
            if ((limit && shown >= limit)); then sc_line "$(sc_t more)"; return 0; fi
            ((shown+=1)); object=${SC_F_OBJECT[i]}
            printf '\n'
            sc_line "#$((i+1)) / $(sc_t "priority_$priority") / $(sc_t "${SC_F_MODULE[i]}")" "$(sc_status_color "$priority")"
            sc_line "$(sc_t "confidence_${SC_F_CONFIDENCE[i]}")" "$SC_C_MUTED"
            [[ -z $object ]] || sc_line "$(sc_t object): $object"
            sc_line "$(sc_t "${SC_F_KEY[i]}")"
            if [[ ${SC_F_MODULE[i]} == integrity && ( $object == /etc/* || ${SC_F_EVIDENCE[i]} == *'backup file:'* ) ]]; then
                sc_line "$(sc_t file_config)"
            fi
            sc_line "$(sc_t evidence): ${SC_F_EVIDENCE[i]}" "$SC_C_MUTED"
        done
    done
}

# ---- Private run reports ----------------------------------------------------
sc_prepare_run() {
    local parent=${1:-/var/log/seccheck} owner
    [[ ! -L $parent ]] || return 1
    if [[ ! -e $parent ]]; then (umask 077; mkdir -- "$parent") || return 1; fi
    [[ -d $parent ]] || return 1
    owner=$(stat -c '%u' -- "$parent") || return 1
    [[ $owner == "$EUID" ]] || return 1
    chmod 700 -- "$parent" || return 1
    SC_RUN_DIR=$(umask 077; mktemp -d "$parent/run.$(date -u +%Y%m%dT%H%M%SZ).XXXXXX") || return 1
    SC_STARTED=$(date -u +%FT%TZ)
}

sc_render_report() {
    sc_header; sc_render_summary; sc_render_details
    sc_heading scope_report
    sc_line "SecCheck=$SC_VERSION; started=${SC_STARTED:-demo}; rules=$SC_RULESET; rules-date=$SC_RULESET_DATE"
    local module value
    for module in "${SC_SELECTED[@]}"; do
        sc_line "$module: version=${SC_MODULE_VERSION[$module]}; exit=${SC_MODULE_RC[$module]}; reason=${SC_MODULE_REASON[$module]}"
        sc_render_diagnostics "$module" 0
    done
    for value in "${SC_SCOPE[@]}"; do sc_line "$value"; done
    sc_line 'Indicator sources: https://ioctl.fail/preliminary-analysis-of-aur-malware/'
    sc_line 'https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency'
    sc_line "$(sc_t report_info)"
}

sc_save_report() (
    umask 077
    SC_NO_COLOR=1
    sc_ui_init; SC_WIDTH=100; SC_ASCII=0
    SC_RULE_CHAR='-' SC_BAR_CHAR='#' SC_EMPTY_CHAR='.' SC_DOT='*'
    local module i
    sc_render_report > "$SC_RUN_DIR/report.txt" || return 1
    {
        printf 'module\tkind\tpriority\tconfidence\tobject\tkey\tevidence\n'
        for ((i=0;i<${#SC_F_MODULE[@]};i++)); do
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "${SC_F_MODULE[i]}" "${SC_F_KIND[i]}" \
                "${SC_F_PRIORITY[i]}" "${SC_F_CONFIDENCE[i]}" "${SC_F_OBJECT[i]}" "${SC_F_KEY[i]}" "${SC_F_EVIDENCE[i]}"
        done
    } > "$SC_RUN_DIR/findings.tsv" || return 1
    {
        printf 'module\tstatus\treason\texit\tversion\n'
        for module in $SC_ALL_MODULES; do
            printf '%s\t%s\t%s\t%s\t%s\n' "$module" "${SC_MODULE_STATUS[$module]}" \
                "${SC_MODULE_REASON[$module]}" "${SC_MODULE_RC[$module]}" "${SC_MODULE_VERSION[$module]}"
        done
    } > "$SC_RUN_DIR/modules.tsv" || return 1
)

# ---- CLI and interactive workflow ------------------------------------------
sc_is_arch() {
    local key value
    [[ -r ${1:-/etc/os-release} ]] || return 1
    while IFS='=' read -r key value; do
        value=${value#\"}; value=${value%\"}; value=${value#\'}; value=${value%\'}
        case $key in
            ID) [[ $value == arch ]] && return 0;;
            ID_LIKE) [[ " $value " == *' arch '* ]] && return 0;;
        esac
    done < "${1:-/etc/os-release}"
    return 1
}

sc_help() {
    printf '%s bash seccheck.sh [options]\n\n' "$(sc_t usage)"
    printf '%s\n' '  --lang en|it' '  --scan full|rkhunter|lynis|integrity|aur|aur-health' \
        '  --aur-path /absolute/path   (repeatable)' '  --offline' '  --no-color' '  --ascii' \
        '  --demo [review|urgent|incomplete|clean]' '  --help' '  --version'
    printf '\n%s\n' "$(sc_t batch_usage)"
    printf '%s\n' "$(sc_t health_network)"
}

sc_parse_args() {
    SC_LANG='' SC_SCAN='' SC_DEMO=0 SC_SCENARIO=review SC_NO_COLOR=0 SC_ASCII=0 SC_ACTION='' SC_OFFLINE=0
    declare -ga SC_EXTRA_AUR_PATHS=()
    while (($#)); do
        case $1 in
            --lang) (($# >= 2)) || return 64; case $2 in en|it) SC_LANG=$2;; *) return 64;; esac; shift;;
            --scan) (($# >= 2)) || return 64; case $2 in full|rkhunter|lynis|integrity|aur|aur-health) SC_SCAN=$2;; *) return 64;; esac; shift;;
            --aur-path) (($# >= 2)) && [[ $2 == /* ]] || return 64; SC_EXTRA_AUR_PATHS+=("$2"); shift;;
            --no-color) SC_NO_COLOR=1;;
            --offline) SC_OFFLINE=1;;
            --ascii) SC_ASCII=1;;
            --demo) SC_DEMO=1
                if (($# > 1)) && [[ $2 != --* ]]; then
                    case $2 in review|urgent|incomplete|clean) SC_SCENARIO=$2;; *) return 64;; esac; shift
                fi;;
            --help|-h) SC_ACTION=help;;
            --version) SC_ACTION=version;;
            --install-tools) SC_ACTION=install;;
            --update-signatures) SC_ACTION=update;;
            *) return 64;;
        esac
        shift
    done
    [[ $SC_DEMO == 0 || ( -z $SC_SCAN && -z $SC_ACTION ) ]] || return 64
}

sc_choose_language() {
    local answer
    printf '\n  S E C C H E C K   /   %s\n\n  1  English\n  2  Italiano\n\n' "$SC_VERSION"
    while :; do
        printf '  > '
        IFS= read -r answer || return 1
        case $answer in 1) SC_LANG=en; return 0;; 2) SC_LANG=it; return 0;; *) printf '  1 / 2\n';; esac
    done
}

sc_elevate() {
    local action=$1 path
    local -a args=(--lang "$SC_LANG")
    case $action in scan) args+=(--scan "$SC_SCAN");; install) args+=(--install-tools);; update) args+=(--update-signatures);; esac
    [[ ${SC_NO_COLOR:-0} == 0 && ! ${NO_COLOR+x} ]] || args+=(--no-color)
    [[ ${SC_ASCII:-0} == 0 ]] || args+=(--ascii)
    [[ ${SC_OFFLINE:-0} == 0 ]] || args+=(--offline)
    for path in "${SC_EXTRA_AUR_PATHS[@]}"; do args+=(--aur-path "$path"); done
    path=$(readlink -f -- "${BASH_SOURCE[0]}") || return 77
    sudo -- bash "$path" "${args[@]}"
}

sc_require_scan_host() {
    if ! sc_is_arch /etc/os-release || ! command -v pacman >/dev/null; then sc_line "$(sc_t unsupported)"; return 78; fi
}

sc_demo() {
    sc_reset
    local module
    for module in "${SC_SELECTED[@]}"; do sc_module_set "$module" completed ''; SC_MODULE_VERSION[$module]=demo; done
    SC_SCOPE=('Demo data only; no commands or filesystem inspection.')
    case ${1:-review} in
        clean) ;;
        incomplete) sc_module_set rkhunter skipped missing_rkhunter; sc_module_set integrity partial missing_paccheck;;
        urgent)
            sc_add_finding aur suspicious urgent match /home/example/.cache/sample/deps aur_hash 'DEMO: documented SHA-256 match'
            sc_module_set rkhunter partial unfinished;;
        review)
            sc_add_finding integrity integrity review observation /etc/example.conf integrity_content 'DEMO: SHA-256 differs from local package record'
            sc_add_finding aur exposure review observation /home/example/.cache/yay/sample/PKGBUILD aur_reference 'DEMO: atomic-lockfile reference'
            sc_add_finding lynis hardening suggestion observation SSH-DEMO lynis_suggestion 'DEMO: review SSH configuration'
            sc_add_finding aur-health maintenance review observation example-app health_maintainer 'DEMO: old-owner -> new-owner'
            sc_add_finding aur-health maintenance suggestion observation example-tool health_inactive 'DEMO: days=420';;
    esac
    sc_assess; sc_header; sc_render_summary; sc_render_details 6
}

sc_update_signatures() {
    local rc
    if ! command -v rkhunter >/dev/null; then printf '%s\n' "$(sc_t missing_rkhunter)"; return 1; fi
    sc_capture "$SC_RUN_DIR/rkhunter-update.stdout" "$SC_RUN_DIR/rkhunter-update.stderr" 300 rkhunter --update --nocolors --lang en
    rc=$?
    case $rc in
        0) printf '%s\n' "$(sc_t signatures_current)";;
        2) printf '%s\n' "$(sc_t signatures_updated)";;
        *) printf '%s\n' "$(sc_t signatures_failed)"; return 1;;
    esac
}

sc_dependencies() {
    local tool label answer
    local -a missing=()
    sc_heading deps
    for tool in rkhunter lynis paccheck python3 curl; do
        label=$(sc_t available)
        if ! command -v "$tool" >/dev/null; then
            label=$(sc_t absent)
            case $tool in paccheck) missing+=(pacutils);; python3) missing+=(python);; *) missing+=("$tool");; esac
        fi
        case $tool in rkhunter) sc_line "$tool / $(sc_t menu_rkhunter): $label";;
            lynis) sc_line "$tool / $(sc_t menu_lynis): $label";;
            paccheck) sc_line "pacutils (paccheck) / SHA-256: $label";;
            *) sc_line "$tool / $(sc_t aur-health): $label";; esac
    done
    ((${#missing[@]})) || return 0
    [[ -t 0 ]] || return 1
    sc_line "$(sc_t install_question)"
    IFS= read -r answer || return 0
    case $answer in y|Y|s|S) ;; *) return 0;; esac
    sc_require_scan_host || return $?
    if ((EUID != 0)); then sc_line "$(sc_t root)"; sc_elevate install; return $?; fi
    sc_line "$(sc_t install_note)"
    pacman -S --needed -- "${missing[@]}" || { sc_line "$(sc_t install_failed)"; return 1; }
}

sc_abort() {
    trap - INT TERM
    local module
    if [[ ${SC_RUN_ACTIVE:-0} == 1 ]]; then
        for module in "${SC_SELECTED[@]}"; do
            [[ ${SC_MODULE_STATUS[$module]} == running || ${SC_MODULE_STATUS[$module]} == not-run ]] && sc_module_set "$module" partial interrupted
        done
        sc_assess
        sc_save_report || printf '%s\n' "$(sc_t save_error)" >&2
        printf '\n'; sc_line "$(sc_t interrupted)"; sc_line "$(sc_t report): $SC_RUN_DIR/report.txt"
    fi
    exit 130
}

sc_scan_once() {
    local modules=$SC_SCAN module step=0
    [[ $modules != full ]] || modules=$SC_ALL_MODULES
    sc_reset "$modules"
    sc_prepare_run /var/log/seccheck || { sc_line "$(sc_t storage_error)"; return 73; }
    SC_RUN_ACTIVE=1
    trap sc_abort INT TERM
    sc_header; sc_line "$(sc_t wait)" "$SC_C_MUTED"
    if [[ $SC_SCAN == full || $SC_SCAN == aur-health ]]; then sc_line "$(sc_t health_network)" "$SC_C_MUTED"; fi
    for module in "${SC_SELECTED[@]}"; do
        ((step+=1)); printf '\n'
        sc_line "[$step/${#SC_SELECTED[@]}] $(sc_t scanning): $(sc_t "$module")" "$SC_C_PRIMARY"
        case $module in rkhunter) sc_run_rkhunter;; lynis) sc_run_lynis;; integrity) sc_run_integrity;; aur) sc_run_aur;; aur-health) sc_run_aur_health;; esac
        sc_line "$(sc_t "${SC_MODULE_STATUS[$module]}")" "$(sc_status_color "${SC_MODULE_STATUS[$module]}")"
        [[ -z ${SC_MODULE_REASON[$module]} ]] || sc_line "$(sc_t "${SC_MODULE_REASON[$module]}")" "$SC_C_MUTED"
    done
    sc_assess
    SC_RUN_ACTIVE=0
    trap - INT TERM
    sc_render_summary
    sc_save_report || { sc_line "$(sc_t save_error)"; return 73; }
    printf '\n'; sc_line "$(sc_t report): $SC_RUN_DIR/report.txt" "$SC_C_PRIMARY"
    sc_line "$(sc_t report_info)" "$SC_C_MUTED"
    ((SC_INCOMPLETE == 0)) || return 2
    ((SC_URGENT == 0 && SC_REVIEW == 0)) || return 1
    return 0
}

sc_run_requested() {
    local rc answer
    sc_require_scan_host || return $?
    if ((EUID != 0)); then
        if [[ ! -t 0 ]]; then printf '%s\n' "$(sc_t need_root)" >&2; return 77; fi
        sc_line "$(sc_t root)"; sc_elevate scan; return $?
    fi
    while :; do
        sc_scan_once; rc=$?
        [[ -t 0 && $rc -le 2 ]] || return "$rc"
        while :; do
            printf '\n'; sc_line "$(sc_t result_menu)"
            printf '  > '; IFS= read -r answer || return "$rc"
            case $answer in
                1) sc_render_details 20;;
                2) sc_render_report;;
                3) break;;
                0) return "$rc";;
                *) sc_line "$(sc_t invalid)";;
            esac
        done
    done
}

sc_menu() {
    local answer
    while :; do
        SC_DEMO=0; sc_header; sc_heading welcome
        sc_line "$(sc_t health_network)" "$SC_C_MUTED"; printf '\n'
        sc_line "1  $(sc_t menu_full)" "$SC_C_PRIMARY"
        sc_line "2  $(sc_t menu_rkhunter)"; sc_line "3  $(sc_t menu_lynis)"
        sc_line "4  $(sc_t menu_integrity)"; sc_line "5  $(sc_t menu_aur)"
        printf '\n'; sc_line "6  $(sc_t menu_deps)"; sc_line "7  $(sc_t menu_update)"
        sc_line "8  $(sc_t menu_demo)"; sc_line "9  $(sc_t aur-health)"; sc_line "0  $(sc_t exit)"
        printf '\n  %s > ' "$(sc_t choose)"; IFS= read -r answer || return 0
        case $answer in
            1) SC_SCAN=full; sc_run_requested;;
            2) SC_SCAN=rkhunter; sc_run_requested;;
            3) SC_SCAN=lynis; sc_run_requested;;
            4) SC_SCAN=integrity; sc_run_requested;;
            5) SC_SCAN=aur; sc_run_requested;;
            6) sc_dependencies;;
            7) sc_update_action;;
            8) SC_DEMO=1; sc_demo review;;
            9) SC_SCAN=aur-health; sc_run_requested;;
            0) return 0;;
            *) sc_line "$(sc_t invalid)";;
        esac
    done
}

sc_update_action() {
    sc_require_scan_host || return $?
    if ((EUID != 0)); then sc_line "$(sc_t root)"; sc_elevate update; return $?; fi
    sc_prepare_run /var/log/seccheck || { sc_line "$(sc_t storage_error)"; return 73; }
    sc_update_signatures
    local rc=$?
    sc_line "$(sc_t report): $SC_RUN_DIR"
    return "$rc"
}

sc_main() {
    if ((BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4))); then
        printf 'SecCheck requires Bash 4.4+.\n' >&2; return 64
    fi
    set -o pipefail
    umask 077
    sc_parse_args "$@" || { printf 'SecCheck: invalid arguments / argomenti non validi. --help\n' >&2; return 64; }
    case $SC_ACTION in help) sc_help; return 0;; version) printf 'SecCheck %s\n' "$SC_VERSION"; return 0;; esac
    if [[ -z $SC_LANG ]]; then
        if [[ -t 0 ]]; then sc_choose_language || return 0
        else printf '%s\n' "$(sc_t language_needed)" >&2; return 64; fi
    fi
    sc_ui_init
    if ((SC_DEMO)); then sc_demo "$SC_SCENARIO"; return 0; fi
    case $SC_ACTION in install) sc_dependencies; return $?;; update) sc_update_action; return $?;; esac
    if [[ -n $SC_SCAN ]]; then sc_run_requested; return $?; fi
    [[ -t 0 ]] || { sc_help; return 64; }
    sc_menu
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then sc_main "$@"; fi

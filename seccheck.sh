#!/usr/bin/env bash
# SecCheck 2.0 — Klod Cripta — MIT
# Standalone, read-only security assistant for Arch Linux and derivatives.
# Sourcing this file defines functions only: no traps, privilege changes or I/O.

SC_VERSION=2.0.0
SC_ALL_MODULES='rkhunter lynis integrity aur-health'

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
    declare -ga SC_F_CHECK_KEY=() SC_F_CHECK_DETAIL=()
    declare -ga SC_D_MODULE=() SC_D_KEY=() SC_D_EVIDENCE=()
    declare -gA SC_MODULE_STATUS=() SC_MODULE_REASON=() SC_MODULE_RC=() SC_MODULE_VERSION=()
    declare -ga SC_SCOPE=()
    declare -ga SC_RKH_OPTIONAL=()
    SC_FOLLOWUPS_DONE=0 SC_FOLLOWUPS_ACTIVE=0 SC_FOLLOWUPS_INTERRUPTED=0
    local module
    for module in $SC_ALL_MODULES; do
        SC_MODULE_STATUS[$module]=not-run
        SC_MODULE_REASON[$module]=''
        SC_MODULE_RC[$module]=''
        SC_MODULE_VERSION[$module]=''
    done
    for module in ${1:-$SC_ALL_MODULES}; do
        case $module in rkhunter|lynis|integrity|aur-health) SC_SELECTED+=("$module");; *) return 2;; esac
    done
    SC_INCOMPLETE=1 SC_COMPLETED=0 SC_URGENT=0 SC_REVIEW=0 SC_SUGGESTIONS=0 SC_INFO=0
    SC_ASSESSMENT=unknown
    SC_HEALTH_NOTE=''
}

sc_module_set() {
    local module=$1 status=$2 reason=${3-}
    case $module in rkhunter|lynis|integrity|aur-health) ;; *) return 2;; esac
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
    case $module in rkhunter|lynis|integrity|aur-health) ;; *) return 2;; esac
    case $priority in urgent|review|suggestion|info) ;; *) return 2;; esac
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
    SC_F_CHECK_KEY+=('') SC_F_CHECK_DETAIL+=('')
}

sc_assess() {
    local module priority
    SC_COMPLETED=0 SC_INCOMPLETE=0 SC_URGENT=0 SC_REVIEW=0 SC_SUGGESTIONS=0 SC_INFO=0
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
            suggestion) ((SC_SUGGESTIONS+=1));; info) ((SC_INFO+=1));; esac
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

sc_rkh_finding() {
    local key=$1 priority=$2 object=$3 evidence=$4 i same
    # Display sanitization must never turn an unreadable source path into a
    # different, existing filesystem path that could receive a clean verdict.
    if [[ $object != "$(sc_text "$object")" ]]; then
        key=rkh_path_unreadable; object=''; SC_PARSE_UNKNOWN=1
    fi
    evidence=$(sc_text "$evidence")
    for ((i=0;i<${#SC_F_MODULE[@]};i++)); do
        [[ ${SC_F_MODULE[i]} == rkhunter && ${SC_F_OBJECT[i]} == "$object" ]] || continue
        same=0
        [[ ${SC_F_KEY[i]} == "$key" ]] && same=1
        if [[ -n $object && ( $key == rkh_script || $key == rkh_file_warning ) &&
              ( ${SC_F_KEY[i]} == rkh_script || ${SC_F_KEY[i]} == rkh_file_warning ) ]]; then same=1; fi
        ((same)) || continue
        # Generic warnings without an identity only merge identical evidence.
        [[ -n $object || ${SC_F_EVIDENCE[i]} == "$evidence" ]] || continue
        [[ $key != rkh_script ]] || SC_F_KEY[i]=$key
        if [[ ${SC_F_EVIDENCE[i]} != *"$evidence"* ]]; then SC_F_EVIDENCE[i]+=" | $evidence"; fi
        return 0
    done
    sc_add_finding rkhunter suspicious "$priority" unconfirmed "$object" "$key" "$evidence"
}

sc_rkh_optional_reasons() {
    local line pending='' optional=0
    local -a words
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line#\[??:??:??\] }
        read -r -a words <<< "$line"; line=${words[*]}
        [[ -n $line ]] || continue
        optional=0
        case "$pending|$line" in
            "Running skdet command [ Skipped ]|Info: Unable to find the 'skdet' command"| \
            'Checking for software intrusions [ Skipped ]|Info: Check skipped - tripwire not installed'| \
            'Checking for missing log files [ Skipped ]|Info: No missing log file names configured.'| \
            'Checking for empty log files [ Skipped ]|Info: No empty log file names configured.'| \
            "Checking for enabled inetd services [ Skipped ]|Info: Check skipped - file '"*"' does not exist."| \
            "Checking for enabled xinetd services [ Skipped ]|Info: Check skipped - file '"*"' does not exist.") optional=1;;
        esac
        if ((optional)); then
            SC_RKH_OPTIONAL+=("$pending")
            sc_add_diagnostic rkhunter rkh_optional "$pending: $line"
        fi
        pending=$line
    done < "$1"
}

sc_parse_rkhunter() {
    local line lower key priority object normalized description hidden_kind prerequisite=0 optional candidate
    local -a words
    local script_re="^The command '(/[^']+)' has been replaced by a script:"
    local script_marker="' has been replaced by a script:" hidden_separator=': '
    local hidden_re='^Hidden (file|directory) found: (/.+)$'
    local file_re='^(/[^[:space:]]+)[[:blank:]]+\[ *Warning *\]$'
    SC_PARSE_UNKNOWN=0
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line#\[??:??:??\] }
        line=${line#"${line%%[![:space:]]*}"}
        line=${line%"${line##*[![:space:]]}"}
        lower=${line,,}
        if ((prerequisite)); then
            case $line in
                'The file of stored file properties (rkhunter.dat) does not exist,'*| \
                'The file of stored file properties (rkhunter.dat) is empty,'*)
                    sc_add_diagnostic rkhunter rkh_baseline_missing "$line";;
                "Unable to find the '"*' command - all '*|'All file '*'checks '*| \
                "Unable to find 'prelink' command."|"No output from the '"*' command - all '*| \
                "The '"*' command has been disabled - all '*| \
                'The current hash function '*|'The local host configuration or operating system has changed.'| \
                'This system uses prelinking,'*|'Libsafe was found,'*)
                    sc_add_diagnostic rkhunter rkh_prerequisite_detail "$line";;
            esac
            [[ $line != *' [ '* && $line != 'Info: Starting test '* ]] || prerequisite=0
        fi
        # Examine findings before descriptive prefixes; [ Warning ] is significant.
        if [[ $lower == *warning:* || $lower == *'[ warning ]'* || $lower == *'[warning]'* || \
              $lower == *'[ infected ]'* || $lower == *'infected file'* ]]; then
            SC_RKH_WARNINGS=$((${SC_RKH_WARNINGS:-0}+1))
            key=rkh_warning priority=review object=''
            normalized=${line#Warning: }
            # Only recognized message prefixes select explanatory follow-ups or
            # diagnostics; wording embedded in a filename must not select SSH.
            case ${normalized,,} in
                *'possible rootkit'*|*'rootkit found'*|*'infected file'*|*'[ infected ]'*)
                    key=rkh_signature; priority=urgent;;
                *'properties have changed'*|*'hash value'*|*'hash changed'*) key=rkh_properties;;
                'checking for prerequisites '* )
                    prerequisite=1; SC_PARSE_UNKNOWN=1
                    sc_add_diagnostic rkhunter rkh_prerequisite "$normalized"; continue;;
                "warning! it is the users responsibility to ensure that when the '--propupd' option"*)
                    sc_add_diagnostic rkhunter rkh_baseline_notice "$normalized"; continue;;
                'checking if ssh root access is allowed '*|"the ssh configuration option 'permitrootlogin' "*)
                    key=rkh_ssh_root; object=PermitRootLogin;;
                'checking if ssh protocol v1 is allowed '*|"the ssh configuration option 'protocol' "*)
                    key=rkh_ssh_protocol; object=Protocol;;
                'checking for hidden files and directories '*) key=rkh_hidden_summary; object='hidden-files';;
                'checking /dev for suspicious file types '*|'suspicious file types found in /dev:')
                    key=rkh_dev; object=/dev;;
            esac
            if [[ $key == rkh_warning ]]; then
                if [[ $normalized =~ $script_re ]]; then
                    key=rkh_script; object=${BASH_REMATCH[1]}
                    description=${normalized#*"$script_marker"}
                    if [[ $description == *"$script_marker"* ]]; then
                        key=rkh_path_unreadable; object=''; SC_PARSE_UNKNOWN=1
                    fi
                elif [[ $normalized =~ $hidden_re ]]; then
                    hidden_kind=${BASH_REMATCH[1]}; object=${BASH_REMATCH[2]}
                    if [[ $hidden_kind == directory ]]; then
                        key=rkh_hidden_directory
                    else
                        key=rkh_hidden_file; description=${object#*"$hidden_separator"}
                        # Plain text cannot disambiguate a filename containing
                        # the same separator as the file-type description.
                        if [[ $object != *"$hidden_separator"* || $description == *"$hidden_separator"* ]]; then
                            key=rkh_path_unreadable; object=''; SC_PARSE_UNKNOWN=1
                        else object=${object%%"$hidden_separator"*}; fi
                    fi
                elif [[ $normalized =~ $file_re ]]; then key=rkh_file_warning; object=${BASH_REMATCH[1]}; fi
            fi
            # Only the specific file-warning forms above authorize file lookups.
            sc_rkh_finding "$key" "$priority" "$object" "$normalized"
        fi
        if [[ $lower == *'test skipped'* || $lower == *'skipped due to'* || $lower == *'[ skipped ]'* ]]; then
            read -r -a words <<< "$line"
            optional=0
            for candidate in "${SC_RKH_OPTIONAL[@]}"; do
                [[ $candidate != "${words[*]}" ]] || optional=1
            done
            if ((optional == 0)); then
                SC_PARSE_UNKNOWN=1
                sc_add_diagnostic rkhunter rkh_skipped "${words[*]}"
            fi
        fi
    done < "$1"
}

sc_rkh_check_file() {
    local i=$1 object=${SC_F_OBJECT[$1]} prefix="$SC_RUN_DIR/rkh-context.$1"
    local line field value package='' recorded='' digest='' actual='' size rc
    local files=0 owners=0 modes=0 types=0 uids=0 groups=0 hashes=0 metadata=0
    SC_F_CHECK_KEY[i]=rkh_file_unknown
    SC_F_CHECK_DETAIL[i]=''
    if ! command -v pacfile >/dev/null; then SC_F_CHECK_KEY[i]=rkh_file_tool_missing; return; fi
    if [[ $object != /* || ! -f $object || -L $object ]]; then
        SC_F_CHECK_KEY[i]=rkh_file_nonregular; return
    fi
    size=$(timeout 5 stat -c '%s' -- "$object" 2>/dev/null) || return
    if [[ ! $size =~ ^[0-9]{1,12}$ ]] || ((size > 67108864)); then
        SC_F_CHECK_KEY[i]=rkh_context_limit; return
    fi
    sc_capture "$prefix.pacfile" "$prefix.stderr" 20 pacfile --check -- "$object"
    rc=$?
    SC_F_CHECK_DETAIL[i]="log=rkh-context.$i.pacfile / rkh-context.$i.stderr"
    ((rc == 0)) && [[ ! -s $prefix.stderr ]] || return
    while IFS= read -r line || [[ -n $line ]]; do
        if [[ $line == "no package owns '$object'" ]]; then SC_F_CHECK_KEY[i]=rkh_file_unowned; return; fi
        field=${line%%:*}; value=${line#*:}; value=${value#"${value%%[![:space:]]*}"}
        case $field in
            file) ((files+=1)); recorded=$value;;
            owner)
                if [[ $value =~ ^[A-Za-z0-9@_+.-]+$ ]]; then ((owners+=1)); package=$value
                elif [[ $value =~ ^[0-9]+/ ]]; then ((uids+=1)); [[ $value != *' on filesystem)' ]] || metadata=1; fi;;
            mode) ((modes+=1)); [[ $value =~ ^[0-7]{3,4}$ ]] || metadata=1;;
            type) ((types+=1)); [[ $value == file ]] || metadata=1;;
            group) [[ $value =~ ^[0-9]+/ ]] && ((groups+=1)); [[ $value != *' on filesystem)' ]] || metadata=1;;
            sha256)
                ((hashes+=1)); [[ $value =~ ^([0-9a-f]{64})($|[[:space:]]) ]] && digest=${BASH_REMATCH[1]};;
        esac
    done < "$prefix.pacfile"
    # Exit zero alone is insufficient: require one exact file, its owner, MTREE
    # properties and a SHA-256, then hash the actual regular file ourselves.
    ((files == 1 && owners == 1 && modes == 1 && types == 1 && uids == 1 && groups == 1 && hashes == 1)) || return
    [[ $recorded == "${object#/}" && -n $digest ]] || return
    sc_capture "$prefix.sha256" "$prefix.sha256.stderr" 5 sha256sum -- "$object"
    rc=$?
    ((rc == 0)) && [[ ! -s $prefix.sha256.stderr ]] || return
    read -r actual _ < "$prefix.sha256"
    [[ $actual =~ ^[0-9a-f]{64}$ ]] || return
    SC_F_CHECK_DETAIL[i]="$(sc_t package): $package; log=rkh-context.$i.pacfile / rkh-context.$i.sha256"
    if [[ $actual != "$digest" ]]; then SC_F_CHECK_KEY[i]=rkh_file_changed
    elif ((metadata)); then SC_F_CHECK_KEY[i]=rkh_file_metadata
    else SC_F_CHECK_KEY[i]=rkh_file_match; SC_F_PRIORITY[i]=info; SC_F_CONFIDENCE[i]=observation; fi
}

sc_rkh_ssh_evidence() {
    local i=$1 command=$2 rc=$3 prefix=${4:-"$SC_RUN_DIR/rkh-context.$1"} excerpt
    # Show a short, inert excerpt; the full original streams stay in the report directory.
    excerpt=$(timeout 2 head -c 320 -- "$prefix.stderr" 2>/dev/null)
    [[ -n $excerpt ]] || excerpt=$(timeout 2 head -c 320 -- "$prefix.ssh" 2>/dev/null)
    SC_F_CHECK_DETAIL[i]="$command: exit=$rc; $(sc_text "$excerpt")"
}

sc_rkh_check_ssh() {
    local i=$1 prefix="$SC_RUN_DIR/rkh-context.$1" value='' line rc major minor count=0 j executable resolved other guard_started=$SECONDS
    local query=-T error_size
    SC_F_CHECK_KEY[i]=rkh_ssh_unknown
    SC_F_CHECK_DETAIL[i]="$(sc_t rkh_ssh_not_started)"
    executable=$(command -v sshd) || return
    resolved=$(timeout 5 readlink -f -- "$executable") || return
    # Do not launch an SSH binary which this scan has left under suspicion,
    # including a finding reached through a different symlink to that binary.
    for j in "${!SC_F_MODULE[@]}"; do
        ((SECONDS-guard_started < 10)) || return
        [[ ${SC_F_PRIORITY[j]} == urgent || ${SC_F_PRIORITY[j]} == review ]] || continue
        [[ ${SC_F_OBJECT[j]} == /* ]] || continue
        other=$(timeout 5 readlink -f -- "${SC_F_OBJECT[j]}" 2>/dev/null) || return
        if [[ $other == "$resolved" ]]; then
            SC_F_CHECK_KEY[i]=rkh_ssh_flagged; return
        fi
    done
    SC_F_CHECK_DETAIL[i]="log=rkh-context.$i.ssh / rkh-context.$i.stderr"
    if [[ ${SC_F_KEY[i]} == rkh_ssh_root ]]; then
        sc_capture "$prefix.ssh" "$prefix.stderr" 10 sshd -T
        rc=$?
        sc_rkh_ssh_evidence "$i" 'sshd -T' "$rc"
        if ((rc == 1)); then
            error_size=$(timeout 2 stat -c '%s' -- "$prefix.stderr") || return
            # Never treat a truncated diagnostic excerpt as the complete error.
            ((error_size <= 321)) || return
            line=$(timeout 2 head -c 321 -- "$prefix.stderr") || return
            line=${line%$'\r'}
            # OpenSSH >= 9.3 can read settings without loading private host keys.
            # Retry only this exact failure; retain both attempts and never create keys.
            if [[ $line == 'sshd: no hostkeys available -- exiting.' ]]; then
                sc_add_diagnostic rkhunter rkh_ssh_hostkeys "$line"
                prefix+=.config; query=-G
                sc_capture "$prefix.ssh" "$prefix.stderr" 10 sshd -G
                rc=$?
                sc_rkh_ssh_evidence "$i" 'sshd -G' "$rc" "$prefix"
            fi
        fi
        ((rc == 0)) && [[ ! -s $prefix.stderr ]] || return
        while IFS= read -r line; do
            if [[ $line == 'permitrootlogin '* ]]; then value=${line#* }; ((count+=1)); fi
        done < "$prefix.ssh"
        ((count == 1)) || return
        case $value in
            yes) SC_F_CHECK_KEY[i]=rkh_ssh_allowed;;
            no) SC_F_CHECK_KEY[i]=rkh_ssh_disabled; SC_F_PRIORITY[i]=suggestion;;
            prohibit-password|without-password) SC_F_CHECK_KEY[i]=rkh_ssh_keys; SC_F_PRIORITY[i]=suggestion;;
            forced-commands-only) SC_F_CHECK_KEY[i]=rkh_ssh_commands; SC_F_PRIORITY[i]=suggestion;;
            *) return;;
        esac
        SC_F_KIND[i]=hardening
        SC_F_CONFIDENCE[i]=observation
        SC_F_CHECK_DETAIL[i]="sshd $query: PermitRootLogin=$value; log=${prefix##*/}.ssh"
    else
        sc_capture "$prefix.ssh" "$prefix.stderr" 10 sshd -V
        rc=$?
        sc_rkh_ssh_evidence "$i" 'sshd -V' "$rc"
        ((rc == 0)) || return
        while IFS= read -r line || [[ -n $line ]]; do
            if [[ $line =~ ^OpenSSH_([0-9]{1,3})\.([0-9]{1,3})(p[0-9]+)?([,[:space:]]|$) ]]; then
                major=${BASH_REMATCH[1]}; minor=${BASH_REMATCH[2]}
                if ((10#$major > 7 || (10#$major == 7 && 10#$minor >= 6))); then
                    SC_F_CHECK_KEY[i]=rkh_ssh_modern; SC_F_PRIORITY[i]=info
                    SC_F_CONFIDENCE[i]=observation; SC_F_CHECK_DETAIL[i]="$(sc_text "$line"); sshd -V"; return
                fi
            fi
        done < <(cat -- "$prefix.ssh" "$prefix.stderr")
    fi
}

sc_interpret_rkhunter() {
    local i hidden=0 name checked=0 started=$SECONDS
    SC_RKH_CONTEXT_PARTIAL=0
    for name in "${SC_F_KEY[@]}"; do
        [[ $name == rkh_hidden_file || $name == rkh_hidden_directory ]] && hidden=1
    done
    if ((hidden)); then
        for i in "${!SC_F_KEY[@]}"; do
            [[ ${SC_F_KEY[i]} == rkh_hidden_summary ]] || continue
            for name in SC_F_MODULE SC_F_KIND SC_F_PRIORITY SC_F_CONFIDENCE SC_F_OBJECT SC_F_KEY SC_F_EVIDENCE SC_F_CHECK_KEY SC_F_CHECK_DETAIL; do
                local -n values=$name
                unset 'values[i]'
            done
        done
        for name in SC_F_MODULE SC_F_KIND SC_F_PRIORITY SC_F_CONFIDENCE SC_F_OBJECT SC_F_KEY SC_F_EVIDENCE SC_F_CHECK_KEY SC_F_CHECK_DETAIL; do
            local -n values=$name
            values=("${values[@]}")
        done
    fi
    for ((i=0;i<${#SC_F_MODULE[@]};i++)); do
        [[ ${SC_F_MODULE[i]} == rkhunter ]] || continue
        case ${SC_F_KEY[i]} in
            rkh_hidden_directory)
                SC_F_CHECK_KEY[i]=rkh_file_nonregular; SC_RKH_CONTEXT_PARTIAL=1; continue;;
            rkh_script|rkh_hidden_file|rkh_file_warning|rkh_ssh_root|rkh_ssh_protocol) ;;
            *) continue;;
        esac
        if ((checked >= 40 || SECONDS-started >= 180)); then
            SC_F_CHECK_KEY[i]=rkh_context_limit; SC_RKH_CONTEXT_PARTIAL=1; continue
        fi
        ((checked+=1))
        case ${SC_F_KEY[i]} in rkh_ssh_*) sc_rkh_check_ssh "$i";; *) sc_rkh_check_file "$i";; esac
        case ${SC_F_CHECK_KEY[i]} in
            rkh_file_unknown|rkh_file_tool_missing|rkh_file_nonregular|rkh_context_limit|rkh_ssh_unknown|rkh_ssh_flagged)
                SC_RKH_CONTEXT_PARTIAL=1;;
        esac
    done
    SC_SCOPE+=('rkhunter context: up to 40 checks / 180s plus one in-flight check; regular files <=64MiB; exact pacfile MTREE record + SHA-256; local package records do not prove trusted origin. SSH uses default configuration, not every Match context or running daemon.')
}

sc_run_rkhunter() {
    if ! command -v rkhunter >/dev/null; then sc_module_set rkhunter skipped missing_rkhunter; return 0; fi
    sc_module_set rkhunter running ''
    SC_MODULE_VERSION[rkhunter]=$(sc_version rkhunter --version)
    local out="$SC_RUN_DIR/rkhunter.stdout" err="$SC_RUN_DIR/rkhunter.stderr"
    local raw="$SC_RUN_DIR/rkhunter.log" parsed rc line errors=0 unknown=0 reason
    SC_RKH_WARNINGS=0
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
    sc_rkh_optional_reasons "$parsed"
    [[ $parsed == "$out" ]] || sc_rkh_optional_reasons "$out"
    sc_parse_rkhunter "$parsed"
    unknown=$SC_PARSE_UNKNOWN
    # Both streams can contain unique evidence. Neither may erase uncertainty.
    if [[ $parsed != "$out" ]]; then
        sc_parse_rkhunter "$out"
        SC_PARSE_UNKNOWN=$((SC_PARSE_UNKNOWN || unknown))
    fi
    if ((rc <= 1)) && grep -Eq 'System checks summary|Info: End date is' "$parsed" "$out"; then
        if ((rc == 1 && SC_RKH_WARNINGS == 0)); then
            errors=1; sc_add_diagnostic rkhunter rkh_unparsed 'exit=1; rkhunter.log / rkhunter.stdout'
        fi
        if ((errors || SC_PARSE_UNKNOWN)); then
            reason=rkh_limited
            for line in "${SC_D_KEY[@]}"; do
                case $line in rkh_prerequisite) reason=$line;; esac
            done
            for line in "${SC_D_KEY[@]}"; do
                case $line in rkh_baseline_missing|rkh_regex) reason=$line;; esac
            done
            sc_module_set rkhunter partial "$reason"
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
        if [[ $id == KRNL-5830 && $description == 'Reboot of system is most likely needed' ]]; then
            key=lynis_reboot
        fi
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
    local line normalized object detail key message mode=${2:-pacman}
    local re_pacman='^[^:]+: (/.+) \((.*)\)$'
    local re_paccheck="^[^:]+: '(.+)' (.*)$"
    SC_PARSE_SEEN=0 SC_PARSE_UNKNOWN=0 SC_PARSE_ERRORS=0
    while IFS= read -r line || [[ -n $line ]]; do
        [[ -z $line ]] && continue
        object='' detail=''
        normalized=${line#warning: }; normalized=${normalized#backup file: }
        if [[ $normalized == 'error: '* ]]; then
            SC_PARSE_ERRORS=1; sc_add_diagnostic integrity integrity_tool_error "$mode: $line"; continue
        fi
        if [[ $mode == pacman && $normalized =~ $re_pacman ]]; then
            object=${BASH_REMATCH[1]}; detail=${BASH_REMATCH[2]}
        elif [[ $mode == paccheck && $normalized =~ $re_paccheck ]]; then
            object=${BASH_REMATCH[1]}; detail=${BASH_REMATCH[2]}
        elif [[ $line =~ ^[^:]+:\ [0-9]+\ total\ files?,\ [0-9]+\ altered\ files?$ || \
                $line == *': all files match mtree sha256sums' || $line == *': all files present and unmodified' ]]; then
            ((SC_PARSE_SEEN+=1)); continue
        else
            message=${normalized#*: }
            case ${message,,} in
                'mtree data not available ('*|'error reading mtree data ('*)
                    SC_PARSE_ERRORS=1; sc_add_diagnostic integrity integrity_mtree "$mode: $line"; continue;;
                'read error ('*)
                    SC_PARSE_ERRORS=1; sc_add_diagnostic integrity integrity_read_error "$mode: $line"; continue;;
            esac
            SC_PARSE_UNKNOWN=1; sc_add_diagnostic integrity integrity_unparsed "$mode: $line"
            continue
        fi
        ((SC_PARSE_SEEN+=1))
        # Classify the tool's reason, never words embedded in the pathname.
        case ${detail,,} in
            'permission denied'|'read error ('*)
                SC_PARSE_ERRORS=1; sc_add_diagnostic integrity integrity_read_error "$mode: $line"; continue;;
            'missing file'|'no such file or directory') key=integrity_missing;;
            'sha256sum mismatch ('*|'sha256 checksum mismatch') key=integrity_content;;
            'permissions mismatch'|'permission mismatch ('*) key=integrity_permissions;;
            'uid mismatch'|'gid mismatch'|'uid mismatch ('*|'gid mismatch ('*) key=integrity_owner;;
            'modification time mismatch'|'modification time mismatch ('*) key=integrity_time;;
            'size mismatch'|'size mismatch ('*|'file type mismatch'|'symbolic link path mismatch') key=integrity_metadata;;
            *) SC_PARSE_UNKNOWN=1
                sc_add_diagnostic integrity integrity_unparsed "$mode: $line"; continue;;
        esac
        if [[ $object != "$(sc_text "$object")" ]]; then
            SC_PARSE_UNKNOWN=1
            sc_add_finding integrity integrity review unconfirmed '' integrity_path_unreadable "$mode: $line"
            continue
        fi
        sc_add_finding integrity integrity review observation "$object" "$key" "$mode: $line"
    done < "$1"
}

sc_integrity_complete() {
    local tool=$1 rc=$2 before=$3 partial=0
    if ((rc > 1)); then
        partial=1
        case $rc in
            124|137) sc_add_diagnostic integrity integrity_timeout "$tool: exit=$rc";;
            *) sc_add_diagnostic integrity integrity_exit_error "$tool: exit=$rc";;
        esac
    fi
    if ((SC_PARSE_SEEN == 0)); then
        partial=1; sc_add_diagnostic integrity integrity_no_results "$tool: exit=$rc"
    fi
    if ((SC_PARSE_UNKNOWN || SC_PARSE_ERRORS)); then partial=1
    elif ((rc == 1 && ${#SC_F_MODULE[@]} == before)); then
        partial=1; sc_add_diagnostic integrity integrity_exit_unexplained "$tool: exit=$rc"
    fi
    ((partial == 0))
}

sc_run_integrity() {
    if ! command -v pacman >/dev/null; then sc_module_set integrity skipped missing_pacman; return 0; fi
    sc_module_set integrity running ''
    SC_MODULE_VERSION[integrity]=$(sc_version pacman --version)
    local rc partial=0 out="$SC_RUN_DIR/pacman.stdout" err="$SC_RUN_DIR/pacman.stderr"
    local before=${#SC_F_MODULE[@]}
    sc_capture "$out" "$err" 1200 pacman -Qkk
    rc=$?; SC_MODULE_RC[integrity]="pacman=$rc"
    cat -- "$out" "$err" > "$SC_RUN_DIR/pacman-combined.txt"
    sc_parse_integrity "$SC_RUN_DIR/pacman-combined.txt" pacman
    sc_integrity_complete pacman "$rc" "$before" || partial=1
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
    sc_integrity_complete paccheck "$rc" "$before" || partial=1
    if ((partial)); then sc_module_set integrity partial integrity_incomplete
    else sc_module_set integrity completed ''; fi
    SC_SCOPE+=("integrity: pacman metadata + paccheck SHA-256 against local package MTREE; includes backup files; excludes NoExtract/NoUpgrade")
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
from email.utils import parsedate_to_datetime
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
next_request = started
requests_stopped = False
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

def http_response(headers_path):
    status, headers = 0, {}
    if not headers_path.exists(): return status, headers
    with headers_path.open('rb') as stream: raw = stream.read(65537)
    if len(raw) > 65536: raise ValueError('AUR response headers exceed 64 KiB')
    for line in raw.decode('iso-8859-1').splitlines():
        match = re.match(r'HTTP/\S+\s+(\d{3})(?:\s|$)', line)
        if match:
            # A proxy CONNECT response can precede the actual HTTP response.
            status, headers = int(match[1]), {}
        elif ':' in line:
            key, value = line.split(':', 1)
            headers[key.lower().strip()] = value.strip()
    return status, headers

def retry_delay(value):
    # Respect Retry-After seconds and HTTP dates. Missing/invalid values use a
    # conservative fallback; never shorten a long server-requested delay.
    if value.isascii() and value.isdecimal():
        digits = value.lstrip('0') or '0'
        # A huge valid integer still requests a long wait; do not let Python's
        # integer conversion limit turn it into an ignored Retry-After value.
        if len(digits) > 9: return float('inf')
        return max(5, int(digits))
    try:
        stamp = parsedate_to_datetime(value)
        if stamp.tzinfo is not None: return max(5, stamp.timestamp() - time.time())
    except (ValueError, TypeError, OverflowError):
        pass
    return 5

def fetch(url, stem):
    global next_request, requests_stopped
    if requests_stopped: raise RequestError('AUR requests stopped for this scan')
    delay = 0
    for attempt in range(2):
        wait = max(0, delay, next_request - time.monotonic())
        if time.monotonic() + wait + 23 > started + 260:
            requests_stopped = True
            diagnostics.append(('health_budget', 'request-budget=260s; URL=' + url))
            raise RequestError('request budget exhausted')
        if wait: time.sleep(wait)
        next_request = time.monotonic() + 1.1
        attempt_stem = stem if attempt == 0 else stem + '.retry1'
        (run / (attempt_stem + '.request.txt')).write_text(url + '\n')
        headers_path = run / (attempt_stem + '.headers')
        try:
            result = subprocess.run(['curl', '--disable', '--proto', '=https', '--tlsv1.2',
                '--fail', '--silent', '--show-error', '--connect-timeout', '5', '--max-time', '20',
                '--max-filesize', '2097152', '--dump-header', str(headers_path),
                '--header', 'Accept-Language: en-US',
                '--user-agent', 'SecCheck/2.0 (AUR maintenance check)', url],
                capture_output=True, timeout=23, env=dict(os.environ, LC_ALL='C'))
            output, errors, code = result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as error:
            output, errors, code = error.stdout or b'', error.stderr or b'', 28
            errors += b'\nSecCheck: curl exceeded the 23-second process deadline\n'
        (run / (attempt_stem + '.raw')).write_bytes(output[:2097152])
        (run / (attempt_stem + '.stderr')).write_bytes(errors[:65536])
        status, headers = http_response(headers_path)
        detail = 'curl=' + str(code) + '; HTTP=' + str(status) + '; URL=' + url + \
                 '; log=' + attempt_stem + '.stderr; ' + \
                 text(errors.decode('utf-8', errors='replace').strip())[:500]
        if status == 429:
            value = headers.get('retry-after', '')
            delay = retry_delay(value)
            detail += '; Retry-After=' + text(value or 'absent')[:256]
            # One retry at most. A long cooldown or another 429 stops all further
            # AUR requests in this run, including requests for other packages.
            if attempt == 0 and delay <= 30 and time.monotonic() + delay + 23 <= started + 260:
                notes.append('AUR HTTP 429: wait=' + str(delay) + 's; URL=' + url)
                continue
            requests_stopped = True
            diagnostics.append(('health_rate_limited', detail))
            raise RequestError(detail)
        if not code and len(output) <= 2097152:
            if attempt:
                diagnostics.append(('health_retry', 'URL=' + url + '; wait=' + str(delay) +
                                    's; logs=' + stem + '.stderr / ' + attempt_stem + '.raw'))
            return output.decode('utf-8')
        key = {5: 'health_dns', 6: 'health_dns', 7: 'health_connection', 22: 'health_http',
               28: 'health_timeout', 35: 'health_tls', 60: 'health_tls'}.get(code, 'health_fetch')
        if len(output) > 2097152: detail += '; response exceeds 2 MiB'
        diagnostics.append((key, detail))
        raise RequestError(detail)

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
    if len(observed) > 50:
        issue('health_many', 'AUR', 'AUR matches=' + str(len(observed)) + '; reminder-threshold=50', 'suggestion')
    (run / 'aur-health-observed.json').write_text(json.dumps(dict(observed_at=now, packages=observed), indent=2) + '\n')
    if not partial:
        # A complete snapshot is atomically replaced, never merged from a failed query.
        fd, temporary = tempfile.mkstemp(prefix='aur-maintainers.', suffix='.next', dir=state)
        with os.fdopen(fd, 'w') as stream:
            json.dump(dict(schema=1, observed_at=now, packages=current), stream, indent=2)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, baseline_path)
    notes.append('foreign=' + str(len(names)) + '; AUR observed=' + str(len(observed)) +
                 '; age-threshold=365 days; max-packages=2000; request-budget=260s; request-spacing=1.1s; max-429-retries=1; baseline=' +
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
        health_build) en="Read the PKGBUILD (build instructions), .install files and changes before installing or updating."; it="Prima di installare o aggiornare, leggi PKGBUILD (istruzioni di compilazione), file .install e modifiche.";;
        health_sources) en="Check download sources. If unsure, ask for help before running the build."; it="Verifica le fonti dei download. Se hai dubbi, chiedi aiuto prima di compilare.";;
        rkh_prerequisite_detail) en="Prerequisite failure reported by rkhunter:"; it="Causa segnalata da rkhunter:";;
        rkh_baseline_missing) en="rkhunter has no usable file baseline. Do not create one until the current files have been independently checked."; it="La base di confronto di rkhunter manca o è vuota. Va creata solo dopo aver verificato i file attuali.";;
        rkh_optional) en="Optional or unconfigured tests excluded from this scan:"; it="Test facoltativi o non configurati esclusi da questa scansione:";;
        rkh_optional_short) en="Optional tests excluded; reasons in the report."; it="Test facoltativi esclusi; motivi nel rapporto.";;
        followup_question) en="Would you like me to run the follow-up checks for you? [y/N]"; it="Vuoi che faccia io le verifiche del caso al posto tuo? [s/N]";;
        followups) en="ADDITIONAL CHECKS"; it="VERIFICHE AGGIUNTIVE";;
        followup_rootkit) en="Checking reported files and SSH settings..."; it="Verifico i file segnalati e le impostazioni SSH...";;
        followup_files) en="Comparing reported files with local package records..."; it="Confronto i file segnalati con i dati dei pacchetti...";;
        followup_manual) en="This finding cannot be resolved automatically. Follow the advice above or ask for help using the report."; it="Questa segnalazione richiede una valutazione. Segui il consiglio sopra o chiedi aiuto usando il rapporto.";;
        followup_pending) en="Still to assess"; it="Voci ancora da chiarire";;
        followup_group_note) en="File differences are grouped by path in Findings. Suggestions are separate."; it="Nei Dettagli le differenze sullo stesso file sono riunite. I consigli sono separati.";;
        grouped_findings) en="Warnings for this path"; it="Avvisi su questo percorso";;
        integrity_fields) en="Reported differences"; it="Differenze segnalate";;
        field_integrity_content) en="content"; it="contenuto";;
        field_integrity_permissions) en="permissions"; it="permessi";;
        field_integrity_owner) en="owner or group"; it="proprietario o gruppo";;
        field_integrity_time) en="modification time"; it="data di modifica";;
        field_integrity_metadata) en="size, type or link target"; it="dimensione, tipo o collegamento";;
        field_integrity_missing) en="missing file"; it="file assente";;
        followup_interrupted) en="Additional checks were interrupted. Unfinished findings remain open."; it="Verifiche aggiuntive interrotte. Gli avvisi non verificati restano aperti.";;
        rkh_ssh_flagged) en="The SSH executable has an unresolved warning. It was not run."; it="L’eseguibile SSH ha una segnalazione aperta. Non è stato avviato.";;
        followup_finished) en="Checks finished. Open Findings to see what remains and why."; it="Verifiche terminate. Nei Dettagli trovi ciò che resta da chiarire e perché.";;
        integrity_rechecked) en="The file now matches the local package content, permissions and ownership. The original difference is kept in the report."; it="Ora contenuto, permessi e proprietario coincidono con il pacchetto locale. La differenza iniziale resta nel rapporto.";;
        integrity_hash_only) en="Content matches the local package. This does not explain the original timestamp, size or path warning."; it="Il contenuto coincide con il pacchetto locale. La differenza iniziale di data, dimensione o percorso resta da chiarire.";;
        integrity_special) en="This is a directory, link or other nonregular path. Its current properties were read; the difference still needs assessment."; it="È una cartella, un collegamento o un altro tipo di file speciale. Ho letto le proprietà; la differenza resta da valutare.";;
        integrity_path_unreadable) en="The source path is ambiguous and cannot be checked automatically."; it="Il percorso nel log è ambiguo e non può essere verificato automaticamente.";;
        welcome) en='Choose what to check'; it="Scegli cosa controllare";;
        menu_scans) en='SCANS'; it="SCANSIONI";;
        menu_tools) en='TOOLS'; it="STRUMENTI";;
        full_includes) en='Runs all four checks: options 2, 3, 4 and 5.'; it="Esegue tutti e quattro i controlli: voci 2, 3, 4 e 5.";;
        tools_separate) en='Dependency installation, signature updates and the demo are separate actions.'; it="Installazione dipendenze, aggiornamento firme ed esempio sono azioni separate.";;
        menu_full) en='Full scan'; it="Scansione completa";;
        menu_rkhunter) en='Rootkit indicators'; it="Indicatori di rootkit";;
        menu_lynis) en='System configuration'; it="Configurazione del sistema";;
        menu_integrity) en='Installed package files'; it="File dei pacchetti installati";;
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
        clear) en='NO UNRESOLVED FINDINGS'; it="NESSUNA SEGNALAZIONE APERTA";;
        why_urgent) en="A strong warning needs expert investigation."; it="Un segnale importante richiede una verifica esperta.";;
        why_review) en="Some changes still need an explanation. This does not establish an infection."; it="Alcune modifiche restano da chiarire. Non significa che il PC sia infetto.";;
        why_advice) en="Maintenance or configuration can be improved."; it="Puoi migliorare manutenzione e configurazione.";;
        why_unknown) en="Some checks are missing. See the reason beside each module."; it="Mancano alcuni controlli. La causa è indicata accanto al modulo.";;
        why_clear) en="No unresolved findings in the checks performed."; it="Nessuna segnalazione aperta nei controlli eseguiti.";;
        coverage) en="CHECKS PERFORMED"; it="CONTROLLI ESEGUITI";;
        complete) en="COMPLETED"; it="COMPLETATI";;
        incomplete) en='INCOMPLETE'; it="INCOMPLETA";;
        scope_selected) en="Selected modules only."; it="Solo i controlli scelti.";;
        scope_full) en='All four modules selected. Each has its own detection limits.'; it="Selezionati tutti e quattro i moduli. Ogni controllo ha limiti propri.";;
        coverage_note) en="Completed checks, not a security score."; it="Controlli conclusi, non un punteggio di sicurezza.";;
        module) en='Module'; it="Modulo";;
        status) en='Status'; it="Stato";;
        findings) en='Items'; it="Voci";;
        rkhunter) en='Rootkit / rkhunter'; it="Rootkit / rkhunter";;
        lynis) en='Configuration / Lynis'; it="Configurazione / Lynis";;
        integrity) en='Package integrity'; it="Integrità pacchetti";;
        aur-health) en='AUR / Project health'; it="AUR / Manutenzione";;
        health_network) en="AUR maintenance uses the internet and sends package names to AUR. --offline skips it."; it="La manutenzione AUR usa internet e invia ad AUR i nomi dei pacchetti. --offline la salta.";;
        health_guide) en='AUR: INFORMED USE'; it="AUR: USO CONSAPEVOLE";;
        health_habits) en="Install only what you need."; it="Installa solo ciò che ti serve.";;
        health_limits) en="Good maintenance does not guarantee safe code."; it="Una buona manutenzione non garantisce che il codice sia sicuro.";;
        health_many) en="Over 50 AUR packages: do you still need them all? Check dependencies before removing any. 50 is a reminder, not a security threshold."; it="Oltre 50 pacchetti AUR: ti servono tutti? Controlla le dipendenze prima di rimuoverli. 50 è un promemoria, non un limite di sicurezza.";;
        confidence_explained) en="Explained by additional checks"; it="Chiarito dalle verifiche aggiuntive";;
        offline) en='Online AUR metadata skipped (--offline).'; it="Dati AUR online non consultati (--offline).";;
        missing_health_tools) en='AUR metadata requires python, curl, pacman and vercmp.'; it="I dati AUR richiedono python, curl, pacman e vercmp.";;
        health_state) en='Cannot safely open the private AUR comparison history.'; it="Impossibile aprire in sicurezza lo storico privato dei confronti AUR.";;
        health_unavailable) en="Some AUR data is unavailable. Try again later; details are in the report."; it="Alcuni dati AUR non sono disponibili. Riprova più tardi; dettagli nel rapporto.";;
        health_no_baseline) en='No AUR baseline was created: this first scan was incomplete. Maintainer changes can be compared after a complete snapshot is saved.'; it="La prima scansione AUR è incompleta: non è stata creata una base per i confronti. Per seguire i cambi di maintainer serve prima una scansione completa.";;
        health_preserved) en='The previous AUR baseline was preserved. This incomplete scan did not replace the history used to compare maintainers.'; it="La precedente base AUR è stata conservata. Questa scansione incompleta non ha sostituito lo storico usato per confrontare i maintainer.";;
        health_not_updated) en='The AUR baseline update could not be confirmed. Resolve the history or execution error before comparing maintainer changes.'; it="Non è stato possibile confermare il salvataggio della base AUR. Risolvi il problema dello storico o dell'esecuzione prima di confrontare i cambi di maintainer.";;
        health_dns) en='The AUR address could not be resolved. Check DNS and the connection; this does not mean a package was removed.'; it="Impossibile risolvere l'indirizzo di AUR. Controlla DNS e connessione; questo errore non significa che un pacchetto sia stato rimosso.";;
        health_connection) en='The connection to AUR failed. Check connectivity and any proxy settings, then repeat this module.'; it="Connessione ad AUR non riuscita. Controlla la rete e le eventuali impostazioni proxy, poi ripeti questo modulo.";;
        health_timeout) en='An AUR request timed out. Repeat this module when the service is reachable; its error log is listed below.'; it="Una richiesta AUR ha superato il tempo disponibile. Ripeti questo modulo quando il servizio è raggiungibile; sotto è indicato il log dell'errore.";;
        health_http) en='AUR returned an HTTP error. Read the code below: 429 means too many requests; 5xx indicates a server error. Repeat the module later.'; it="AUR ha risposto con un errore HTTP. Leggi il codice qui sotto: 429 indica troppe richieste; 5xx un errore del server. Ripeti il modulo più tardi.";;
        health_rate_limited) en='Requests stopped: AUR is limiting access (HTTP 429). The requested wait is too long for this scan, or one retry was insufficient. Repeat this module later; no package or maintainer removal is inferred from this error.'; it="Richieste interrotte: AUR sta limitando gli accessi (HTTP 429). L'attesa richiesta supera il limite di questa scansione oppure un nuovo tentativo non è bastato. Ripeti questo modulo più tardi; questo errore non indica la rimozione di pacchetti o maintainer.";;
        health_retry) en='AUR temporarily limited requests. SecCheck waited and the next attempt succeeded:'; it="AUR ha limitato temporaneamente le richieste. SecCheck ha atteso e il tentativo successivo è riuscito:";;
        health_budget) en='The online time limit was reached. Remaining AUR requests were stopped and coverage is partial.'; it="È stato raggiunto il limite di tempo per i controlli online. Le richieste AUR rimanenti sono state interrotte e la copertura è parziale.";;
        health_tls) en='The secure AUR connection could not be verified. Check the clock, certificates and proxy; do not disable certificate checks.'; it="Impossibile verificare la connessione sicura ad AUR. Controlla orologio, certificati e proxy; mantieni attiva la verifica dei certificati.";;
        health_fetch) en='An AUR request failed. The URL, command exit code and original error below identify the failed operation.'; it="Una richiesta AUR è fallita. URL, codice di uscita ed errore originale qui sotto identificano l'operazione non riuscita.";;
        health_data_error) en='Some AUR data could not be read or validated. Unknown maintainer information is not treated as a removal.'; it="Alcuni dati AUR non sono leggibili o verificabili. Un maintainer non verificato non viene considerato rimosso.";;
        health_baseline) en='First AUR snapshot recorded. Earlier maintainer changes are unknown; comparison starts with the next successful AUR check (option 5 or a full scan).'; it="Registrata la prima fotografia AUR. I cambi di maintainer precedenti sono sconosciuti; il confronto inizia dal prossimo controllo AUR riuscito (voce 5 o scansione completa).";;
        health_compared) en='AUR maintainers compared with the preceding successful AUR check. Changes are observations, not evidence of malicious intent.'; it="Maintainer confrontati con il precedente controllo AUR riuscito. I cambi sono osservazioni, non prove di intenzioni malevole.";;
        health_orphan) en="No primary maintainer is listed. Check support or look for a maintained alternative. This is not the same as an unused dependency."; it="Manca un responsabile principale (maintainer). Verifica il supporto o valuta un’alternativa mantenuta. Non significa dipendenza inutilizzata.";;
        health_flagged) en="A user marked the build recipe out of date. Check the AUR page; this is not a confirmed vulnerability."; it="Un utente segnala che la ricetta non è aggiornata. Controlla la pagina AUR: non è una vulnerabilità confermata.";;
        health_upgrade) en="AUR lists a newer version. Read the build changes before updating; VCS versions can be dynamic."; it="AUR indica una versione più nuova. Leggi le modifiche prima di aggiornare; le versioni VCS possono essere dinamiche.";;
        health_inactive) en="The recipe has not changed for 365 days. This does not prove abandonment: check the original project."; it="La ricetta non cambia da almeno 365 giorni. Non significa abbandono: controlla l’attività del progetto originale.";;
        health_unlisted) en="No exact match in AUR. It may be a custom, renamed or removed package; check its origin."; it="Nessuna corrispondenza in AUR. Potrebbe essere un pacchetto personalizzato, rinominato o rimosso: controllane l’origine.";;
        health_removed) en="Previously found in AUR, now absent. Check for a rename, merge or removal."; it="Prima era presente in AUR, ora non risulta. Controlla se è stato rinominato, unito o rimosso.";;
        health_maintainer) en="The primary maintainer changed. Handovers can be legitimate; review recent build changes."; it="È cambiato il responsabile principale. Può essere un passaggio legittimo: leggi le ultime modifiche alla ricetta.";;
        health_co_added) en="New co-maintainers appeared. Review the handover and build changes; this alone is not a threat."; it="Sono stati aggiunti collaboratori alla manutenzione. Controlla passaggio di gestione e modifiche: da solo non è un allarme.";;
        health_co_removed) en="Some co-maintainers are no longer listed. Check whether the package still has support."; it="Alcuni collaboratori non risultano più presenti. Verifica che il pacchetto abbia ancora supporto.";;
        not-run) en='Not selected'; it="Non selezionato";;
        running) en='Running'; it="In corso";;
        completed) en='Completed'; it="Completato";;
        partial) en="Incomplete"; it="Da completare";;
        failed) en='Failed'; it="Fallito";;
        skipped) en='Unavailable'; it="Non disponibile";;
        missing_rkhunter) en='Install rkhunter to run this module.'; it="Installa rkhunter per eseguire questo modulo.";;
        missing_lynis) en='Install lynis to run this module.'; it="Installa lynis per eseguire questo modulo.";;
        missing_pacman) en='pacman is unavailable.'; it="pacman non disponibile.";;
        missing_paccheck) en="SHA-256 unavailable: install pacutils (menu 6), then repeat menu 4."; it="Manca pacutils: installalo dalla voce 6, poi ripeti la voce 4 per verificare il contenuto dei file.";;
        rkh_limited) en="Some rkhunter tests could not run. The report lists the causes."; it="Alcuni test di rkhunter non sono riusciti. Le cause sono nel rapporto.";;
        rkh_skipped) en='Tests not performed by rkhunter. They may require optional tools, services or different settings; this result does not cover them:'; it="Test non eseguiti da rkhunter. Possono dipendere da strumenti facoltativi, servizi o impostazioni; questo risultato non li copre:";;
        rkh_legacy_grep) en='Compatibility notice: rkhunter uses the obsolete egrep name, which still forwards to grep -E. This notice alone does not invalidate the scan:'; it="Avviso di compatibilità: rkhunter usa il nome obsoleto egrep, che richiama ancora grep -E. Questo avviso da solo non invalida la scansione:";;
        rkh_regex) en="rkhunter/grep compatibility problem: check distribution updates, then repeat menu 2."; it="Problema di compatibilità tra rkhunter e grep. Verifica gli aggiornamenti della distribuzione, poi ripeti la voce 2.";;
        rkh_unparsed) en='rkhunter returned a warning exit code, but no corresponding finding was recognized. Read the original logs before drawing conclusions:'; it="rkhunter ha restituito un codice di avviso, ma non è stata riconosciuta la segnalazione corrispondente. Leggi i log originali prima di trarre conclusioni:";;
        scanner_error) en='The scanner reported an execution or reading problem. Original message:'; it="Lo scanner ha segnalato un problema di esecuzione o lettura. Messaggio originale:";;
        diagnostics_more) en='Further diagnostic details are included in the full report (option 2).'; it="Altri dettagli diagnostici sono nel rapporto completo (voce 2).";;
        check_details) en='Warnings, read errors or an unknown output format reduced coverage. Read the raw logs.'; it="Avvisi, errori di lettura o un formato inatteso hanno limitato il controllo. Consulta i log originali.";;
        unfinished) en='The scanner did not report a normal completion.'; it="Lo scanner non ha comunicato una conclusione regolare.";;
        command_failed) en='The command failed without usable results.'; it="Il comando non ha prodotto risultati utilizzabili.";;
        no_report) en='The scanner did not produce a usable report.'; it="Lo scanner non ha prodotto un rapporto utilizzabile.";;
        interrupted) en='Interrupted by the user.'; it="Interrotto dall'utente.";;
        next) en='WHAT TO DO NEXT'; it="COSA FARE ADESSO";;
        next_urgent) en="Ask an expert to investigate the urgent findings before changing files."; it="Chiedi aiuto esperto per i segnali urgenti prima di modificare i file.";;
        next_review) en="Use the additional checks below. Unexplained changes remain in Findings."; it="Usa le verifiche aggiuntive qui sotto. Le modifiche ancora dubbie restano nei Dettagli.";;
        next_advice) en="Read each package or configuration suggestion."; it="Leggi i consigli nei Dettagli e valuta quelli utili al tuo computer.";;
        next_unknown) en="Resolve the listed missing checks, then repeat the scan."; it="Risolvi le cause indicate e ripeti i controlli mancanti.";;
        next_clear) en="Keep the system updated and review software before installing it."; it="Mantieni il sistema aggiornato e controlla il software prima di installarlo.";;
        incomplete_next) en='Also resolve the incomplete modules: the current result does not cover them fully.'; it="Completa anche i moduli rimasti parziali: il risultato attuale non li copre interamente.";;
        signals) en='ITEMS BY PRIORITY'; it="VOCI PER PRIORITÀ";;
        priority_urgent) en='Urgent'; it="Urgenti";;
        priority_review) en='To review'; it="Da verificare";;
        priority_suggestion) en='Suggestions'; it="Consigli";;
        count_note) en="File differences are grouped by path. These counts do not indicate infections."; it="Le differenze sullo stesso file sono riunite. Questi numeri non indicano infezioni.";;
        details) en='FINDING DETAILS'; it="DETTAGLI DELLE SEGNALAZIONI";;
        none) en='No findings were recorded.'; it="Nessuna segnalazione registrata.";;
        evidence) en='Source evidence (original language)'; it="Prova dalla fonte (lingua originale)";;
        object) en='Object'; it="Elemento";;
        confidence_unconfirmed) en='Indicator requiring verification'; it="Indicatore da confermare";;
        confidence_observation) en='Observation; cause not established'; it="Osservazione; causa da chiarire";;
        package) en='Package'; it="Pacchetto";;
        meaning) en='What it means'; it="Cosa significa";;
        checked) en='SecCheck verification'; it="Verifica di SecCheck";;
        action) en='What to do'; it="Cosa fare";;
        explained) en="Explained by additional checks"; it="Chiariti dalle verifiche aggiuntive";;
        explained_note) en='These stay in the details and report. A matching local package record does not certify the package source or the whole system.'; it="Restano consultabili nei dettagli e nel rapporto. La corrispondenza con i dati locali non certifica la provenienza del pacchetto o l'intero sistema.";;
        priority_info) en='Explained'; it="Spiegato";;
        page) en='Page'; it="Pagina";;
        pages_menu) en='1  Next page   2  Previous page   0  Back to result'; it="1  Pagina successiva   2  Pagina precedente   0  Torna al risultato";;
        rkh_prerequisite) en="rkhunter prerequisites need attention. See the exact cause in the report."; it="Un requisito di rkhunter manca o non funziona. La causa precisa è nel rapporto.";;
        rkh_baseline_notice) en='This is a reminder about rkhunter baseline updates, not a detected threat. Do not use --propupd to silence warnings before checking their cause.'; it="Questo è un promemoria sull'aggiornamento della base di confronto di rkhunter, non una minaccia rilevata. Non usare --propupd per azzerare gli avvisi prima di averne verificato la causa.";;
        rkh_context_limited) en="Some additional checks were unavailable. See the finding details."; it="Alcune verifiche aggiuntive non sono riuscite. Vedi i dettagli delle segnalazioni.";;
        rkh_script) en="rkhunter found a script where it expected a program. Legitimate packages can contain scripts."; it="rkhunter ha trovato uno script dove si aspettava un programma. Anche i pacchetti legittimi possono contenerne.";;
        rkh_file_warning) en='rkhunter flagged this file. SecCheck checks whether it belongs to an installed package and whether its contents match the recorded SHA-256.'; it="rkhunter ha segnalato questo file. SecCheck verifica a quale pacchetto appartiene e se il contenuto coincide con lo SHA-256 registrato.";;
        rkh_path_unreadable) en='Control characters or ambiguous text separators prevent reliable identification of the reported path. No automatic file verification was attempted. Inspect the original rkhunter log before acting on the path.'; it="Caratteri di controllo o separatori ambigui nel testo impediscono di identificare con certezza il percorso segnalato. La verifica automatica del file non è stata tentata. Consulta il log originale di rkhunter prima di intervenire sul percorso.";;
        rkh_hidden_file) en='The name starts with a dot, which hides it in ordinary file listings. That is common on Linux and does not by itself indicate malware. SecCheck checks its package record when available.'; it="Il nome inizia con un punto e quindi il file è nascosto negli elenchi ordinari. È comune su Linux e non indica da solo malware. SecCheck verifica i dati del pacchetto, quando disponibili.";;
        rkh_hidden_directory) en='rkhunter reported a hidden directory. Applications commonly create these. A directory cannot be verified with a single file hash: check which application created it and examine its contents without running them.'; it="rkhunter segnala una cartella nascosta. Molte applicazioni ne creano: una cartella non si verifica con lo SHA-256 di un singolo file. Controlla quale applicazione l'ha creata e il suo contenuto, senza eseguirlo.";;
        rkh_hidden_summary) en='rkhunter reported hidden files without individually readable details. Their names are needed before a file verification can be made.'; it="rkhunter segnala file nascosti, ma non sono disponibili dettagli leggibili sui singoli file. Servono i percorsi per verificarli.";;
        rkh_dev) en='rkhunter found unexpected file types under /dev, where devices and runtime data live. Some applications create legitimate files there; this warning needs the listed paths and their origin.'; it="rkhunter segnala tipi di file inattesi in /dev, dove si trovano dispositivi e dati creati durante il funzionamento. Alcune applicazioni vi creano file legittimi: occorre verificarne percorsi e origine.";;
        rkh_ssh_root) en="This concerns remote administrator access through SSH. The effective setting needs checking."; it="Riguarda l’accesso remoto come amministratore tramite SSH. Va controllata l’impostazione effettiva.";;
        rkh_ssh_protocol) en="This old rkhunter test concerns SSH protocol 1. The installed server version can clarify it."; it="Questo vecchio test riguarda il protocollo SSH 1. La versione del server installato può chiarire l’avviso.";;
        rkh_file_match) en="Content, type, permissions and owner match the local package record. This explains this warning."; it="Contenuto, tipo, permessi e proprietario coincidono con il pacchetto locale. Questo chiarisce l’avviso.";;
        rkh_file_changed) en="The content differs from the local package. The warning remains open."; it="Il contenuto è diverso da quello registrato dal pacchetto. La segnalazione resta aperta.";;
        rkh_file_metadata) en="Content matches, but permissions or ownership differ."; it="Il contenuto coincide, ma permessi o proprietario sono diversi.";;
        rkh_file_unknown) en="The exact file could not be verified using package data."; it="Non ho ottenuto dati sufficienti per verificare questo file.";;
        rkh_file_unowned) en="No installed package owns this file. Applications can create such files legitimately."; it="Il file non appartiene a un pacchetto. Può essere stato creato normalmente da un’applicazione.";;
        rkh_file_tool_missing) en='pacfile is unavailable. It is supplied by pacutils, which is needed for this automatic file verification.'; it="pacfile non è disponibile. Fa parte di pacutils, necessario per questa verifica automatica del file.";;
        rkh_file_nonregular) en="The path is absent, is a link or is not a regular file. No content verification was possible."; it="Il percorso manca, è un collegamento o non è un file ordinario. Il contenuto non è stato verificato.";;
        rkh_context_limit) en='The additional check exceeded its file-size, count or time limit. The warning remains open.'; it="La verifica aggiuntiva supera il limite di dimensione, numero di file o tempo. La segnalazione resta aperta.";;
        rkh_ssh_allowed) en="General SSH settings allow root login. This does not establish whether the server is reachable."; it="Le impostazioni generali SSH consentono l’accesso di root. Non sappiamo da questo test se il server sia raggiungibile.";;
        rkh_ssh_disabled) en="General SSH settings disable root login. Connection-specific rules may differ."; it="Le impostazioni generali SSH disabilitano l’accesso di root. Le regole per connessioni specifiche possono essere diverse.";;
        rkh_ssh_keys) en="General SSH settings allow root keys but disable passwords. Connection-specific rules may differ."; it="SSH consente a root l’accesso con chiavi, senza password. Le regole per connessioni specifiche possono essere diverse.";;
        rkh_ssh_commands) en='Root login is limited to keys with a forced command in the general SSH configuration. Review whether this is needed for your remote tasks.'; it="La configurazione generale di SSH limita root alle chiavi associate a un comando prestabilito. Verifica se serve per le tue attività remote.";;
        rkh_ssh_modern) en="The installed OpenSSH server no longer supports protocol 1. This explains the old warning."; it="Il server OpenSSH installato non supporta più il protocollo 1. Questo chiarisce il vecchio avviso.";;
        rkh_ssh_unknown) en="The SSH version or effective settings could not be checked."; it="Non è stato possibile verificare la versione o le impostazioni effettive di SSH.";;
        rkh_ssh_not_started) en="The SSH command is missing or its preliminary checks could not finish."; it="Il comando SSH manca oppure le sue verifiche preliminari non sono terminate.";;
        rkh_ssh_hostkeys) en="SSH could not load usable server keys."; it="SSH non ha trovato chiavi del server utilizzabili.";;
        rkh_ssh_config_only) en="The configuration was read without checking server keys. This does not check whether the service is running."; it="Letta la configurazione senza controllare le chiavi del server. Questo test non verifica se il servizio sia attivo.";;
        rkh_action_explained) en="No action needed for this warning alone."; it="Non serve intervenire per questo singolo avviso.";;
        rkh_action_file) en="If you did not make this change, ask for help using the report before replacing the file."; it="Se non hai fatto tu questa modifica, chiedi aiuto usando il rapporto prima di sostituire il file.";;
        rkh_action_unowned) en="Identify the application that created it. Being hidden or unowned is not a reason to delete it."; it="Verifica quale applicazione lo ha creato. Essere nascosto o fuori dai pacchetti non basta per eliminarlo.";;
        rkh_action_tools) en='Install pacutils using option 6, then repeat this scan.'; it="Installa pacutils dalla voce 6, poi ripeti questo controllo.";;
        rkh_action_ssh) en='If direct root access is unnecessary, consider PermitRootLogin no. Check Include and Match rules before changing the configuration; validate it with sshd -t and keep an existing remote session open.'; it="Se l'accesso diretto come root non ti serve, valuta PermitRootLogin no. Controlla le regole Include e Match prima di modificare la configurazione; validala con sshd -t e mantieni aperta un'eventuale sessione remota.";;
        rkh_action_ssh_disabled) en='No change is needed for the general root-login setting. If you use SSH, also review any connection-specific Match rules.'; it="Non serve cambiare l'impostazione generale del login di root. Se usi SSH, controlla anche le eventuali regole Match per connessioni specifiche.";;
        rkh_action_unknown) en="The report contains the original warning and the failed check. Use it to ask for help."; it="Nel rapporto trovi avviso originale e verifica tentata. Usalo per chiedere aiuto.";;
        rkh_signature) en='rkhunter reported a possible rootkit signature. It remains unresolved even if package checks pass. Check the exact signature and its context with expert help.'; it="rkhunter segnala una possibile firma di rootkit. Resta da chiarire anche se i pacchetti superano il controllo. Verifica la firma precisa e il contesto con aiuto esperto.";;
        rkh_properties) en='rkhunter found changed file properties. Updates can cause this, but the change needs checking. Do not reset its baseline before investigating.'; it="rkhunter ha trovato proprietà di file cambiate. Gli aggiornamenti possono causarlo, ma occorre verificare. Non azzerare la base di confronto prima di approfondire.";;
        rkh_warning) en='rkhunter raised an alert. Read the specific evidence: hidden files and configuration warnings can have legitimate explanations.'; it="rkhunter ha prodotto un avviso. Leggi la prova specifica: file nascosti e avvisi di configurazione possono avere spiegazioni legittime.";;
        lynis_warning) en='Lynis found a configuration issue. Use its test ID and evidence to decide what to change; this does not independently confirm malware.'; it="Lynis segnala un problema di configurazione. Usa il codice del test e i dettagli per decidere cosa cambiare; questo non conferma da solo la presenza di malware.";;
        lynis_suggestion) en='Lynis suggests stronger settings. Assess compatibility and the purpose of this machine before applying the suggestion.'; it="Lynis suggerisce impostazioni più robuste. Valuta compatibilità e uso di questo computer prima di applicare il consiglio.";;
        lynis_reboot) en='Lynis suggests restarting the computer.'; it='Lynis suggerisce un riavvio del computer.';;
        lynis_action_reboot) en='Save your work, restart when convenient, then repeat this check.'; it='Salva il lavoro, riavvia quando puoi e ripeti questo controllo.';;
        integrity_metadata) en="Size, type or link target differs from the package record. The cause needs checking."; it="Dimensione, tipo o destinazione del collegamento sono diversi dai dati del pacchetto. La causa va verificata.";;
        integrity_content) en="File content differs from the local package record. Explain the change before replacing anything."; it="Il contenuto è diverso da quello registrato nel pacchetto locale. La modifica va chiarita prima di sostituire il file.";;
        integrity_permissions) en="Access permissions changed: who can read, write or execute this path. A service may require this."; it="Sono cambiati i permessi: chi può leggere, scrivere o eseguire. Potrebbe essere una scelta del servizio che usa il file.";;
        integrity_owner) en="The owner or group changed. A service may need its own account; check before changing ownership."; it="È cambiato il proprietario o il gruppo. Un servizio può avere bisogno di un account dedicato: verifica prima di modificarlo.";;
        integrity_time) en="The modification time changed. This alone does not show that the content changed."; it="È cambiata la data di modifica. Da sola non dimostra una modifica del contenuto.";;
        integrity_incomplete) en="Some files could not be checked. Details are in the report."; it="Alcuni file non sono stati verificati. Dettagli nel rapporto.";;
        integrity_unparsed) en='SecCheck could not interpret this output line. It remains visible so an unsupported format cannot silently count as a completed check. Include this line when reporting the problem.'; it="SecCheck non riesce a interpretare questa riga. La mostra per evitare che un formato non supportato venga considerato un controllo completato. Includi questa riga quando segnali il problema.";;
        integrity_mtree) en='Local package reference data (MTREE) is missing or unreadable. The affected comparison cannot finish. Check the named package and local database; this does not by itself establish that its installed files changed.'; it="I dati locali di confronto del pacchetto (MTREE) sono assenti o illeggibili. La verifica interessata non può terminare. Controlla il pacchetto indicato e il database locale: questo non dimostra da solo una modifica ai file installati.";;
        integrity_read_error) en='The tool could not read a file or its reference data. This is a coverage limit, not a confirmed file change. Check the reported path, permissions and storage error before repeating the check.'; it="Lo strumento non ha potuto leggere un file o i suoi dati di confronto. È un limite della verifica, non una modifica confermata. Controlla il percorso, i permessi e l'errore di lettura indicati prima di ripetere il controllo.";;
        integrity_tool_error) en='The package tool reported an execution error. Read its exact message below; this part of the check did not complete normally.'; it="Lo strumento dei pacchetti ha segnalato un errore di esecuzione. Leggi il messaggio preciso qui sotto: questa parte del controllo non si è conclusa normalmente.";;
        integrity_timeout) en='The package check timed out or was forcibly stopped. Its earlier results remain available, but later files may not have been checked.'; it="Il controllo dei pacchetti ha superato il tempo massimo oppure è stato terminato forzatamente. I risultati già ottenuti restano disponibili, ma altri file potrebbero non essere stati controllati.";;
        integrity_exit_error) en='The package tool ended with an unexpected exit code. Even if it printed successful checks, its overall execution remains incomplete. See the tool name, code and original logs.'; it="Lo strumento dei pacchetti è terminato con un codice inatteso. Anche se ha mostrato verifiche riuscite, l'esecuzione complessiva resta incompleta. Consulta nome dello strumento, codice e log originali.";;
        integrity_no_results) en='The tool produced no interpretable file result or package summary. SecCheck cannot count this as a completed comparison.'; it="Lo strumento non ha prodotto risultati interpretabili sui file o riepiloghi dei pacchetti. SecCheck non può considerarlo un confronto completato.";;
        integrity_exit_unexplained) en='The tool reported a problem through its exit code, but no corresponding file difference was found in the interpreted output. Its original logs need review.'; it="Il codice di uscita dello strumento segnala un problema, ma nei messaggi interpretati non compare una differenza sui file che lo spieghi. Occorre controllare i log originali.";;
        integrity_missing) en="A packaged file is missing. Check exclusions and recent changes before restoring it."; it="Manca un file previsto dal pacchetto. Verifica esclusioni e modifiche recenti prima di ripristinarlo.";;
        file_config) en='Configuration/backup path: an intentional edit is possible, but must be verified.'; it="Percorso di configurazione o backup: la modifica può essere voluta, ma va verificata.";;
        demo) en='DEMO - INVENTED RESULTS. No system scan was performed.'; it="DEMO - RISULTATI DI ESEMPIO. Nessuna scansione del sistema eseguita.";;
        report) en='Private report'; it="Rapporto privato";;
        report_info) en="Root is needed to read the report. Review private paths before sharing."; it="Il rapporto richiede root. Contiene percorsi privati: controllalo prima di condividerlo.";;
        scope_report) en='TECHNICAL SCOPE / ORIGINAL LOGS'; it="AMBITO TECNICO / LOG ORIGINALI";;
        limits) en="No scan can guarantee a secure system."; it="Nessuna scansione garantisce da sola un sistema sicuro.";;
        result_menu) en='1  Findings   2  Full report   3  Repeat scan   0  Main menu'; it="1  Dettagli   2  Rapporto   3  Ripeti scansione   0  Menu";;
        more) en='More findings are available on the following pages and in the full report.'; it="Le altre segnalazioni sono nelle pagine successive e nel rapporto completo.";;
        unsupported) en='Scanning requires Arch Linux or an Arch derivative with pacman.'; it="La scansione richiede Arch Linux o una derivata con pacman.";;
        root) en='This action requires root. SecCheck will request permission through sudo.'; it="Questa azione richiede root. SecCheck chiederà i permessi tramite sudo.";;
        need_root) en='Run this command with sudo to scan noninteractively.'; it="Esegui questo comando con sudo per una scansione non interattiva.";;
        storage_error) en='Cannot create a private report directory. Scan not started.'; it="Impossibile creare una cartella privata per i rapporti. Scansione non avviata.";;
        save_error) en='Report could not be saved completely. Check free space and permissions.'; it="Rapporto non salvato completamente. Controlla spazio libero e permessi.";;
        deps) en='TOOLS AND PURPOSE'; it="STRUMENTI E FUNZIONE";;
        deps_startup) en='STARTUP CHECK'; it="CONTROLLO INIZIALE";;
        deps_explain) en='SecCheck checks which tools are available before you choose a scan.'; it="SecCheck verifica gli strumenti disponibili prima di scegliere una scansione.";;
        deps_ready) en='Tools ready: all scan dependencies are available.'; it="Strumenti pronti: sono disponibili tutte le dipendenze delle scansioni.";;
        deps_missing) en='Missing packages'; it="Pacchetti mancanti";;
        deps_continue) en='You can continue. Checks needing missing tools will remain incomplete. Use option 6 to install them later.'; it="Puoi proseguire. I controlli che richiedono gli strumenti mancanti resteranno incompleti. Puoi installarli in seguito dalla voce 6.";;
        deps_pacutils) en='File contents and automatic verification of rkhunter file warnings (paccheck + pacfile)'; it="Contenuto dei file e verifica automatica degli avvisi di rkhunter (paccheck + pacfile)";;
        deps_python) en='Read AUR metadata and compare maintainer history'; it="Lettura dei dati AUR e confronto dello storico dei maintainer";;
        deps_curl) en='HTTPS connection to AUR for maintenance information'; it="Collegamento HTTPS ad AUR per i dati sulla manutenzione";;
        available) en='available'; it="disponibile";;
        absent) en='missing'; it="mancante";;
        install_question) en='Install the missing packages with pacman? [y/N]'; it="Installare con pacman i pacchetti mancanti? [s/N]";;
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
    SC_C_PRIMARY='' SC_C_MUTED='' SC_C_RED='' SC_C_AMBER='' SC_C_GREEN='' SC_C_WHITE='' SC_C_RESET='' SC_C_BOLD=''
    if [[ -t 1 && ${TERM:-dumb} != dumb && ${SC_NO_COLOR:-0} == 0 && ! ${NO_COLOR+x} ]]; then
        SC_C_RESET=$'\e[0m' SC_C_BOLD=$'\e[1m'
        SC_C_PRIMARY=$'\e[38;5;80m' SC_C_MUTED=$'\e[38;5;109m'
        SC_C_RED=$'\e[38;5;203m' SC_C_AMBER=$'\e[38;5;222m' SC_C_GREEN=$'\e[38;5;114m'
        SC_C_WHITE=$'\e[38;5;255m'
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
sc_heading() { printf '\n'; sc_line "$(sc_t "$1")" "${2:-$SC_C_PRIMARY}$SC_C_BOLD"; sc_rule; }
sc_brand() {
    printf '\n'
    if ((SC_WIDTH >= 68)) && [[ ${SC_ASCII:-0} == 0 ]]; then
        local i
        local -a sec=(
            '███████╗███████╗ ██████╗'
            '██╔════╝██╔════╝██╔════╝'
            '███████╗█████╗  ██║     '
            '╚════██║██╔══╝  ██║     '
            '███████║███████╗╚██████╗'
            '╚══════╝╚══════╝ ╚═════╝'
        ) check=(
            ' ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗'
            '██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝'
            '██║     ███████║█████╗  ██║     █████╔╝ '
            '██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ '
            '╚██████╗██║  ██║███████╗╚██████╗██║  ██╗'
            ' ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝'
        )
        for ((i=0;i<6;i++)); do
            printf '  %s%s%s %s%s%s\n' "$SC_C_PRIMARY$SC_C_BOLD" "${sec[i]}" "$SC_C_RESET" "$SC_C_WHITE$SC_C_BOLD" "${check[i]}" "$SC_C_RESET"
        done
        printf '\n'
    else
        sc_rule; sc_line 'S E C C H E C K' "$SC_C_PRIMARY$SC_C_BOLD"; sc_rule
    fi
    sc_line 'Security & Integrity Checker for Arch Linux' "$SC_C_PRIMARY$SC_C_BOLD"
    sc_line "v$SC_VERSION | KlodCripta" "$SC_C_WHITE"
}
sc_header() {
    sc_brand; sc_rule; printf '\n'
    [[ ${SC_DEMO:-0} == 0 ]] || sc_line "$(sc_t demo)" "$SC_C_AMBER"
}

sc_status_color() {
    case $1 in urgent|failed) printf '%s' "$SC_C_RED";; review|advice|partial) printf '%s' "$SC_C_AMBER";;
        clear|completed) printf '%s' "$SC_C_GREEN";; info|suggestion) printf '%s' "$SC_C_PRIMARY";; *) printf '%s' "$SC_C_MUTED";; esac
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
    local module count i color label bar total=${#SC_SELECTED[@]} urgent=0 review=0 suggestions=0 explained=0
    sc_detail_groups
    for i in "${SC_DETAIL_GROUPS[@]}"; do
        i=${i%% *}
        case ${SC_F_PRIORITY[i]} in
            urgent) ((urgent+=1));; review) ((review+=1));;
            suggestion) ((suggestions+=1));; info) ((explained+=1));;
        esac
    done
    sc_heading result "$(sc_status_color "$SC_ASSESSMENT")"
    color=$(sc_status_color "$SC_ASSESSMENT")
    sc_line "$SC_DOT  $(sc_t "$SC_ASSESSMENT")" "$color$SC_C_BOLD"
    sc_line "$(sc_t "why_$SC_ASSESSMENT")"
    ((SC_FOLLOWUPS_INTERRUPTED == 0)) || sc_line "$(sc_t followup_interrupted)" "$SC_C_AMBER"
    sc_heading coverage
    if ((SC_INCOMPLETE)); then label=$(sc_t incomplete); color=$SC_C_MUTED
    else label=$(sc_t complete); color=$SC_C_PRIMARY; fi
    sc_line "$SC_COMPLETED/$total  $label" "$color"
    bar="$(sc_repeat "$SC_BAR_CHAR" "$SC_COMPLETED")$(sc_repeat "$SC_EMPTY_CHAR" "$((total-SC_COMPLETED))")"
    sc_line "[$bar]" "$color"
    if ((total < 4)); then sc_line "$(sc_t scope_selected)"; fi
    printf '\n'
    if ((SC_WIDTH >= 64)); then
        printf '  %s%-24s %-17s %7s%s\n' "$SC_C_MUTED" "$(sc_t module)" "$(sc_t status)" "$(sc_t findings)" "$SC_C_RESET"
        sc_rule
    fi
    for module in "${SC_SELECTED[@]}"; do
        count=0
        for i in "${SC_DETAIL_GROUPS[@]}"; do
            i=${i%% *}; [[ ${SC_F_MODULE[i]} == "$module" ]] && ((count+=1))
        done
        color=$(sc_status_color "${SC_MODULE_STATUS[$module]}")
        if ((SC_WIDTH >= 64)); then
            printf '  '; sc_cell "$(sc_t "$module")" 24; printf ' %s' "$color"
            sc_cell "$(sc_t "${SC_MODULE_STATUS[$module]}")" 17; printf '%s %7d\n' "$SC_C_RESET" "$count"
        else
            sc_line "$(sc_t "$module")" "$SC_C_PRIMARY"
            sc_line "$(sc_t "${SC_MODULE_STATUS[$module]}") / $(sc_t findings): $count" "$color"
        fi
        [[ -z ${SC_MODULE_REASON[$module]} ]] || sc_line "$(sc_t "${SC_MODULE_REASON[$module]}")" "$SC_C_MUTED"
        if [[ $module == rkhunter && " ${SC_D_KEY[*]} " == *' rkh_optional '* ]]; then
            sc_line "$(sc_t rkh_optional_short)" "$SC_C_MUTED"
        fi
    done
    sc_line "$(sc_t coverage_note)" "$SC_C_MUTED"
    sc_heading signals
    local max=$urgent slots=$((SC_WIDTH-29)) n priority
    ((review > max)) && max=$review; ((suggestions > max)) && max=$suggestions
    ((slots < 4)) && slots=4; ((slots > 24)) && slots=24
    for priority in urgent review suggestion; do
        case $priority in urgent) count=$urgent;; review) count=$review;; suggestion) count=$suggestions;; esac
        n=0; ((max)) && n=$(((count*slots+max-1)/max))
        sc_line "$(sc_t "priority_$priority"): $count  $(sc_repeat "$SC_BAR_CHAR" "$n")" "$(sc_status_color "$priority")"
    done
    sc_line "$(sc_t count_note)" "$SC_C_MUTED"
    if ((explained)); then
        printf '\n'; sc_line "$(sc_t explained): $explained" "$SC_C_GREEN$SC_C_BOLD"
    fi
    if ((SC_FOLLOWUPS_DONE)); then
        count=$((urgent+review))
        sc_line "$(sc_t followup_pending): $count" "$SC_C_MUTED"
        sc_line "$(sc_t followup_group_note)" "$SC_C_MUTED"
    fi
    sc_heading next
    if ((SC_FOLLOWUPS_DONE)) && [[ $SC_ASSESSMENT != urgent ]]; then sc_line "$(sc_t followup_finished)"
    else sc_line "$(sc_t "next_$SC_ASSESSMENT")"; fi
    sc_line "$(sc_t limits)" "$SC_C_MUTED"
    if [[ ${SC_MODULE_STATUS[aur-health]} != not-run ]]; then
        sc_heading health_guide
        sc_line "- $(sc_t health_habits)"
        sc_line "- $(sc_t health_build)"
        sc_line "- $(sc_t health_sources)"
        sc_line "$(sc_t health_limits)" "$SC_C_MUTED"
        for i in "${SC_F_KEY[@]}"; do
            [[ $i == health_many ]] || continue
            sc_line "$(sc_t health_many)" "$SC_C_AMBER"; break
        done
    fi
}

# Group only the presentation, never the original evidence or its assessment.
# The first member has the highest priority. Ambiguous paths remain separate.
sc_detail_groups() {
    local technical=${1:-0} priority i g first found
    declare -ga SC_DETAIL_GROUPS=()
    for priority in urgent review suggestion info; do
        for i in "${!SC_F_MODULE[@]}"; do
            [[ ${SC_F_PRIORITY[i]} == "$priority" ]] || continue
            found=-1
            if ((technical == 0)) && [[ ${SC_F_MODULE[i]} == integrity && ${SC_F_OBJECT[i]} == /* ]]; then
                for g in "${!SC_DETAIL_GROUPS[@]}"; do
                    first=${SC_DETAIL_GROUPS[g]%% *}
                    if [[ ${SC_F_MODULE[first]} == integrity && ${SC_F_OBJECT[first]} == "${SC_F_OBJECT[i]}" ]]; then
                        found=$g; break
                    fi
                done
            fi
            if ((found >= 0)); then SC_DETAIL_GROUPS[found]+=" $i"
            else SC_DETAIL_GROUPS+=("$i"); fi
        done
    done
}

sc_render_details() {
    local limit=${1:-0} offset=${2:-0} technical=${3:-0} i j group shown=0 visited=0 priority object check action fields seen key config
    local -a members=()
    sc_heading details
    ((${#SC_F_MODULE[@]})) || { sc_line "$(sc_t none)"; return 0; }
    sc_detail_groups "$technical"
    for group in "${SC_DETAIL_GROUPS[@]}"; do
            read -r -a members <<< "$group"
            i=${members[0]}; priority=${SC_F_PRIORITY[i]}
            ((visited+=1)); ((visited > offset)) || continue
            if ((limit && shown >= limit)); then sc_line "$(sc_t more)"; return 0; fi
            ((shown+=1)); object=${SC_F_OBJECT[i]}
            printf '\n'
            sc_line "#$((i+1)) / $(sc_t "priority_$priority") / $(sc_t "${SC_F_MODULE[i]}")" "$(sc_status_color "$priority")"
            if [[ $priority == info && -n ${SC_F_CHECK_KEY[i]} ]]; then
                sc_line "$(sc_t confidence_explained)" "$SC_C_GREEN"
            elif ((technical)); then
                sc_line "$(sc_t "confidence_${SC_F_CONFIDENCE[i]}")" "$SC_C_MUTED"
            fi
            [[ -z $object ]] || sc_line "$(sc_t object): $object"
            if ((${#members[@]} > 1)); then
                fields='' seen=' '
                for j in "${members[@]}"; do
                    key=${SC_F_KEY[j]}
                    [[ $seen == *" $key "* ]] && continue
                    seen+="$key "
                    fields+="${fields:+; }$(sc_t "field_$key")"
                done
                sc_line "$(sc_t grouped_findings): ${#members[@]}" "$SC_C_MUTED"
                sc_line "$(sc_t integrity_fields): $fields"
            else
                sc_line "$(sc_t meaning):" "$SC_C_WHITE$SC_C_BOLD"
                sc_line "$(sc_t "${SC_F_KEY[i]}")"
            fi
            seen=' ' action=''
            for j in "${members[@]}"; do
                check=${SC_F_CHECK_KEY[j]}
                [[ -n $check && $seen != *" $check "* ]] || continue
                [[ ${SC_F_KEY[j]} == lynis_reboot && $check == followup_manual ]] && continue
                seen+="$check "
                sc_line "$(sc_t checked):" "$SC_C_PRIMARY$SC_C_BOLD"
                sc_line "$(sc_t "$check")"
                if ((technical)) || [[ $check == rkh_ssh_unknown ]]; then
                    [[ -z ${SC_F_CHECK_DETAIL[j]} ]] || sc_line "${SC_F_CHECK_DETAIL[j]}" "$SC_C_MUTED"
                fi
                if [[ $check == rkh_ssh_allowed || $check == rkh_ssh_disabled ||
                      $check == rkh_ssh_keys || $check == rkh_ssh_commands ]] &&
                   [[ ${SC_F_CHECK_DETAIL[j]} == 'sshd -G:'* ]]; then
                    sc_line "$(sc_t rkh_ssh_config_only)"
                fi
                [[ -z $action ]] || continue
                case $check in
                    rkh_file_match|rkh_ssh_modern|integrity_rechecked) action=rkh_action_explained;;
                    rkh_file_changed|rkh_file_metadata|integrity_hash_only|integrity_special) action=rkh_action_file;;
                    rkh_file_unowned) action=rkh_action_unowned;;
                    rkh_file_tool_missing) action=rkh_action_tools;;
                    rkh_ssh_allowed|rkh_ssh_keys|rkh_ssh_commands) action=rkh_action_ssh;;
                    rkh_ssh_disabled) action=rkh_action_ssh_disabled;;
                    *) action=rkh_action_unknown;;
                esac
            done
            [[ ${SC_F_KEY[i]} != lynis_reboot ]] || action=lynis_action_reboot
            if [[ -n $action ]]; then
                # A matching sibling must not dismiss a still-open difference.
                if ((${#members[@]} > 1)) && [[ $priority != info && $action == rkh_action_explained ]]; then
                    action=rkh_action_file
                fi
                sc_line "$(sc_t action):" "$SC_C_AMBER$SC_C_BOLD"; sc_line "$(sc_t "$action")"
            fi
            if [[ ${SC_F_MODULE[i]} == integrity ]]; then
                config=0; [[ $object != /etc/* ]] || config=1
                for j in "${members[@]}"; do [[ ${SC_F_EVIDENCE[j]} != *'backup file:'* ]] || config=1; done
                ((config == 0)) || sc_line "$(sc_t file_config)"
            fi
            if ((technical)) || [[ ${SC_F_MODULE[i]} == lynis || ${SC_F_KEY[i]} == rkh_signature || ${SC_F_KEY[i]} == rkh_warning ]]; then
                sc_line "$(sc_t evidence): ${SC_F_EVIDENCE[i]}" "$SC_C_MUTED"
            fi
    done
}

sc_browse_details() {
    sc_detail_groups
    local page=0 pages=$(((${#SC_DETAIL_GROUPS[@]}+9)/10)) answer
    ((pages)) || { sc_render_details; return; }
    while :; do
        sc_line "$(sc_t page) $((page+1)) / $pages" "$SC_C_PRIMARY"
        sc_render_details 10 "$((page*10))"
        [[ -t 0 ]] || return 0
        printf '\n'; sc_line "$(sc_t pages_menu)"
        printf '  > '; IFS= read -r answer || return 0
        case $answer in
            1) ((page+1 < pages)) && ((page+=1));;
            2) ((page > 0)) && ((page-=1));;
            0) return 0;;
            *) sc_line "$(sc_t invalid)";;
        esac
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
    sc_header; sc_render_summary; sc_render_details 0 0 1
    sc_heading scope_report
    sc_line "SecCheck=$SC_VERSION; started=${SC_STARTED:-demo}"
    ((${#SC_SELECTED[@]} != 4)) || sc_line "$(sc_t scope_full)"
    local module value
    for module in "${SC_SELECTED[@]}"; do
        sc_line "$module: version=${SC_MODULE_VERSION[$module]}; exit=${SC_MODULE_RC[$module]}; reason=${SC_MODULE_REASON[$module]}"
        sc_render_diagnostics "$module" 0
    done
    [[ -z ${SC_HEALTH_NOTE:-} ]] || sc_line "$(sc_t "$SC_HEALTH_NOTE")"
    for value in "${SC_SCOPE[@]}"; do sc_line "$value"; done
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
        printf 'finding\tresult\tdetail\n'
        for ((i=0;i<${#SC_F_MODULE[@]};i++)); do
            [[ -n ${SC_F_CHECK_KEY[i]} ]] || continue
            printf '%d\t%s\t%s\n' "$((i+1))" "${SC_F_CHECK_KEY[i]}" "$(sc_text "${SC_F_CHECK_DETAIL[i]}")"
        done
    } > "$SC_RUN_DIR/checks.tsv" || return 1
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
    printf '%s\n' '  --lang en|it' '  --scan full|rkhunter|lynis|integrity|aur-health' \
        '  --offline' '  --no-color' '  --ascii' \
        '  --demo [review|urgent|incomplete|clean]' '  --help' '  --version'
    printf '\n%s\n' "$(sc_t batch_usage)"
    printf '%s\n' "$(sc_t health_network)"
}

sc_parse_args() {
    SC_LANG='' SC_SCAN='' SC_DEMO=0 SC_SCENARIO=review SC_NO_COLOR=0 SC_ASCII=0 SC_ACTION='' SC_OFFLINE=0
    while (($#)); do
        case $1 in
            --lang) (($# >= 2)) || return 64; case $2 in en|it) SC_LANG=$2;; *) return 64;; esac; shift;;
            --scan) (($# >= 2)) || return 64; case $2 in full|rkhunter|lynis|integrity|aur-health) SC_SCAN=$2;; *) return 64;; esac; shift;;
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
    sc_brand
    printf '\n  1  English\n  2  Italiano\n\n'
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
            sc_add_finding rkhunter suspicious urgent unconfirmed example-signature rkh_signature 'DEMO: possible rootkit signature'
            sc_module_set rkhunter partial unfinished;;
        review)
            sc_add_finding integrity integrity review observation /etc/example.conf integrity_content 'DEMO: SHA-256 differs from local package record'
            sc_add_finding lynis hardening suggestion observation SSH-DEMO lynis_suggestion 'DEMO: review SSH configuration'
            sc_add_finding aur-health maintenance review observation example-app health_maintainer 'DEMO: old-owner -> new-owner'
            sc_add_finding aur-health maintenance suggestion observation example-tool health_inactive 'DEMO: days=420'
            sc_add_finding rkhunter suspicious info observation /usr/bin/example-tool rkh_script 'DEMO: The command is a script'
            SC_F_CHECK_KEY[${#SC_F_MODULE[@]}-1]=rkh_file_match
            SC_F_CHECK_DETAIL[${#SC_F_MODULE[@]}-1]='DEMO: example-package / SHA-256';;
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
    local mode=${1:-menu} tool label answer package purpose color missing_tool
    local -a missing=() install=()
    if [[ $mode == startup ]]; then sc_heading deps_startup; sc_line "$(sc_t deps_explain)"
    else sc_heading deps; fi
    for package in rkhunter lynis pacutils python curl; do
        missing_tool=0
        case $package in
            rkhunter) tool=rkhunter; purpose=menu_rkhunter;;
            lynis) tool=lynis; purpose=menu_lynis;;
            pacutils) tool=paccheck; purpose=deps_pacutils; command -v pacfile >/dev/null || missing_tool=1;;
            python) tool=python3; purpose=deps_python;;
            curl) tool=curl; purpose=deps_curl;;
        esac
        command -v "$tool" >/dev/null || missing_tool=1
        label=$(sc_t available); color=$SC_C_GREEN
        if ((missing_tool)); then missing+=("$package"); label=$(sc_t absent); color=$SC_C_AMBER; fi
        printf '\n'; sc_line "$package: $label" "$color$SC_C_BOLD"
        sc_line "$(sc_t "$purpose")"
    done
    if ((${#missing[@]} == 0)); then printf '\n'; sc_line "$(sc_t deps_ready)" "$SC_C_GREEN"; return 0; fi
    printf '\n'; sc_line "$(sc_t deps_missing): ${missing[*]}" "$SC_C_AMBER"
    if [[ $mode == report ]]; then sc_line "$(sc_t deps_continue)"; return 1; fi
    [[ -t 0 ]] || return 1
    # --install-tools is an explicit installation request (also used by sudo).
    # The interactive menu asks once; pacman still confirms the transaction.
    if [[ $mode != install ]]; then
        sc_line "$(sc_t install_question)"
        IFS= read -r answer || return 0
        case $answer in y|Y|s|S) ;; *) sc_line "$(sc_t deps_continue)"; return 0;; esac
    fi
    sc_require_scan_host || return $?
    install=(pacman -S --needed -- "${missing[@]}")
    if ((EUID != 0)); then sc_line "$(sc_t root)"; install=(sudo -- "${install[@]}"); fi
    sc_line "$(sc_t install_note)"
    "${install[@]}" || { sc_line "$(sc_t install_failed)"; return 1; }
    sc_dependencies report
}

sc_abort() {
    trap - INT TERM
    local module i
    if [[ ${SC_RUN_ACTIVE:-0} == 1 ]]; then
        if [[ ${SC_FOLLOWUPS_ACTIVE:-0} == 1 ]]; then
            SC_FOLLOWUPS_INTERRUPTED=1
            for i in "${!SC_F_MODULE[@]}"; do
                [[ -n ${SC_F_CHECK_KEY[i]} ]] || SC_F_CHECK_KEY[i]=followup_interrupted
            done
        fi
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
        case $module in rkhunter) sc_run_rkhunter;; lynis) sc_run_lynis;; integrity) sc_run_integrity;; aur-health) sc_run_aur_health;; esac
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

sc_interpret_integrity() {
    local i j object checked=0 started=$SECONDS result detail found
    local -a objects=() results=() details=()
    for i in "${!SC_F_MODULE[@]}"; do
        [[ ${SC_F_MODULE[i]} == integrity ]] || continue
        object=${SC_F_OBJECT[i]}; found=0
        if [[ -z $object ]]; then SC_F_CHECK_KEY[i]=followup_manual; continue; fi
        for j in "${!objects[@]}"; do
            if [[ ${objects[j]} == "$object" ]]; then
                result=${results[j]}; detail=${details[j]}; found=1; break
            fi
        done
        if ((found == 0)); then
            if ((checked >= 80 || SECONDS-started >= 180)); then
                SC_F_CHECK_KEY[i]=rkh_context_limit; continue
            fi
            ((checked+=1))
            sc_rkh_check_file "$i"
            result=${SC_F_CHECK_KEY[i]}; detail=${SC_F_CHECK_DETAIL[i]}
            objects+=("$object"); results+=("$result"); details+=("$detail")
        fi
        SC_F_CHECK_KEY[i]=$result; SC_F_CHECK_DETAIL[i]=$detail
        SC_F_PRIORITY[i]=review
        # A hash comparison cannot resolve a timestamp, size, link or missing
        # path observation. Leave those open even when a regular file matches.
        if [[ $result == rkh_file_match ]]; then
            case ${SC_F_KEY[i]} in
                integrity_content|integrity_permissions|integrity_owner)
                    SC_F_PRIORITY[i]=info; SC_F_CHECK_KEY[i]=integrity_rechecked;;
                *) SC_F_CHECK_KEY[i]=integrity_hash_only;;
            esac
        elif [[ $result == rkh_file_nonregular ]]; then
            # Describe directories, links and absent paths without hashing or
            # reading their targets. Never infer legitimacy from their names.
            if sc_capture "$SC_RUN_DIR/file-context.$i.stat" "$SC_RUN_DIR/file-context.$i.stderr" 5 \
                stat -c 'type=%F mode=%a uid=%u gid=%g' -- "$object" &&
                [[ ! -s $SC_RUN_DIR/file-context.$i.stderr ]]; then
                SC_F_CHECK_KEY[i]=integrity_special
                SC_F_CHECK_DETAIL[i]="$(sc_text "$(<"$SC_RUN_DIR/file-context.$i.stat")"); log=file-context.$i.stat"
            fi
        fi
    done
    SC_SCOPE+=('Integrity follow-ups: up to 80 distinct paths / 180s plus one in-flight check; regular files <=64MiB; pacfile local MTREE + SHA-256. Directory/link metadata is observed without declaring it legitimate. Timestamp/size/missing observations remain open.')
}

sc_run_followups() {
    local i
    SC_RUN_ACTIVE=1 SC_FOLLOWUPS_ACTIVE=1
    trap sc_abort INT TERM
    sc_heading followups
    if [[ ${SC_MODULE_STATUS[rkhunter]} != not-run ]]; then
        sc_line "$(sc_t followup_rootkit)" "$SC_C_PRIMARY"
        sc_interpret_rkhunter
        if ((SC_RKH_CONTEXT_PARTIAL)) && [[ ${SC_MODULE_STATUS[rkhunter]} == completed ]]; then
            sc_module_set rkhunter partial rkh_context_limited
        fi
    fi
    if [[ ${SC_MODULE_STATUS[integrity]} != not-run ]]; then
        sc_line "$(sc_t followup_files)" "$SC_C_PRIMARY"
        sc_interpret_integrity
    fi
    for i in "${!SC_F_MODULE[@]}"; do
        [[ -n ${SC_F_CHECK_KEY[i]} ]] || SC_F_CHECK_KEY[i]=followup_manual
    done
    SC_FOLLOWUPS_DONE=1
    sc_assess
    sc_save_report || { SC_RUN_ACTIVE=0; SC_FOLLOWUPS_ACTIVE=0; trap - INT TERM; sc_line "$(sc_t save_error)"; return 73; }
    SC_RUN_ACTIVE=0 SC_FOLLOWUPS_ACTIVE=0
    trap - INT TERM
    sc_render_summary
    sc_line "$(sc_t report): $SC_RUN_DIR/report.txt" "$SC_C_PRIMARY"
}

sc_offer_followups() {
    local answer
    printf '\n'; sc_line "$(sc_t followup_question)" "$SC_C_PRIMARY$SC_C_BOLD"
    printf '  > '; IFS= read -r answer || return 0
    case $answer in s|S|y|Y) sc_run_followups;; *) return 0;; esac
}

sc_result_code() {
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
        sc_offer_followups || return $?
        sc_result_code; rc=$?
        while :; do
            printf '\n'; sc_line "$(sc_t result_menu)"
            printf '  > '; IFS= read -r answer || return "$rc"
            case $answer in
                1) sc_browse_details;;
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
        sc_heading menu_scans
        sc_line "1  $(sc_t menu_full)" "$SC_C_PRIMARY$SC_C_BOLD"
        sc_line "$(sc_t full_includes)" "$SC_C_WHITE"; printf '\n'
        sc_line "2  $(sc_t menu_rkhunter)"; sc_line "3  $(sc_t menu_lynis)"
        sc_line "4  $(sc_t menu_integrity)"; sc_line "5  $(sc_t aur-health)"
        sc_heading menu_tools "$SC_C_AMBER"
        sc_line "6  $(sc_t menu_deps)"; sc_line "7  $(sc_t menu_update)"
        sc_line "8  $(sc_t menu_demo)"
        sc_line "$(sc_t tools_separate)" "$SC_C_MUTED"
        printf '\n'; sc_line "0  $(sc_t exit)" "$SC_C_WHITE"
        printf '\n  %s > ' "$(sc_t choose)"; IFS= read -r answer || return 0
        case $answer in
            1) SC_SCAN=full; sc_run_requested;;
            2) SC_SCAN=rkhunter; sc_run_requested;;
            3) SC_SCAN=lynis; sc_run_requested;;
            4) SC_SCAN=integrity; sc_run_requested;;
            5) SC_SCAN=aur-health; sc_run_requested;;
            6) sc_dependencies;;
            7) sc_update_action;;
            8) SC_DEMO=1; sc_demo review;;
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
    sc_ui_init
    if [[ -z $SC_LANG ]]; then
        if [[ -t 0 ]]; then sc_choose_language || return 0
        else printf '%s\n' "$(sc_t language_needed)" >&2; return 64; fi
    fi
    sc_ui_init
    if ((SC_DEMO)); then sc_demo "$SC_SCENARIO"; return 0; fi
    case $SC_ACTION in install) sc_dependencies install; return $?;; update) sc_update_action; return $?;; esac
    if [[ -n $SC_SCAN ]]; then sc_run_requested; return $?; fi
    [[ -t 0 ]] || { sc_help; return 64; }
    if sc_is_arch /etc/os-release && command -v pacman >/dev/null; then sc_dependencies startup; fi
    sc_menu
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then sc_main "$@"; fi

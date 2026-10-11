#!/usr/bin/env bash
# SecCheck 2.0 — Klod Cripta — MIT
# Standalone security assistant for Arch Linux and derivatives.
# Checks are read-only; initial rkhunter setup needs separate confirmation.
# Sourcing this file defines functions only: no traps, privilege changes or I/O.

SC_VERSION=2.0.0
SC_ALL_MODULES='rkhunter lynis integrity'

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
    SC_BASELINE_STATE='' SC_BASELINE_REASON='' SC_BASELINE_CHECKED=0
    SC_BASELINE_CONFIRMED=0 SC_BASELINE_ACTIVE=0 SC_RKH_CONTEXT_TAG=rkh-context
    declare -ga SC_BASELINE_PATHS=() SC_BASELINE_RECORDS=()
    local module
    for module in $SC_ALL_MODULES; do
        SC_MODULE_STATUS[$module]=not-run
        SC_MODULE_REASON[$module]=''
        SC_MODULE_RC[$module]=''
        SC_MODULE_VERSION[$module]=''
    done
    for module in ${1:-$SC_ALL_MODULES}; do
        case $module in rkhunter|lynis|integrity) SC_SELECTED+=("$module");; *) return 2;; esac
    done
    SC_INCOMPLETE=1 SC_COMPLETED=0 SC_URGENT=0 SC_REVIEW=0 SC_SUGGESTIONS=0 SC_INFO=0
    SC_ASSESSMENT=unknown
}

sc_module_set() {
    local module=$1 status=$2 reason=${3-}
    case $module in rkhunter|lynis|integrity) ;; *) return 2;; esac
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
    case $module in rkhunter|lynis|integrity) ;; *) return 2;; esac
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

sc_no_nul() {
    # A pattern file carries the NUL byte: neither argv nor command substitution
    # can preserve it. GNU grep checks the raw file before Bash read removes it.
    LC_ALL=C timeout 5 grep -aqF -f <(printf '\000') -- "$1" 2>/dev/null
    case $? in 1) return 0;; 0) return 1;; *) return 2;; esac
}

sc_parse_rkhunter() {
    local line lower key priority object normalized description hidden_kind prerequisite=0 optional candidate dev_list=0
    local -a words
    local script_re="^The command '(/[^']+)' has been replaced by a script:"
    local script_marker="' has been replaced by a script:" hidden_separator=': '
    local hidden_re='^Hidden (file|directory) found: (/.+)$'
    local file_re='^(/[^[:space:]]+)[[:blank:]]+\[ *Warning *\]$'
    SC_PARSE_UNKNOWN=0
    if ! sc_no_nul "$1"; then
        SC_PARSE_UNKNOWN=1
        sc_add_diagnostic rkhunter rkh_stream_unreadable "stream=$1; NUL byte or failed raw-input check"
        sc_rkh_finding rkh_path_unreadable review '' "Unparseable rkhunter stream: $1"
        return 0
    fi
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line#\[??:??:??\] }
        line=${line#"${line%%[![:space:]]*}"}
        line=${line%"${line##*[![:space:]]}"}
        lower=${line,,}
        if ((dev_list)); then
            if [[ $line == /* ]]; then
                # Native rkhunter lists these paths on following indented lines.
                # A repeated separator cannot identify an exact lookup target.
                object=${line%%"$hidden_separator"*}
                description=${line#*"$hidden_separator"}
                if [[ $object != /dev/* || $line != *"$hidden_separator"* ||
                      -z $description || $description == *"$hidden_separator"* ]]; then
                    SC_PARSE_UNKNOWN=1
                    sc_rkh_finding rkh_path_unreadable review '' "$line"
                else
                    sc_rkh_finding rkh_dev_file review "$object" "$line"
                fi
                continue
            fi
            dev_list=0
        fi
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
                    key=rkh_dev; object=/dev
                    [[ ${normalized,,} != 'suspicious file types found in /dev:' ]] || dev_list=1;;
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

sc_rkh_tool_allowed() {
    local executable i
    executable=$(command -v "$1") || return 0
    for i in "${!SC_F_MODULE[@]}"; do
        [[ ${SC_F_PRIORITY[i]} == urgent || ${SC_F_PRIORITY[i]} == review ]] || continue
        [[ ${SC_F_OBJECT[i]} == /* ]] || continue
        # Bash compares inode identity without running a resolver or either file.
        if [[ $executable == "${SC_F_OBJECT[i]}" || $executable -ef ${SC_F_OBJECT[i]} ]]; then return 1; fi
    done
    return 0
}

sc_rkh_check_dev() {
    local i=$1 object=${SC_F_OBJECT[$1]} prefix="$SC_RUN_DIR/${SC_RKH_CONTEXT_TAG:-rkh-context}.$1"
    local type uid gid mode owner extra rc size pids pid line executable package tool started=$SECONDS count=0
    local -a processes=()
    SC_F_CHECK_KEY[i]=rkh_dev_unknown
    SC_F_CHECK_DETAIL[i]="log=rkh-context.$i.stat / rkh-context.$i.fuser.stderr"
    [[ $object == /dev/* ]] || return
    for tool in timeout stat grep head tr fuser ps readlink pacman; do
        if ! sc_rkh_tool_allowed "$tool"; then
            SC_F_CHECK_KEY[i]=rkh_dev_tool_flagged
            SC_F_CHECK_DETAIL[i]="$(sc_t dev_flagged_tool): $tool"
            return
        fi
    done
    if [[ ! -e $object && ! -L $object ]]; then
        SC_F_CHECK_KEY[i]=rkh_dev_missing; return
    fi
    # Record link/device metadata without reading contents or following targets.
    sc_capture "$prefix.stat" "$prefix.stat.stderr" 3 stat -c '%F|%u|%g|%a|%U' -- "$object"
    rc=$?
    ((rc == 0)) && [[ ! -s $prefix.stat.stderr ]] || return
    IFS='|' read -r type uid gid mode owner extra < "$prefix.stat"
    [[ $uid =~ ^[0-9]{1,10}$ && $gid =~ ^[0-9]{1,10}$ && $mode =~ ^[0-7]{1,4}$ && -z $extra ]] || return
    SC_F_CHECK_DETAIL[i]="$(sc_t dev_owner): $(sc_text "$owner") (UID $uid); $(sc_t dev_permissions): $mode"
    if [[ ( $type != 'regular file' && $type != 'regular empty file' ) || ! -f $object || -L $object ]]; then
        SC_F_CHECK_KEY[i]=rkh_dev_nonregular; return
    fi
    if ! command -v fuser >/dev/null; then SC_F_CHECK_KEY[i]=rkh_dev_tool_missing; return; fi
    # fuser does not reliably accept --. The validated absolute /dev/ path
    # cannot be an option. No -k, signals, mount-wide search or file execution.
    sc_capture "$prefix.fuser" "$prefix.fuser.stderr" 5 fuser -v "$object"
    rc=$?
    size=$(timeout 2 stat -c '%s' -- "$prefix.fuser") || return
    [[ $size =~ ^[0-9]{1,10}$ ]] && ((size <= 4096)) || return
    sc_no_nul "$prefix.fuser" || return
    pids=$(<"$prefix.fuser")
    if ((rc == 1)) && [[ -z $pids && ! -s $prefix.fuser.stderr ]]; then
        SC_F_CHECK_KEY[i]=rkh_dev_idle; return
    fi
    ((rc == 0)) && [[ -n $pids && $pids != *[!0-9$' \t\r\n']* ]] || return
    read -r -a processes <<< "${pids//$'\n'/ }"
    ((${#processes[@]})) || return
    for pid in "${processes[@]}"; do
        [[ $pid =~ ^[1-9][0-9]{0,9}$ ]] || return
    done
    SC_F_CHECK_KEY[i]=rkh_dev_process
    for pid in "${processes[@]}"; do
        ((count < 3 && SECONDS-started < 20)) || {
            SC_F_CHECK_DETAIL[i]+="; $(sc_t dev_more_processes)"; break;
        }
        ((count+=1))
        # Process identity is a live observation, not proof of who created the file.
        sc_capture "$prefix.ps.$pid" "$prefix.ps.$pid.stderr" 2 ps -p "$pid" -o pid=,uid=,comm=
        rc=$?
        if ((rc != 0)) || [[ -s $prefix.ps.$pid.stderr ]]; then
            SC_F_CHECK_DETAIL[i]+="; PID $pid: $(sc_t dev_process_unavailable)"; continue
        fi
        sc_no_nul "$prefix.ps.$pid" || continue
        line=$(timeout 2 head -c 256 -- "$prefix.ps.$pid")
        if [[ ! $line =~ ^[[:blank:]]*([0-9]+)[[:blank:]]+([0-9]+)[[:blank:]]+([^$'\n']+)$ || ${BASH_REMATCH[1]} != "$pid" ]]; then
            SC_F_CHECK_DETAIL[i]+="; PID $pid: $(sc_t dev_process_unavailable)"; continue
        fi
        SC_F_CHECK_DETAIL[i]+="; $(sc_t dev_program): $(sc_text "${BASH_REMATCH[3]}") (PID $pid, UID ${BASH_REMATCH[2]})"
        ((SECONDS-started < 20)) || { SC_F_CHECK_DETAIL[i]+="; $(sc_t dev_more_processes)"; break; }
        sc_capture "$prefix.exe.$pid" "$prefix.exe.$pid.stderr" 2 readlink -n -- "/proc/$pid/exe"
        rc=$?
        ((rc == 0)) && [[ ! -s $prefix.exe.$pid.stderr ]] || continue
        size=$(timeout 2 stat -c '%s' -- "$prefix.exe.$pid") || continue
        [[ $size =~ ^[0-9]{1,10}$ ]] || continue
        ((size <= 4096)) || continue
        sc_no_nul "$prefix.exe.$pid" || continue
        # Preserve even a filename ending in LF; command substitution normally
        # strips it and could ask pacman about an unrelated executable.
        executable=$(timeout 2 head -c 4097 -- "$prefix.exe.$pid"; printf '.')
        executable=${executable%.}
        [[ $executable == /* && ${#executable} -le 4096 && $executable == "$(sc_text "$executable")" ]] || continue
        ((SECONDS-started < 20)) || { SC_F_CHECK_DETAIL[i]+="; $(sc_t dev_more_processes)"; break; }
        sc_capture "$prefix.package.$pid" "$prefix.package.$pid.stderr" 2 pacman -Qqo -- "$executable"
        rc=$?
        ((rc == 0)) && [[ ! -s $prefix.package.$pid.stderr ]] || continue
        sc_no_nul "$prefix.package.$pid" || continue
        package=$(timeout 2 head -c 257 -- "$prefix.package.$pid")
        [[ ${#package} -le 256 && $package =~ ^[A-Za-z0-9@_+.-]+$ ]] || continue
        SC_F_CHECK_DETAIL[i]+="; $(sc_t dev_program_package): $package"
    done
}

sc_rkh_check_file() {
    local i=$1 object=${SC_F_OBJECT[$1]} prefix=${2:-"$SC_RUN_DIR/${SC_RKH_CONTEXT_TAG:-rkh-context}.$1"}
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
    SC_F_CHECK_DETAIL[i]="log=${prefix##*/}.pacfile / ${prefix##*/}.stderr"
    ((rc == 0)) && [[ ! -s $prefix.stderr ]] || return
    sc_no_nul "$prefix.pacfile" || return
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
    SC_F_CHECK_DETAIL[i]="$(sc_t package): $package; log=${prefix##*/}.pacfile / ${prefix##*/}.sha256"
    if [[ $actual != "$digest" ]]; then SC_F_CHECK_KEY[i]=rkh_file_changed
    elif ((metadata)); then SC_F_CHECK_KEY[i]=rkh_file_metadata
    else SC_F_CHECK_KEY[i]=rkh_file_match; SC_F_PRIORITY[i]=info; SC_F_CONFIDENCE[i]=observation; fi
}

sc_rkh_ssh_evidence() {
    local i=$1 command=$2 rc=$3 prefix=${4:-"$SC_RUN_DIR/${SC_RKH_CONTEXT_TAG:-rkh-context}.$1"} excerpt
    # Show a short, inert excerpt; the full original streams stay in the report directory.
    excerpt=$(timeout 2 head -c 320 -- "$prefix.stderr" 2>/dev/null)
    [[ -n $excerpt ]] || excerpt=$(timeout 2 head -c 320 -- "$prefix.ssh" 2>/dev/null)
    SC_F_CHECK_DETAIL[i]="$command: exit=$rc; $(sc_text "$excerpt")"
}

sc_rkh_check_ssh() {
    local i=$1 prefix="$SC_RUN_DIR/${SC_RKH_CONTEXT_TAG:-rkh-context}.$1" value='' line rc major minor count=0 j executable resolved other guard_started=$SECONDS
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
    SC_F_CHECK_DETAIL[i]="log=${prefix##*/}.ssh / ${prefix##*/}.stderr"
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
            # Native sshd versions use both lowercase and canonical keyword case.
            if [[ ${line,,} == 'permitrootlogin '* ]]; then value=${line#* }; ((count+=1)); fi
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
    local i hidden=0 dev=0 name checked=0 started=$SECONDS
    SC_RKH_CONTEXT_PARTIAL=0
    for name in "${SC_F_KEY[@]}"; do
        [[ $name == rkh_hidden_file || $name == rkh_hidden_directory ]] && hidden=1
        [[ $name != rkh_dev_file ]] || dev=1
    done
    if ((hidden || dev)); then
        for i in "${!SC_F_KEY[@]}"; do
            if [[ ${SC_F_KEY[i]} != rkh_hidden_summary || $hidden == 0 ]] &&
               [[ ${SC_F_KEY[i]} != rkh_dev || $dev == 0 ]]; then continue; fi
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
            rkh_script|rkh_hidden_file|rkh_file_warning|rkh_ssh_root|rkh_ssh_protocol|rkh_dev_file) ;;
            *) continue;;
        esac
        if ((checked >= 40 || SECONDS-started >= 180)); then
            SC_F_CHECK_KEY[i]=rkh_context_limit; SC_RKH_CONTEXT_PARTIAL=1; continue
        fi
        ((checked+=1))
        case ${SC_F_KEY[i]} in
            rkh_ssh_*) sc_rkh_check_ssh "$i";;
            rkh_dev_file) sc_rkh_check_dev "$i";;
            *) sc_rkh_check_file "$i";;
        esac
        case ${SC_F_CHECK_KEY[i]} in
            rkh_file_unknown|rkh_file_tool_missing|rkh_file_nonregular|rkh_context_limit|rkh_ssh_unknown|rkh_ssh_flagged|rkh_dev_unknown|rkh_dev_tool_missing|rkh_dev_missing|rkh_dev_nonregular|rkh_dev_tool_flagged)
                SC_RKH_CONTEXT_PARTIAL=1;;
        esac
    done
    SC_SCOPE+=('rkhunter context: up to 40 checks / 180s plus one in-flight check; regular files <=64MiB; exact pacfile MTREE record + SHA-256; local package records do not prove trusted origin. SSH uses default configuration, not every Match context or running daemon.')
    ((dev == 0)) || SC_SCOPE+=('/dev context: exact parsed paths, stat without dereferencing links, optional fuser -v; up to three process identities per file / 20s before another ps/readlink/pacman query. Raw input is checked before Bash can discard NUL/LF; identified flagged utilities are not launched. Live usage and executable package ownership do not establish the creator or trusted origin. No file contents read, processes stopped or data removed.')
}

sc_run_rkhunter() {
    if ! command -v rkhunter >/dev/null; then sc_module_set rkhunter skipped missing_rkhunter; return 0; fi
    sc_module_set rkhunter running ''
    SC_MODULE_VERSION[rkhunter]=$(sc_version rkhunter --version)
    local prefix=${1:-"$SC_RUN_DIR/rkhunter"}
    local out="$prefix.stdout" err="$prefix.stderr"
    local raw="$prefix.log" parsed rc line errors=0 unknown=0 reason
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

# ---- Guided first baseline: package checks, consent, staged native output -----
sc_baseline_safe_path() {
    [[ $1 == /* && $1 != / && ${#1} -le 4096 && $1 == "$(sc_text "$1")" &&
       $1 != *:* && $1 != *"'"* && $1 != *'//'* && $1 != */./* && $1 != */../* &&
       $1 != */. && $1 != */.. && $1 != */ ]]
}

sc_baseline_trusted_dir() {
    local path=$1 resolved data uid mode
    sc_baseline_safe_path "$path" || return 1
    resolved=$(timeout 5 readlink -fn -- "$path") || return 1
    [[ $resolved == "$path" && -d $path && ! -L $path ]] || return 1
    while [[ $path != / ]]; do
        data=$(timeout 5 stat -c '%u %a' -- "$path") || return 1
        read -r uid mode <<< "$data"
        [[ ( $uid == 0 || $uid == "$EUID" ) && $mode =~ ^[0-7]{3,4}$ ]] || return 1
        # A root-owned sticky ancestor (e.g. /tmp) is permitted, but the
        # database directory itself must never be shared/writable by others.
        if (( (8#$mode & 0022) != 0 )); then
            [[ $path != "$1" && $uid == 0 ]] && (( (8#$mode & 01000) != 0 )) || return 1
        fi
        path=${path%/*}; [[ -n $path ]] || path=/
    done
}

sc_baseline_guard() {
    local tool i
    for i in "${!SC_F_PRIORITY[@]}"; do
        [[ ${SC_F_PRIORITY[i]} != urgent ]] || return 1
        # Native rkhunter launches indirect/configured utilities too. Do not
        # start it while an identified executable remains under suspicion.
        if [[ ${SC_F_PRIORITY[i]} == review && ${SC_F_OBJECT[i]} == /* && -x ${SC_F_OBJECT[i]} && ! -d ${SC_F_OBJECT[i]} ]]; then return 1; fi
    done
    for tool in rkhunter pacfile timeout stat readlink sha256sum grep tr head cat cp chmod mkdir mktemp ln mv rm; do
        command -v "$tool" >/dev/null && sc_rkh_tool_allowed "$tool" || return 1
    done
}

sc_baseline_input_file() {
    local file=$1 data uid mode bytes
    [[ -f $file && ! -L $file ]] || return 1
    data=$(timeout 5 stat -c '%u %a %s' -- "$file") || return 1
    read -r uid mode bytes <<< "$data"
    [[ ( $uid == 0 || $uid == "$EUID" ) && $mode =~ ^[0-7]{3,4}$ && $bytes =~ ^[0-9]{1,10}$ ]] || return 1
    (( (8#$mode & 0022) == 0 && bytes > 0 && bytes <= 1048576 )) && sc_no_nul "$file"
}

sc_baseline_target_missing() {
    local path="$SC_BASELINE_DB/rkhunter.dat"
    # There is no shell-level compare-and-swap replacement for an empty file.
    # Create-only installation must not overwrite a concurrently populated one.
    [[ ! -e $path && ! -L $path ]]
}

sc_baseline_link() {
    local object=$1 prefix=$2 line field value rc files=0 owners=0 modes=0 types=0 uids=0 groups=0 targets=0
    local recorded='' target='' link=''
    sc_capture "$prefix.link" "$prefix.link.stderr" 5 pacfile --check -- "$object"
    rc=$?
    ((rc == 0)) && [[ ! -s $prefix.link.stderr ]] && sc_no_nul "$prefix.link" || return 1
    while IFS= read -r line || [[ -n $line ]]; do
        field=${line%%:*}; value=${line#*:}; value=${value#"${value%%[![:space:]]*}"}
        case $field in
            file) ((files+=1)); recorded=$value;;
            owner)
                if [[ $value =~ ^[A-Za-z0-9@_+.-]+$ ]]; then ((owners+=1));
                elif [[ $value =~ ^[0-9]+/[^\(]*$ ]]; then ((uids+=1)); fi;;
            group) [[ $value =~ ^[0-9]+/[^\(]*$ ]] && ((groups+=1));;
            mode) [[ $value =~ ^[0-7]{3,4}$ ]] && ((modes+=1));;
            type) [[ $value == link ]] && ((types+=1));;
            target) ((targets+=1)); target=$value;;
        esac
    done < "$prefix.link"
    ((files == 1 && owners == 1 && modes == 1 && types == 1 && uids == 1 && groups == 1 && targets == 1)) || return 1
    [[ $recorded == "${object#/}" && -n $target && $target != *:* ]] || return 1
    sc_capture "$prefix.target" "$prefix.target.stderr" 5 readlink -n -- "$object"
    rc=$?
    ((rc == 0)) && [[ ! -s $prefix.target.stderr ]] && sc_no_nul "$prefix.target" || return 1
    link=$(cat "$prefix.target"; printf '.'); link=${link%.}
    [[ $link == "$target" && $link == "$(sc_text "$link")" ]]
}

sc_baseline_file() {
    local object=$1 prefix=$2 canonical parent='' part rc link='' digest='' attrs='' i=${#SC_F_OBJECT[@]} n=0
    local -a parts=()
    SC_BASELINE_FILE_KEY=rkh_file_unknown
    SC_BASELINE_FILE_DETAIL="log=${prefix##*/}.*"
    # Check every parent alias as a package symlink before resolving it. Merely
    # checking /usr/bin/tool cannot establish the metadata of /bin itself.
    IFS=/ read -r -a parts <<< "${object#/}"
    for part in "${parts[@]:0:${#parts[@]}-1}"; do
        parent+="/$part"
        if [[ -L $parent ]]; then
            sc_baseline_link "$parent" "$prefix.parent.$n" || return 1
            sc_capture "$prefix.parent" "$prefix.parent.stderr" 5 readlink -fn -- "$parent"
            rc=$?
            ((rc == 0)) && [[ ! -s $prefix.parent.stderr ]] && sc_no_nul "$prefix.parent" || return 1
            parent=$(cat "$prefix.parent"; printf '.'); parent=${parent%.}
            sc_baseline_safe_path "$parent" || return 1
        fi
        ((n+=1))
    done
    canonical="$parent/${object##*/}"
    if [[ -L $canonical ]]; then
        sc_baseline_link "$canonical" "$prefix" || return 1
        sc_capture "$prefix.resolve" "$prefix.resolve.stderr" 5 readlink -fn -- "$canonical"
        rc=$?
        ((rc == 0)) && [[ ! -s $prefix.resolve.stderr ]] && sc_no_nul "$prefix.resolve" || return 1
        canonical=$(cat "$prefix.resolve"; printf '.'); canonical=${canonical%.}
        sc_baseline_safe_path "$canonical" || return 1
        link=$canonical
    fi
    # Reuse the strict regular-file verifier in a temporary numeric slot;
    # baseline checks never change the user's existing finding outcomes.
    SC_F_OBJECT[i]=$canonical SC_F_PRIORITY[i]=review SC_F_CONFIDENCE[i]=observation
    sc_rkh_check_file "$i" "$prefix"
    SC_BASELINE_FILE_KEY=${SC_F_CHECK_KEY[i]}
    unset 'SC_F_OBJECT[i]' 'SC_F_PRIORITY[i]' 'SC_F_CONFIDENCE[i]' 'SC_F_CHECK_KEY[i]' 'SC_F_CHECK_DETAIL[i]'
    [[ $SC_BASELINE_FILE_KEY == rkh_file_match ]] || return 1
    read -r digest _ < "$prefix.sha256"
    attrs=$(timeout 5 stat -c '%i:0%a:%u:%g:%s:%Y' -- "$object") || return 1
    [[ $attrs =~ ^[0-9]+:0[0-7]{3,4}:[0-9]+:[0-9]+:[0-9]+:-?[0-9]+$ ]] || return 1
    # Native rkhunter stores exactly four mode digits, including setuid/sticky.
    [[ ! $attrs =~ ^[0-9]+:0[0-7]{4}: ]] || attrs="${attrs%%:*}:${attrs#*:0}"
    SC_BASELINE_RECORD="File:0:$object:$digest:$attrs::0:$link:"
}

sc_baseline_prepare() {
    local raw="$SC_RUN_DIR/rkhunter.log" line directory='' count=0 path seen i started=$SECONDS hash=''
    SC_BASELINE_STATE=blocked SC_BASELINE_REASON=baseline_unavailable SC_BASELINE_CHECKED=0
    SC_BASELINE_PATHS=() SC_BASELINE_RECORDS=()
    sc_baseline_guard || { SC_BASELINE_REASON=baseline_guard; return 0; }
    [[ -f $raw && ! -L $raw ]] && sc_no_nul "$raw" || return 0
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line#\[*\] }; line=${line#'Info: '}
        if [[ $line == "Using '"*"' as the database directory" ]]; then
            ((count+=1)); directory=${line#"Using '"}; directory=${directory%"' as the database directory"}
        fi
        if [[ $line == "No package manager specified: using hash function '"*"'" ]]; then
            [[ -z $hash ]] || { SC_BASELINE_REASON=baseline_hash; return 0; }
            hash=${line#"No package manager specified: using hash function '"}; hash=${hash%"'"}
        fi
    done < "$raw"
    ((count == 1)) || return 0
    sc_baseline_trusted_dir "$directory" || return 0
    SC_BASELINE_DB=$directory
    if ! sc_baseline_target_missing; then
        SC_BASELINE_REASON=baseline_exists
        [[ ! -f $directory/rkhunter.dat || -L $directory/rkhunter.dat || -s $directory/rkhunter.dat ]] || SC_BASELINE_REASON=baseline_empty
        return 0
    fi
    SC_BASELINE_HASH_COMMAND=$(command -v sha256sum) || return 0
    if [[ ! $hash =~ ^/[A-Za-z0-9_./+-]+$ || ! $hash -ef $SC_BASELINE_HASH_COMMAND ]]; then
        SC_BASELINE_REASON=baseline_hash; return 0
    fi
    # rkhunter compares the recorded command string as well as the algorithm.
    # Preserve its native path even when /bin and /usr/bin identify one inode.
    SC_BASELINE_HASH_COMMAND=$hash
    path="$directory/rkhunter_prop_list.dat"
    sc_baseline_input_file "$path" && sc_baseline_trusted_dir "$directory/i18n" &&
        sc_baseline_input_file "$directory/i18n/en" || return 0
    cp -- "$path" "$SC_RUN_DIR/baseline-paths.txt" || return 0
    count=0
    while IFS= read -r line || [[ -n $line ]]; do
        ((count+=1)); ((count <= 10000)) && sc_baseline_safe_path "$line" || return 0
        # Native rkhunter skips absent candidates and directories. Broken
        # symlinks are retained and fail verification, rather than being skipped.
        [[ -f $line || -L $line ]] || continue
        seen=0
        for path in "${SC_BASELINE_PATHS[@]}"; do [[ $line != "$path" ]] || seen=1; done
        ((seen == 0)) || continue
        ((${#SC_BASELINE_PATHS[@]} < 512 && SECONDS-started < 240)) || { SC_BASELINE_REASON=baseline_limit; return 0; }
        SC_BASELINE_PATHS+=("$line")
    done < "$SC_RUN_DIR/baseline-paths.txt"
    ((${#SC_BASELINE_PATHS[@]} > 0)) || return 0
    printf 'path\tresult\tdetail\n' > "$SC_RUN_DIR/baseline-checks.tsv"
    for i in "${!SC_BASELINE_PATHS[@]}"; do
        ((SECONDS-started < 240)) || { SC_BASELINE_REASON=baseline_limit; return 0; }
        path=${SC_BASELINE_PATHS[i]}
        if ! sc_baseline_file "$path" "$SC_RUN_DIR/baseline-file.$i"; then
            printf '%s\t%s\t%s\n' "$path" "$SC_BASELINE_FILE_KEY" "$SC_BASELINE_FILE_DETAIL" >> "$SC_RUN_DIR/baseline-checks.tsv"
            SC_BASELINE_REASON=baseline_files
            sc_add_finding rkhunter baseline review observation "$path" baseline_files "$(sc_t baseline_files)"
            i=$((${#SC_F_MODULE[@]}-1))
            SC_F_CHECK_KEY[i]=$SC_BASELINE_FILE_KEY SC_F_CHECK_DETAIL[i]=$SC_BASELINE_FILE_DETAIL
            return 0
        fi
        SC_BASELINE_RECORDS+=("$SC_BASELINE_RECORD")
        ((SC_BASELINE_CHECKED+=1))
        printf '%s\t%s\t%s\n' "$path" "$SC_BASELINE_FILE_KEY" "$SC_BASELINE_FILE_DETAIL" >> "$SC_RUN_DIR/baseline-checks.tsv"
        if ((SC_BASELINE_CHECKED % 25 == 0)); then sc_line "$(sc_t baseline_checking): $SC_BASELINE_CHECKED" "$SC_C_MUTED"; fi
    done
    SC_BASELINE_STATE=ready SC_BASELINE_REASON=''
}

sc_baseline_validate_candidate() {
    local file=$1 line bytes i match count=0 hash=0 attrs=0 format=0 pkg=0 version=0 field object label
    local -a actual=() expected=()
    SC_BASELINE_FAILURE="candidate: missing, unreadable, binary or oversized reference"
    local -a seen=()
    [[ -f $file && ! -L $file ]] || return 1
    bytes=$(timeout 5 stat -c '%s' -- "$file") || return 1
    [[ $bytes =~ ^[0-9]{1,10}$ ]] && ((bytes > 0 && bytes <= 1048576)) && sc_no_nul "$file" || return 1
    while IFS= read -r line || [[ -n $line ]]; do
        SC_BASELINE_FAILURE="candidate header: $(sc_text "${line%%:*}")"
        case $line in
            Hash:*) [[ $line == "Hash:$SC_BASELINE_HASH_COMMAND" ]] || return 1; ((hash+=1));;
            Attributes:*) [[ $line == Attributes:Stored ]] || return 1; ((attrs+=1));;
            FormatVersion:*) [[ $line == FormatVersion:1 ]] || return 1; ((format+=1));;
            Pkgmgr:*) [[ $line == Pkgmgr: ]] || return 1; ((pkg+=1));;
            Version:*) [[ $line =~ ^Version:[0-9]{10}$ ]] || return 1; ((version+=1));;
            File:*)
                match=0
                for i in "${!SC_BASELINE_RECORDS[@]}"; do
                    if [[ $line == "${SC_BASELINE_RECORDS[i]}" ]]; then
                        [[ ${seen[i]:-0} == 0 ]] || return 1
                        seen[i]=1; match=1; ((count+=1)); break
                    fi
                done
                if ((match == 0)); then
                    IFS=: read -r -a actual <<< "$line"
                    object=${actual[2]:-unknown}
                    SC_BASELINE_FAILURE="candidate: $(sc_text "$object"); unverified record"
                    for i in "${!SC_BASELINE_RECORDS[@]}"; do
                        IFS=: read -r -a expected <<< "${SC_BASELINE_RECORDS[i]}"
                        [[ ${expected[2]:-} == "$object" ]] || continue
                        SC_BASELINE_FAILURE="candidate: $(sc_text "$object"); different properties:"
                        for field in 1 3 4 5 6 7 8 9 10 11 12; do
                            [[ ${actual[field]:-} != "${expected[field]:-}" ]] || continue
                            case $field in
                                1) label="path-format";; 3) label=SHA256;; 4) label=inode;; 5) label=permissions;;
                                6) label=UID;; 7) label=GID;; 8) label=size;; 9) label=mtime;;
                                10) label=package;; 11) label="link-format";; 12) label="link-target";;
                            esac
                            SC_BASELINE_FAILURE+=" $label"
                        done
                        break
                    done
                    return 1
                fi;;
            Host:*|Arch:*|OS:*|Prelinked:No) ;;
            *) return 1;;
        esac
    done < "$file"
    SC_BASELINE_FAILURE="candidate: headers or file count invalid; checked=$count expected=$SC_BASELINE_CHECKED"
    ((hash == 1 && attrs == 1 && format == 1 && pkg == 1 && version == 1 && count == SC_BASELINE_CHECKED && count > 0))
}

sc_baseline_create() {
    local stage rc install='' path i record line started=$SECONDS
    [[ $SC_BASELINE_CONFIRMED == 1 && $SC_BASELINE_STATE == ready ]] || return 1
    SC_BASELINE_STATE=failed SC_BASELINE_REASON=baseline_failed
    SC_BASELINE_FAILURE="preparation: safety checks or database permissions"
    sc_baseline_guard && sc_baseline_trusted_dir "$SC_BASELINE_DB" && sc_baseline_target_missing || return 1
    # Recheck after the user's decision; do not register files changed while
    # the confirmation was on screen. Candidate validation also pins the set.
    for i in "${!SC_BASELINE_PATHS[@]}"; do
        ((SECONDS-started < 240)) || return 1
        SC_BASELINE_FAILURE="confirmation: $(sc_text "${SC_BASELINE_PATHS[i]}"); file changed or verification failed"
        record=${SC_BASELINE_RECORDS[i]}
        sc_baseline_file "${SC_BASELINE_PATHS[i]}" "$SC_RUN_DIR/baseline-confirm.$i" || return 1
        [[ $SC_BASELINE_RECORD == "$record" ]] || return 1
    done
    SC_BASELINE_FAILURE="preparation: temporary folder or language file"
    stage=$(umask 077; mktemp -d "$SC_RUN_DIR/baseline-candidate.XXXXXX") || return 1
    mkdir -m 700 -- "$stage/i18n" || return 1
    sc_baseline_trusted_dir "$SC_BASELINE_DB/i18n" && sc_baseline_input_file "$SC_BASELINE_DB/i18n/en" || return 1
    cp -- "$SC_BASELINE_DB/i18n/en" "$stage/i18n/en" || return 1
    [[ $SC_BASELINE_HASH_COMMAND == /* ]] || return 1
    sc_capture "$SC_RUN_DIR/baseline-create.stdout" "$SC_RUN_DIR/baseline-create.stderr" 240 \
        rkhunter --propupd --dbdir "$stage" --hash "$SC_BASELINE_HASH_COMMAND" --pkgmgr NONE \
        --nocolors --lang en --logfile "$SC_RUN_DIR/baseline-create.log"
    rc=$?
    SC_BASELINE_FAILURE="rkhunter --propupd: exit=$rc; binary or unreadable stderr"
    ((rc == 0)) && sc_no_nul "$SC_RUN_DIR/baseline-create.stderr" || return 1
    while IFS= read -r line || [[ -n $line ]]; do
        case $line in
            '') ;;
            'egrep: warning: egrep is obsolescent; using grep -E')
                sc_add_diagnostic rkhunter rkh_legacy_grep "$line";;
            *) SC_BASELINE_FAILURE="rkhunter --propupd: $(sc_text "$line")"; return 1;;
        esac
    done < "$SC_RUN_DIR/baseline-create.stderr"
    sc_baseline_validate_candidate "$stage/rkhunter.dat" || return 1
    SC_BASELINE_FAILURE="installation: database permissions or reference appeared meanwhile"
    sc_baseline_trusted_dir "$SC_BASELINE_DB" && sc_baseline_target_missing || return 1
    install=$(umask 077; mktemp "$SC_BASELINE_DB/.seccheck-baseline.XXXXXX") || return 1
    SC_BASELINE_FAILURE="installation: private copy, permissions or exclusive creation"
    if ! cp -- "$stage/rkhunter.dat" "$install" || ! chmod 600 -- "$install"; then rm -f -- "$install"; return 1; fi
    path="$SC_BASELINE_DB/rkhunter.dat"
    ln -T -- "$install" "$path" > "$SC_RUN_DIR/baseline-install.stdout" 2> "$SC_RUN_DIR/baseline-install.stderr"; rc=$?
    rm -f -- "$install"
    ((rc == 0)) || return 1
    SC_BASELINE_STATE=created SC_BASELINE_REASON=''
    sc_add_diagnostic rkhunter baseline_created "db=$SC_BASELINE_DB; verified=$SC_BASELINE_CHECKED; explicit consent; staged SHA-256 baseline"
    return 0
}

sc_baseline_repeat() {
    local i file prefix="$SC_RUN_DIR/rkhunter-repeat"
    for file in report.txt findings.tsv checks.tsv modules.tsv; do
        [[ ! -f $SC_RUN_DIR/$file ]] || cp -- "$SC_RUN_DIR/$file" "$SC_RUN_DIR/before-setup.$file" || return 73
    done
    # Initial findings stay in the model even if a transient indicator is no
    # longer present. Only old coverage diagnostics move to their audit file.
    {
        printf 'module\tkey\tevidence\n'
        for i in "${!SC_D_MODULE[@]}"; do
            [[ ${SC_D_MODULE[i]} == rkhunter ]] || continue
            printf '%s\t%s\t%s\n' rkhunter "${SC_D_KEY[i]}" "${SC_D_EVIDENCE[i]}"
            [[ ${SC_D_KEY[i]} == baseline_created ]] && continue
            unset 'SC_D_MODULE[i]' 'SC_D_KEY[i]' 'SC_D_EVIDENCE[i]'
        done
    } > "$SC_RUN_DIR/rkhunter-before-setup.tsv"
    SC_D_MODULE=("${SC_D_MODULE[@]}") SC_D_KEY=("${SC_D_KEY[@]}") SC_D_EVIDENCE=("${SC_D_EVIDENCE[@]}")
    SC_RKH_OPTIONAL=()
    sc_run_rkhunter "$prefix"
    SC_RKH_CONTEXT_TAG=rkh-repeat-context
    sc_interpret_rkhunter
    SC_RKH_CONTEXT_TAG=rkh-context
    if ((SC_RKH_CONTEXT_PARTIAL)) && [[ ${SC_MODULE_STATUS[rkhunter]} == completed ]]; then
        sc_module_set rkhunter partial rkh_context_limited
    fi
    SC_SCOPE+=('Initial rkhunter setup: full native properties list; <=512 existing files / 240s before another check; local pacfile MTREE + SHA-256; separate consent; staged candidate exact records. Initial log and pre-setup diagnostics retained. Unexplained initial findings remain open.')
}

sc_offer_initial_baseline() {
    local i answer missing=0
    [[ -t 0 ]] || return 0
    for i in "${!SC_D_MODULE[@]}"; do
        [[ ${SC_D_MODULE[i]} == rkhunter && ${SC_D_KEY[i]} == rkh_baseline_missing ]] && missing=1
    done
    ((missing)) || return 0
    sc_line "$(sc_t rkh_baseline_short)" "$SC_C_AMBER"
    sc_line "$(sc_t baseline_help)" "$SC_C_WHITE$SC_C_BOLD"
    printf '  > '; IFS= read -r answer || answer=''
    case $answer in
        s|S|y|Y)
            sc_interpret_rkhunter
            sc_offer_baseline initial || return $?
            SC_RUN_ACTIVE=1
            trap sc_abort INT TERM;;
    esac
}

sc_offer_baseline() {
    local i missing=0 answer
    for i in "${!SC_D_MODULE[@]}"; do
        [[ ${SC_D_MODULE[i]} == rkhunter && ${SC_D_KEY[i]} == rkh_baseline_missing ]] && missing=1
    done
    ((missing)) || return 0
    sc_heading baseline_setup
    sc_line "$(sc_t baseline_explain)"
    sc_line "$(sc_t baseline_checking)" "$SC_C_WHITE"
    SC_RUN_ACTIVE=1 SC_BASELINE_ACTIVE=1
    trap sc_abort INT TERM
    sc_baseline_prepare
    if [[ $SC_BASELINE_STATE == ready ]]; then
        sc_line "$(sc_t baseline_verified): $SC_BASELINE_CHECKED" "$SC_C_WHITE$SC_C_BOLD"
        sc_line "$(sc_t baseline_limits)" "$SC_C_WHITE$SC_C_ITALIC"
        sc_line "$(sc_t baseline_question)" "$SC_C_WHITE$SC_C_BOLD"
        printf '  > '; IFS= read -r answer || answer=''
        case $answer in
            s|S|y|Y)
                SC_BASELINE_CONFIRMED=1
                sc_line "$(sc_t baseline_creating)"
                if sc_baseline_create; then
                    sc_line "$(sc_t baseline_repeating)"
                    sc_baseline_repeat || { SC_RUN_ACTIVE=0 SC_BASELINE_ACTIVE=0; trap - INT TERM; sc_line "$(sc_t save_error)"; return 73; }
                fi;;
            *) SC_BASELINE_STATE=declined SC_BASELINE_REASON=baseline_declined;;
        esac
    fi
    sc_add_diagnostic rkhunter baseline_setup "state=$SC_BASELINE_STATE; reason=$SC_BASELINE_REASON; checked=$SC_BASELINE_CHECKED; consent=$SC_BASELINE_CONFIRMED"
    [[ $SC_BASELINE_STATE != created ]] || sc_line "$(sc_t baseline_created)" "$SC_C_GREEN"
    [[ -z $SC_BASELINE_REASON ]] || sc_line "$(sc_t "$SC_BASELINE_REASON")" "$SC_C_AMBER"
    if [[ $SC_BASELINE_STATE == failed ]]; then
        sc_line "$(sc_t baseline_failure_cause): $(sc_text "${SC_BASELINE_FAILURE:-unknown}")" "$SC_C_AMBER"
        printf '%s\n' "${SC_BASELINE_FAILURE:-unknown}" > "$SC_RUN_DIR/baseline-failure.txt"
        sc_add_diagnostic rkhunter baseline_failure "${SC_BASELINE_FAILURE:-unknown}"
    fi
    sc_assess
    sc_save_report || { SC_RUN_ACTIVE=0 SC_BASELINE_ACTIVE=0; trap - INT TERM; sc_line "$(sc_t save_error)"; return 73; }
    SC_RUN_ACTIVE=0 SC_BASELINE_ACTIVE=0; trap - INT TERM
    [[ $SC_BASELINE_STATE != created || ${1:-} == initial ]] || sc_render_summary
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

# ---- Language: authored explanations, never translate upstream evidence -----
sc_t() {
    local en it
    case $1 in
        context_accounts) en="These files record accounts, passwords and groups. They change when users or services are added."; it="Questi file registrano account, password e gruppi. Cambiano quando aggiungi utenti o servizi.";;
        action_accounts) en="Check accounts you do not recognize. Restoring the package defaults can remove your access."; it="Controlla gli account che non riconosci. Ripristinare gli originali può farti perdere l’accesso.";;
        context_dns) en="These settings control network name resolution. Your connection may update them."; it="Queste impostazioni traducono i nomi di rete in indirizzi. La connessione può aggiornarle.";;
        action_dns) en="Compare the settings with those provided by your network or chosen by you."; it="Confronta le impostazioni con quelle della tua rete o scelte da te.";;
        context_repositories) en="These settings choose the software repositories and download servers."; it="Queste impostazioni scelgono i repository del software e i server di download.";;
        action_repositories) en="Check that the repositories and mirrors are the ones you chose. Keep signature verification enabled."; it="Verifica che repository e mirror siano quelli scelti da te. Mantieni attiva la verifica delle firme.";;
        context_login) en="These rules control login and administrator access."; it="Queste regole controllano l’accesso al computer e i permessi di amministratore.";;
        action_login) en="Review the changes carefully. Incorrect rules can block login."; it="Verifica con attenzione le modifiche. Regole sbagliate possono bloccare l’accesso.";;
        context_preferences) en="This file records enabled languages or login shells. System setup can change it."; it="Questo file registra le lingue o le shell abilitate. La configurazione del sistema può cambiarlo.";;
        action_preferences) en="Compare it with your chosen languages or shells before restoring it."; it="Confrontalo con le lingue o le shell che hai scelto prima di ripristinarlo.";;
        lynis_audit) en="Lynis suggests an extra check for known package vulnerabilities."; it="Lynis suggerisce un controllo aggiuntivo delle vulnerabilità note dei pacchetti.";;
        lynis_action_audit) en="Consider arch-audit for this check. A vulnerability advisory is different from an infection."; it="Valuta arch-audit per questo controllo. Una vulnerabilità segnalata è diversa da un’infezione.";;
        lynis_updates) en="Lynis reminds you to update this rolling-release system."; it="Lynis ricorda di aggiornare il sistema, che riceve aggiornamenti continui.";;
        lynis_action_updates) en="Read your distribution update notices, then perform a full system update."; it="Leggi gli avvisi della tua distribuzione, poi esegui un aggiornamento completo.";;
        lynis_services) en="Service isolation could be strengthened."; it="L’isolamento dei servizi potrebbe essere migliorato.";;
        lynis_action_services) en="Review individual services with systemd-analyze security. Apply changes only when compatible with the service."; it="Valuta i singoli servizi con systemd-analyze security. Applica solo modifiche compatibili con il servizio.";;
        lynis_dumps) en="Crash reports may contain private data from program memory."; it="I rapporti di arresto dei programmi possono contenere dati privati della memoria.";;
        lynis_action_dumps) en="Consider whether you need these diagnostic reports before changing their settings."; it="Valuta se ti servono questi rapporti diagnostici prima di cambiarne le impostazioni.";;
        lynis_passwords) en="Password storage settings could be strengthened."; it="Le impostazioni di protezione delle password potrebbero essere migliorate.";;
        lynis_password_strength) en="Lynis suggests checking the strength of new passwords."; it="Lynis suggerisce di verificare la robustezza delle nuove password.";;
        lynis_action_passwords) en="Review the authentication settings with your distribution guidance; an incorrect change can block login."; it="Valuta le impostazioni di autenticazione con le istruzioni della distribuzione: un errore può bloccare l’accesso.";;
        lynis_password_expiry) en="Lynis suggests password expiry or age rules."; it="Lynis propone regole sulla scadenza o sull’età delle password.";;
        lynis_action_password_expiry) en="Decide whether those rules suit the accounts on this computer."; it="Valuta se queste regole sono adatte agli account di questo computer.";;
        lynis_permissions) en="Default file access rules could be more restrictive."; it="Le regole di accesso ai file potrebbero essere più restrittive.";;
        lynis_action_permissions) en="Review the affected file and its use before changing permissions."; it="Valuta il file interessato e il suo uso prima di cambiare i permessi.";;
        lynis_storage) en="A separate /var partition can limit disruption when logs fill the disk."; it="Una partizione separata per /var può limitare i problemi quando i log riempiono il disco.";;
        lynis_action_storage) en="This is a disk-layout choice for a future installation or planned migration."; it="È una scelta per una futura installazione o una migrazione pianificata.";;
        lynis_unused) en="Lynis suggests disabling hardware or network features you do not use."; it="Lynis propone di disabilitare funzioni hardware o di rete inutilizzate.";;
        lynis_action_unused) en="Check the exact feature named in the technical report before disabling it."; it="Verifica la funzione indicata nel rapporto tecnico prima di disabilitarla.";;
        lynis_dns) en="Lynis suggests checking the computer name and network name settings."; it="Lynis suggerisce di verificare il nome del computer e le impostazioni dei nomi di rete.";;
        lynis_remote_logs) en="Logs could also be stored on another computer."; it="I log potrebbero essere conservati anche su un altro computer.";;
        lynis_action_optional) en="This is an optional configuration choice. Consider your needs before adding tools or services."; it="È una scelta di configurazione facoltativa. Valuta le tue esigenze prima di aggiungere strumenti o servizi.";;
        lynis_deleted) en="Some processes may still use files removed during an update."; it="Alcuni processi potrebbero usare file rimossi durante un aggiornamento.";;
        lynis_action_deleted) en="Save your work and check whether the affected application or computer needs restarting."; it="Salva il lavoro e valuta se riavviare l’applicazione interessata o il computer.";;
        lynis_banner) en="Lynis suggests a message warning against unauthorized login."; it="Lynis propone un messaggio che avverte contro gli accessi non autorizzati.";;
        lynis_logging) en="Lynis suggests collecting more activity records for later investigation."; it="Lynis propone di registrare più informazioni sulle attività per analisi successive.";;
        lynis_certificates) en="Some certificates may need an expiry check."; it="Alcuni certificati richiedono un controllo della scadenza.";;
        lynis_action_certificates) en="Identify the certificate and the service that uses it before renewing it."; it="Identifica il certificato e il servizio che lo usa prima di rinnovarlo.";;
        lynis_monitor) en="Lynis suggests monitoring changes to important files over time."; it="Lynis suggerisce di seguire nel tempo le modifiche ai file importanti.";;
        lynis_action_monitor) en="SecCheck checks files now. Continuous monitoring requires a separate tool and a verified reference."; it="SecCheck controlla i file attuali. Il monitoraggio continuo richiede uno strumento dedicato e un riferimento verificato.";;
        lynis_automation) en="Lynis checks whether system administration is automated."; it="Lynis verifica se l’amministrazione del sistema è automatizzata.";;
        lynis_kernel) en="Some kernel settings differ from the Lynis reference profile."; it="Alcune impostazioni del kernel differiscono dal profilo di riferimento di Lynis.";;
        lynis_action_kernel) en="Review each setting before changing it: a desktop may need different values from a server."; it="Valuta ogni impostazione prima di modificarla: un desktop può avere esigenze diverse da un server.";;
        lynis_compilers) en="Lynis suggests limiting who can compile programs."; it="Lynis propone di limitare chi può compilare programmi.";;
        lynis_action_compilers) en="Consider your use of development tools before restricting them."; it="Valuta il tuo uso degli strumenti di sviluppo prima di limitarli.";;
        lynis_unmapped) en="This Lynis message has no specific explanation yet. The original text is in the technical report."; it="Questo avviso di Lynis non ha ancora una spiegazione specifica. Il testo originale è nel rapporto tecnico.";;
        menu_single) en="Individual checks"; it="Controlli singoli";;
        main_tools) en="Tools"; it="Strumenti";;
        analysis_choices) en="y  Analyze for me   m  Show warnings   0  Finish"; it="s  Analizza per me   m  Mostrami gli avvisi   0  Termina";;
        optional_count) en="Optional improvements"; it="Miglioramenti facoltativi";;
        checks_count) en="Checks completed"; it="Controlli conclusi";;
        scan_count) en="Items to verify"; it="Elementi da verificare";;
        analysis_explained) en="Explained"; it="Chiariti";;
        rkh_executed_no_history) en="Executed — historical comparison unavailable"; it="Eseguito — confronto storico non disponibile";;
        rkh_baseline_short) en="The initial file snapshot (rkhunter.dat) is missing: no historical comparison."; it="Manca la fotografia iniziale dei file (rkhunter.dat): confronto storico non eseguito.";;
        partial_short) en="Not all tests completed. The technical report has the cause."; it="Non tutti i test sono riusciti. La causa è nel rapporto tecnico.";;
        attention) en="ITEMS STILL TO CHECK"; it="ELEMENTI ANCORA DA VERIFICARE";;
        suggestions) en="OPTIONAL IMPROVEMENTS"; it="MIGLIORAMENTI FACOLTATIVI";;
        explained_results) en="EXPLAINED WARNINGS"; it="AVVISI CHIARITI";;
        other_results) en="OTHER RESULTS"; it="ALTRI RISULTATI";;
        other_menu) en="1  Improvements   2  Explained warnings   3  Short report   4  Technical report   0  Back"; it="1  Miglioramenti   2  Avvisi chiariti   3  Rapporto breve   4  Rapporto tecnico   0  Indietro";;
        back) en="Back"; it="Indietro";;
        no_filtered_findings) en="No items in this section."; it="Nessun elemento in questa sezione.";;
        saved_report) en="Report saved. Open Other results to read it."; it="Rapporto salvato. Lo trovi in Altri risultati.";;
        next_final_review) en="Some changes remain unexplained. Open Remaining items for the next steps."; it="Alcune modifiche restano da chiarire. In Elementi rimasti trovi cosa fare.";;
        next_final_clear) en="No action needed for the warnings checked."; it="Per gli avvisi verificati non serve intervenire.";;
        followup_lynis) en="Preparing explanations for the configuration warnings..."; it="Preparo le spiegazioni degli avvisi di configurazione...";;
        rkh_prerequisite_detail) en="Prerequisite failure reported by rkhunter:"; it="Causa segnalata da rkhunter:";;
        rkh_baseline_missing) en="The initial file snapshot (rkhunter.dat) is missing or empty. rkhunter cannot compare changes over time."; it="Manca la prima fotografia dei file (rkhunter.dat), oppure è vuota. rkhunter non può confrontare le modifiche nel tempo.";;
        rkh_baseline_help) en="--propupd records the current files as a reference. Use it only after checking their contents and source."; it="--propupd registra i file attuali come riferimento. Va usato solo dopo averne verificato contenuto e provenienza.";;
        baseline_failure_cause) en="Stopped at"; it="Blocco individuato";;
        baseline_help) en="Would you like help configuring it? [y/N]"; it="Vuoi che ti aiuti a configurarlo? [s/N]";;
        baseline_setup) en="RKHUNTER: INITIAL SETUP"; it="RKHUNTER: CONFIGURAZIONE INIZIALE";;
        baseline_explain) en="The initial reference is missing. It lets rkhunter compare files between scans."; it="Manca il riferimento iniziale. Serve a confrontare i file tra una scansione e l’altra.";;
        baseline_checking) en="Checking files for the initial reference"; it="Verifico i file per il riferimento iniziale";;
        baseline_verified) en="Files matching local package records"; it="File conformi ai dati locali dei pacchetti";;
        baseline_limits) en="This records today's files. It does not clean the PC or prove their origin. Proceed only if you trust the installed system and packages."; it="Registra i file di oggi. Non ripulisce il PC e non ne prova la provenienza. Prosegui solo se ti fidi del sistema e dei pacchetti installati.";;
        baseline_question) en="Create the initial reference and repeat rkhunter? [y/N]"; it="Creo il riferimento iniziale e ripeto rkhunter? [s/N]";;
        baseline_creating) en="Preparing and checking the initial reference..."; it="Preparo e verifico il riferimento iniziale...";;
        baseline_repeating) en="Reference saved. Repeating the rootkit check..."; it="Riferimento salvato. Ripeto il controllo rootkit...";;
        baseline_created) en="Initial reference created. Other warnings remain for evaluation."; it="Riferimento iniziale creato. Gli altri avvisi restano da valutare.";;
        baseline_declined) en="Reference not created. You can configure it after a future scan."; it="Riferimento non creato. Potrai configurarlo dopo una prossima scansione.";;
        baseline_exists) en="An existing reference was found. I will not replace it."; it="Ho trovato un riferimento già presente. Lo conservo.";;
        baseline_empty) en="The existing reference file is empty. I preserve it; assisted setup can only create a missing reference."; it="Il riferimento presente è vuoto. Lo conservo: la procedura guidata può creare solo un riferimento mancante.";;
        baseline_hash) en="rkhunter uses a different or unknown file comparison method. I preserve your configuration; no reference created."; it="rkhunter usa un metodo di confronto diverso o sconosciuto. Conservo la tua configurazione; riferimento non creato.";;
        baseline_unavailable) en="I cannot read a complete, usable rkhunter file list. No reference created; details are in the technical report."; it="Non riesco a leggere un elenco completo e utilizzabile dei file di rkhunter. Riferimento non creato; dettagli nel rapporto tecnico.";;
        baseline_guard) en="An urgent warning or a flagged checking tool blocks initial setup. Check the remaining items first."; it="Un avviso urgente o uno strumento da verificare blocca la configurazione. Controlla prima gli Elementi rimasti.";;
        baseline_limit) en="The file or time limit was reached. Initial setup stays incomplete."; it="Raggiunto il limite di file o di tempo. La configurazione iniziale resta da completare.";;
        baseline_files) en="A file could not be verified against its package. No reference created; see Remaining items."; it="Un file non è verificabile rispetto al suo pacchetto. Riferimento non creato: lo trovi in Elementi rimasti.";;
        baseline_failed) en="The initial reference could not be created. No reference was replaced; see the technical report."; it="Non sono riuscito a creare il riferimento iniziale. Nessun riferimento è stato sostituito; dettagli nel rapporto tecnico.";;
        rkh_optional) en="Optional or unconfigured tests excluded from this scan:"; it="Test facoltativi o non configurati esclusi da questa scansione:";;
        rkh_optional_short) en="Optional tests excluded; reasons in the report."; it="Test facoltativi esclusi; motivi nel rapporto.";;
        followup_question) en="Would you like me to run the follow-up checks for you?"; it="Vuoi che faccia io le verifiche del caso al posto tuo?";;
        followups) en="ADDITIONAL CHECKS"; it="VERIFICHE AGGIUNTIVE";;
        followup_rootkit) en="Checking reported files and SSH settings..."; it="Verifico i file segnalati e le impostazioni SSH...";;
        followup_files) en="Comparing reported files with local package records..."; it="Confronto i file segnalati con i dati dei pacchetti...";;
        followup_manual) en="Automatic verification is not available for this finding."; it="Per questo avviso non è disponibile una verifica automatica.";;
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
        followup_finished) en="Checks finished. You can view the remaining items."; it="Verifiche terminate. Puoi aprire gli elementi rimasti.";;
        integrity_rechecked) en="The file now matches the local package content, permissions and ownership. The original difference is kept in the report."; it="Ora contenuto, permessi e proprietario coincidono con il pacchetto locale. La differenza iniziale resta nel rapporto.";;
        integrity_hash_only) en="Content matches the local package. This does not explain the original timestamp, size or path warning."; it="Il contenuto coincide con il pacchetto locale. La differenza iniziale di data, dimensione o percorso resta da chiarire.";;
        integrity_special) en="This is a directory, link or other nonregular path. Its current properties were read; the difference still needs assessment."; it="È una cartella, un collegamento o un altro tipo di file speciale. Ho letto le proprietà; la differenza resta da valutare.";;
        integrity_path_unreadable) en="The source path is ambiguous and cannot be checked automatically."; it="Il percorso nel log è ambiguo e non può essere verificato automaticamente.";;
        welcome) en='Choose what to check'; it="Scegli cosa controllare";;
        menu_scans) en='SCANS'; it="SCANSIONI";;
        menu_tools) en='TOOLS'; it="STRUMENTI";;
        full_includes) en="rkhunter, Lynis and installed package files."; it="rkhunter, Lynis e file dei pacchetti installati.";;
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
        why_review) en="Warnings need checking; they do not confirm an infection."; it="Gli avvisi restano da verificare: non confermano un’infezione.";;
        why_advice) en="Maintenance or configuration can be improved."; it="Puoi migliorare manutenzione e configurazione.";;
        why_unknown) en="Some checks could not finish."; it="Alcuni controlli non sono riusciti.";;
        why_clear) en="No unresolved warnings in the completed checks."; it="Nessun avviso aperto nei controlli conclusi.";;
        coverage) en="CHECKS PERFORMED"; it="CONTROLLI ESEGUITI";;
        complete) en="COMPLETED"; it="COMPLETATI";;
        incomplete) en='INCOMPLETE'; it="INCOMPLETA";;
        scope_selected) en="Selected modules only."; it="Solo i controlli scelti.";;
        scope_full) en="All three security checks selected."; it="Selezionati tutti e tre i controlli di sicurezza.";;
        coverage_note) en="Completed checks, not a security score."; it="Controlli conclusi, non un punteggio di sicurezza.";;
        module) en='Module'; it="Modulo";;
        status) en='Status'; it="Stato";;
        findings) en='Items'; it="Voci";;
        rkhunter) en='Rootkit / rkhunter'; it="Rootkit / rkhunter";;
        lynis) en='Configuration / Lynis'; it="Configurazione / Lynis";;
        integrity) en='Package integrity'; it="Integrità pacchetti";;
        confidence_explained) en="Explained by additional checks"; it="Chiarito dalle verifiche aggiuntive";;
        not-run) en='Not selected'; it="Non selezionato";;
        running) en='Running'; it="In corso";;
        completed) en='Completed'; it="Completato";;
        partial) en="Incomplete"; it="Da completare";;
        failed) en='Failed'; it="Fallito";;
        skipped) en='Unavailable'; it="Non disponibile";;
        missing_rkhunter) en='Install rkhunter to run this module.'; it="Installa rkhunter per eseguire questo modulo.";;
        missing_lynis) en='Install lynis to run this module.'; it="Installa lynis per eseguire questo modulo.";;
        missing_pacman) en='pacman is unavailable.'; it="pacman non disponibile.";;
        missing_paccheck) en="pacutils is missing: install it from Tools, then repeat the check."; it="Manca pacutils: installalo da Strumenti, poi ripeti il controllo.";;
        rkh_limited) en="Some rkhunter tests could not run. The report lists the causes."; it="Alcuni test di rkhunter non sono riusciti. Le cause sono nel rapporto.";;
        rkh_skipped) en='Tests not performed by rkhunter. They may require optional tools, services or different settings; this result does not cover them:'; it="Test non eseguiti da rkhunter. Possono dipendere da strumenti facoltativi, servizi o impostazioni; questo risultato non li copre:";;
        rkh_legacy_grep) en='Compatibility notice: rkhunter uses the obsolete egrep name, which still forwards to grep -E. This notice alone does not invalidate the scan:'; it="Avviso di compatibilità: rkhunter usa il nome obsoleto egrep, che richiama ancora grep -E. Questo avviso da solo non invalida la scansione:";;
        rkh_regex) en="rkhunter and grep are incompatible. Check updates, then repeat the rootkit check."; it="rkhunter e grep non sono compatibili. Verifica gli aggiornamenti, poi ripeti il controllo rootkit.";;
        rkh_unparsed) en='rkhunter returned a warning exit code, but no corresponding finding was recognized. Read the original logs before drawing conclusions:'; it="rkhunter ha restituito un codice di avviso, ma non è stata riconosciuta la segnalazione corrispondente. Leggi i log originali prima di trarre conclusioni:";;
        scanner_error) en='The scanner reported an execution or reading problem. Original message:'; it="Lo scanner ha segnalato un problema di esecuzione o lettura. Messaggio originale:";;
        diagnostics_more) en="More details are in the technical report."; it="Altri dettagli sono nel rapporto tecnico.";;
        check_details) en='Warnings, read errors or an unknown output format reduced coverage. Read the raw logs.'; it="Avvisi, errori di lettura o un formato inatteso hanno limitato il controllo. Consulta i log originali.";;
        unfinished) en='The scanner did not report a normal completion.'; it="Lo scanner non ha comunicato una conclusione regolare.";;
        command_failed) en='The command failed without usable results.'; it="Il comando non ha prodotto risultati utilizzabili.";;
        no_report) en='The scanner did not produce a usable report.'; it="Lo scanner non ha prodotto un rapporto utilizzabile.";;
        interrupted) en='Interrupted by the user.'; it="Interrotto dall'utente.";;
        next) en='WHAT TO DO NEXT'; it="COSA FARE ADESSO";;
        next_urgent) en="Ask an expert to investigate the urgent findings before changing files."; it="Chiedi aiuto esperto per i segnali urgenti prima di modificare i file.";;
        next_review) en="Use automatic analysis to investigate the warnings."; it="Usa l’analisi automatica per approfondire gli avvisi.";;
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
        pages_menu) en='1  Next page   2  Previous page   3  Technical report   0  Back'; it="1  Pagina successiva   2  Pagina precedente   3  Rapporto tecnico   0  Torna";;
        empty_pages_menu) en='3  Technical report   0  Back'; it="3  Rapporto tecnico   0  Torna";;
        rkh_prerequisite) en="rkhunter prerequisites need attention. See the exact cause in the report."; it="Un requisito di rkhunter manca o non funziona. La causa precisa è nel rapporto.";;
        rkh_baseline_notice) en='This is a reminder about rkhunter baseline updates, not a detected threat. Do not use --propupd to silence warnings before checking their cause.'; it="Questo è un promemoria sull'aggiornamento della base di confronto di rkhunter, non una minaccia rilevata. Non usare --propupd per azzerare gli avvisi prima di averne verificato la causa.";;
        rkh_context_limited) en="Some additional checks were unavailable. See the finding details."; it="Alcune verifiche aggiuntive non sono riuscite. Vedi i dettagli delle segnalazioni.";;
        rkh_script) en="rkhunter found a script where it expected a program. Legitimate packages can contain scripts."; it="rkhunter ha trovato uno script dove si aspettava un programma. Anche i pacchetti legittimi possono contenerne.";;
        rkh_file_warning) en='rkhunter flagged this file. SecCheck checks whether it belongs to an installed package and whether its contents match the recorded SHA-256.'; it="rkhunter ha segnalato questo file. SecCheck verifica a quale pacchetto appartiene e se il contenuto coincide con lo SHA-256 registrato.";;
        rkh_path_unreadable) en='Control characters or ambiguous text separators prevent reliable identification of the reported path. No automatic file verification was attempted. Inspect the original rkhunter log before acting on the path.'; it="Caratteri di controllo o separatori ambigui nel testo impediscono di identificare con certezza il percorso segnalato. La verifica automatica del file non è stata tentata. Consulta il log originale di rkhunter prima di intervenire sul percorso.";;
        rkh_hidden_file) en="A name starting with a dot is hidden; this alone is not a threat."; it="Un nome che inizia con un punto è nascosto; da solo non indica una minaccia.";;
        rkh_hidden_directory) en='rkhunter reported a hidden directory. Applications commonly create these. A directory cannot be verified with a single file hash: check which application created it and examine its contents without running them.'; it="rkhunter segnala una cartella nascosta. Molte applicazioni ne creano: una cartella non si verifica con lo SHA-256 di un singolo file. Controlla quale applicazione l'ha creata e il suo contenuto, senza eseguirlo.";;
        rkh_hidden_summary) en='rkhunter reported hidden files without individually readable details. Their names are needed before a file verification can be made.'; it="rkhunter segnala file nascosti, ma non sono disponibili dettagli leggibili sui singoli file. Servono i percorsi per verificarli.";;
        rkh_dev) en='rkhunter found unexpected file types under /dev, where devices and runtime data live. Some applications create legitimate files there; this warning needs the listed paths and their origin.'; it="rkhunter segnala tipi di file inattesi in /dev, dove si trovano dispositivi e dati creati durante il funzionamento. Alcune applicazioni vi creano file legittimi: occorre verificarne percorsi e origine.";;
        rkh_dev_file) en='An application may have created this file under /dev. SecCheck checks its properties and current users without opening its contents.'; it="Un’applicazione può aver creato questo file in /dev. SecCheck controlla le proprietà e chi lo sta usando, senza leggerne il contenuto.";;
        rkh_dev_process) en='Processes using the file were reported. This shows current use, not who created it or whether it is safe.'; it="Sono stati rilevati processi che usano il file. Questo mostra l’uso attuale, non chi l’ha creato o se è sicuro.";;
        rkh_dev_idle) en='No process using the file was reported. It may be leftover runtime data; its origin remains unknown.'; it="Non sono stati rilevati processi che usano il file. Può essere un dato rimasto dopo la chiusura di un’applicazione; l’origine resta sconosciuta.";;
        rkh_dev_unknown) en='The file or its current users could not be reliably checked. See the original check logs.'; it="Non è stato possibile verificare il file o chi lo usa. Il rapporto conserva i log della verifica.";;
        rkh_dev_missing) en='The path no longer exists. Runtime files can disappear when an application closes; this does not explain their original contents.'; it="Il percorso non esiste più. I file temporanei possono sparire quando un’applicazione si chiude; il contenuto originale resta sconosciuto.";;
        rkh_dev_nonregular) en='The path is a link, directory or other nonregular object. Its metadata was recorded; its contents or target were not inspected.'; it="Il percorso è un collegamento, una cartella o un altro tipo di oggetto. Sono state registrate le proprietà, senza leggerne il contenuto o la destinazione.";;
        rkh_dev_tool_missing) en='File properties were recorded. Install optional psmisc to identify current users with fuser, then repeat the check.'; it="Le proprietà del file sono state registrate. Per identificare chi lo usa serve fuser, nel pacchetto facoltativo psmisc. Poi ripeti il controllo.";;
        rkh_dev_tool_flagged) en='A verification tool has an unresolved file warning. It was not run for this check.'; it="Uno strumento di verifica ha una segnalazione ancora aperta. Non è stato avviato per questo controllo.";;
        rkh_stream_unreadable) en='The raw rkhunter output could not be read reliably. It remains in the original log and does not count as a verified path.'; it="Il testo originale di rkhunter non è leggibile in modo affidabile. Resta nel log originale e non viene usato per verificare un percorso.";;
        rkh_dev_lsp) en='LSP audio plugins use names like this for shared-memory data. The name alone does not establish the origin of this file.'; it="I plugin audio LSP usano nomi come questo per dati in memoria condivisa. Il nome non basta a stabilire l’origine del file.";;
        rkh_updated_context) en='systemd uses /etc/.updated as an update timestamp. This explains why that name can exist outside package contents, but does not verify this particular file.'; it="systemd usa /etc/.updated per registrare la data degli aggiornamenti. Questo spiega il nome e l’assenza dai pacchetti, ma non verifica questo specifico file.";;
        dev_owner) en='Owner'; it='Proprietario';;
        dev_permissions) en='Permissions'; it='Permessi';;
        dev_program) en='Program'; it='Programma';;
        dev_program_package) en='Executable package'; it="Pacchetto dell’eseguibile";;
        dev_process_unavailable) en='identity unavailable'; it='identità non disponibile';;
        dev_flagged_tool) en='Tool with an unresolved warning'; it='Strumento con una segnalazione aperta';;
        dev_more_processes) en='additional processes or time limit; see logs'; it='altri processi o tempo esaurito; vedi i log';;
        rkh_action_dev) en='Check whether the listed program is one you use. Do not delete a shared-memory file while it is in use. If the program is unfamiliar, ask for help using these details.'; it="Controlla se il programma elencato è uno che usi. Non eliminare file in memoria condivisa mentre sono in uso. Se non riconosci il programma, chiedi aiuto con questi dettagli.";;
        rkh_action_dev_idle) en='Close your applications normally and repeat the scan. If the unexplained file remains, use its path and properties to ask for help before deleting it.'; it="Chiudi normalmente le applicazioni e ripeti la scansione. Se il file resta senza una spiegazione, chiedi aiuto indicando percorso e proprietà prima di eliminarlo.";;
        rkh_ssh_root) en="This concerns remote administrator access through SSH. The effective setting needs checking."; it="Riguarda l’accesso remoto come amministratore tramite SSH. Va controllata l’impostazione effettiva.";;
        rkh_ssh_protocol) en="This old rkhunter test concerns SSH protocol 1. The installed server version can clarify it."; it="Questo vecchio test riguarda il protocollo SSH 1. La versione del server installato può chiarire l’avviso.";;
        rkh_file_match) en="Content and file properties match the local package record."; it="Contenuto e proprietà coincidono con il pacchetto locale.";;
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
        rkh_action_explained) en="No action needed for this warning."; it="Per questo avviso non serve intervenire.";;
        rkh_action_file) en="Check why the file changed before restoring it."; it="Verifica perché il file è cambiato prima di ripristinarlo.";;
        rkh_action_unowned) en="Identify the application that created it. Being hidden or unowned is not a reason to delete it."; it="Verifica quale applicazione lo ha creato. Essere nascosto o fuori dai pacchetti non basta per eliminarlo.";;
        rkh_action_tools) en="Install pacutils from Tools, then repeat the check."; it="Installa pacutils da Strumenti, poi ripeti il controllo.";;
        rkh_action_ssh) en="If remote root login is not needed, consider disabling it. Validate changes before closing a remote session."; it="Se non ti serve l’accesso remoto come root, valuta di disabilitarlo. Verifica le modifiche prima di chiudere una sessione remota.";;
        rkh_action_ssh_disabled) en='No change is needed for the general root-login setting. If you use SSH, also review any connection-specific Match rules.'; it="Non serve cambiare l'impostazione generale del login di root. Se usi SSH, controlla anche le eventuali regole Match per connessioni specifiche.";;
        rkh_action_unknown) en="Read the explanation or ask for help with the technical report."; it="Leggi la spiegazione o chiedi aiuto con il rapporto tecnico.";;
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
        file_config) en="Configuration files can change during normal use."; it="I file di configurazione possono cambiare durante l’uso normale.";;
        demo) en='DEMO - INVENTED RESULTS. No system scan was performed.'; it="DEMO - RISULTATI DI ESEMPIO. Nessuna scansione del sistema eseguita.";;
        report) en='Private report'; it="Rapporto privato";;
        report_info) en="Root is needed to read the report. Review private paths before sharing."; it="Il rapporto richiede root. Contiene percorsi privati: controllalo prima di condividerlo.";;
        scope_report) en='TECHNICAL SCOPE / ORIGINAL LOGS'; it="AMBITO TECNICO / LOG ORIGINALI";;
        limits) en="No scan can guarantee a secure system."; it="Nessuna scansione garantisce da sola un sistema sicuro.";;
        result_menu) en="1  Remaining items   2  Other results   0  Finish"; it="1  Elementi rimasti   2  Altri risultati   0  Termina";;
        short_report_help) en="Original evidence is available in the technical report."; it="Le prove originali sono disponibili nel rapporto tecnico.";;
        more) en='More findings are available on the following pages and in the full report.'; it="Le altre segnalazioni sono nelle pagine successive e nel rapporto completo.";;
        unsupported) en='Scanning requires Arch Linux or an Arch derivative with pacman.'; it="La scansione richiede Arch Linux o una derivata con pacman.";;
        root) en='This action requires root. SecCheck will request permission through sudo.'; it="Questa azione richiede root. SecCheck chiederà i permessi tramite sudo.";;
        need_root) en='Run this command with sudo to scan noninteractively.'; it="Esegui questo comando con sudo per una scansione non interattiva.";;
        storage_error) en='Cannot create a private report directory. Scan not started.'; it="Impossibile creare una cartella privata per i rapporti. Scansione non avviata.";;
        save_error) en='Report could not be saved completely. Check free space and permissions.'; it="Rapporto non salvato completamente. Controlla spazio libero e permessi.";;
        deps) en='TOOLS AND PURPOSE'; it="STRUMENTI E FUNZIONE";;
        deps_startup) en='STARTUP CHECK'; it="CONTROLLO INIZIALE";;
        deps_explain) en='SecCheck checks which tools are available before you choose a scan.'; it="SecCheck verifica gli strumenti disponibili prima di scegliere una scansione.";;
        deps_ready) en="Tools ready: rkhunter, Lynis and pacutils."; it="Strumenti pronti: rkhunter, Lynis e pacutils.";;
        deps_missing) en='Missing packages'; it="Pacchetti mancanti";;
        deps_continue) en="You can continue; checks needing missing tools stay incomplete."; it="Puoi proseguire; i controlli senza strumenti resteranno incompleti.";;
        deps_pacutils) en="File verification (paccheck + pacfile)."; it="Verifica dei file (paccheck + pacfile).";;
        available) en='available'; it="disponibile";;
        absent) en='missing'; it="mancante";;
        install_question) en='Install the missing packages with pacman? [y/N]'; it="Installare con pacman i pacchetti mancanti? [s/N]";;
        install_note) en="pacman will ask you to confirm the installation."; it="pacman chiederà la conferma dell’installazione.";;
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

# ---- Terminal rendering: no cursor tricks, real counts only --------
sc_ui_init() {
    SC_WIDTH=${COLUMNS:-80}
    if [[ -t 1 ]] && command -v tput >/dev/null; then SC_WIDTH=$(tput cols 2>/dev/null) || SC_WIDTH=80; fi
    [[ $SC_WIDTH =~ ^[0-9]{1,4}$ ]] || SC_WIDTH=80
    ((SC_WIDTH < 24)) && SC_WIDTH=24
    ((SC_WIDTH > 120)) && SC_WIDTH=120
    SC_C_PRIMARY='' SC_C_MUTED='' SC_C_RED='' SC_C_AMBER='' SC_C_GREEN='' SC_C_WHITE='' SC_C_RESET='' SC_C_BOLD='' SC_C_ITALIC=''
    if [[ -t 1 && ${TERM:-dumb} != dumb && ${SC_NO_COLOR:-0} == 0 && ! ${NO_COLOR+x} ]]; then
        SC_C_RESET=$'\e[0m' SC_C_BOLD=$'\e[1m' SC_C_ITALIC=$'\e[3m'
        SC_C_PRIMARY=$'\e[38;5;255m' SC_C_MUTED=$'\e[38;5;255m\e[2m'
        SC_C_RED=$'\e[38;5;203m' SC_C_AMBER=$'\e[38;5;208m' SC_C_GREEN=$'\e[38;5;114m'
        SC_C_WHITE=$'\e[38;5;255m'
    fi
    SC_RULE_CHAR='─' SC_BAR_CHAR='━' SC_EMPTY_CHAR='─' SC_DOT='●'
    if [[ ${SC_ASCII:-0} == 1 || ${TERM:-} == dumb || ${LC_ALL:-${LC_CTYPE:-${LANG:-C}}} != *[Uu][Tt][Ff]* ]]; then
        SC_ASCII=1; SC_RULE_CHAR='-' SC_BAR_CHAR='#' SC_EMPTY_CHAR='.' SC_DOT='*'
    fi
}

sc_repeat() { local i; for ((i=0;i<$2;i++)); do printf '%s' "$1"; done; }

sc_line() {
    local value=${1-} color=${2:-$SC_C_WHITE} word line='' width=$((SC_WIDTH-4))
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
    local tl='╭' tr='╮' bl='╰' br='╯' edge='│' line='─' pad=4
    ((SC_WIDTH >= 27)) || pad=1
    if [[ ${SC_ASCII:-0} == 1 ]]; then tl='+'; tr='+'; bl='+'; br='+'; edge='|'; line='-'; fi
    if ((SC_WIDTH >= 55)); then
        local i
        local -a sec=(
            '█▀▀▀▀ █▀▀▀▀ █▀▀▀▀'
            '█▄▄▄▄ █▄▄▄  █    '
            '    █ █     █    '
            '▀▀▀▀▀ ▀▀▀▀▀ ▀▀▀▀▀'
        ) check=(
            '█▀▀▀▀ █   █ █▀▀▀▀ █▀▀▀▀ █  ▄▀'
            '█     █▄▄▄█ █▄▄▄  █     █▄▀  '
            '█     █   █ █     █     █ ▀▄ '
            '▀▀▀▀▀ ▀   ▀ ▀▀▀▀▀ ▀▀▀▀▀ ▀   ▀'
        )
        if [[ ${SC_ASCII:-0} == 1 ]]; then
            sec=('##### ##### #####' '#     #     #    ' '#     #     #    ' '##### ####  #    ' '    # #     #    ' '    # #     #    ' '##### ##### #####')
            check=('##### #   # ##### ##### #   #' '#     #   # #     #     #  # ' '#     #   # #     #     # #  ' '#     ##### ####  #     ##   ' '#     #   # #     #     # #  ' '#     #   # #     #     #  # ' '##### #   # ##### ##### #   #')
        fi
        printf '\n  %s%s' "$SC_C_WHITE" "$tl"; sc_repeat "$line" 51; printf '%s%s\n' "$tr" "$SC_C_RESET"
        for i in "${!sec[@]}"; do
            printf '  %s%s  %s%s %s%s  %s%s%s\n' "$SC_C_WHITE" "$edge" "$SC_C_RED$SC_C_BOLD" "${sec[i]}" "$SC_C_WHITE$SC_C_BOLD" "${check[i]}" "$SC_C_WHITE" "$edge" "$SC_C_RESET"
        done
        printf '  %s%s' "$SC_C_WHITE" "$bl"; sc_repeat "$line" 51; printf '%s%s\n\n' "$br" "$SC_C_RESET"
    else
    printf '\n  %s%s' "$SC_C_WHITE" "$tl"; sc_repeat "$line" "$((15+2*pad))"; printf '%s%s\n' "$tr" "$SC_C_RESET"
    printf '  %s%s%*s%sS E C %sC H E C K%*s%s%s%s\n' "$SC_C_WHITE" "$edge" "$pad" '' "$SC_C_RED$SC_C_BOLD" "$SC_C_WHITE$SC_C_BOLD" "$pad" '' "$SC_C_WHITE" "$edge" "$SC_C_RESET"
    printf '  %s%s' "$SC_C_WHITE" "$bl"; sc_repeat "$line" "$((15+2*pad))"; printf '%s%s\n\n' "$br" "$SC_C_RESET"
    fi
    if ((SC_WIDTH >= 46)); then
        printf '  %sSecurity%s & Integrity Checker for Arch Linux%s\n' "$SC_C_RED$SC_C_ITALIC" "$SC_C_WHITE$SC_C_ITALIC" "$SC_C_RESET"
    else
        sc_line 'Security & Integrity Checker' "$SC_C_RED$SC_C_ITALIC"
        sc_line 'for Arch Linux' "$SC_C_WHITE$SC_C_ITALIC"
    fi
    sc_line "v$SC_VERSION | KlodCripta" "$SC_C_MUTED"
}
sc_header() {
    sc_brand; sc_rule; printf '\n'
    [[ ${SC_DEMO:-0} == 0 ]] || sc_line "$(sc_t demo)" "$SC_C_AMBER"
}

sc_status_color() {
    case $1 in urgent|failed) printf '%s' "$SC_C_RED";; review|advice|partial|unknown|skipped) printf '%s' "$SC_C_AMBER";;
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

sc_render_technical_summary() {
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
    if ((total < 3)); then sc_line "$(sc_t scope_selected)"; fi
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
        if [[ $module == rkhunter && ${SC_MODULE_REASON[$module]} == rkh_baseline_missing ]]; then
            sc_line "$(sc_t rkh_baseline_help)" "$SC_C_MUTED"
        fi
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

}

# The normal screen is a decision, not a log viewer.
sc_render_summary() {
    local i module reason urgent=0 review=0 suggestions=0 explained=0 total=${#SC_SELECTED[@]}
    sc_detail_groups
    for i in "${SC_DETAIL_GROUPS[@]}"; do
        i=${i%% *}
        case ${SC_F_PRIORITY[i]} in
            urgent) ((urgent+=1));; review) ((review+=1));;
            suggestion) ((suggestions+=1));; info) ((explained+=1));;
        esac
    done
    sc_heading result
    sc_line "$SC_DOT $(sc_t "$SC_ASSESSMENT")" "$(sc_status_color "$SC_ASSESSMENT")$SC_C_BOLD"
    if ((SC_FOLLOWUPS_DONE)); then
        sc_line "$(sc_t analysis_explained): $explained" "$SC_C_WHITE$SC_C_BOLD"
        sc_line "$(sc_t followup_pending): $((urgent+review))" "$SC_C_WHITE$SC_C_BOLD"
    else
        sc_line "$(sc_t scan_count): $((urgent+review))" "$SC_C_WHITE$SC_C_BOLD"
    fi
    ((urgent == 0)) || sc_line "$(sc_t priority_urgent): $urgent" "$SC_C_RED$SC_C_BOLD"
    ((suggestions == 0)) || sc_line "$(sc_t optional_count): $suggestions"
    if ((SC_INCOMPLETE)); then
        sc_line "$(sc_t checks_count): $SC_COMPLETED/$total - $(sc_t incomplete)" "$SC_C_AMBER"
        for module in "${SC_SELECTED[@]}"; do
            [[ ${SC_MODULE_STATUS[$module]} != completed ]] || continue
            reason=${SC_MODULE_REASON[$module]}
            case $reason in
                rkh_baseline_missing) reason=rkh_baseline_short;;
                missing_rkhunter|missing_lynis|missing_paccheck|missing_pacman|rkh_regex|interrupted) ;;
                *) reason=partial_short;;
            esac
            sc_line "$module: $(sc_t "$reason")" "$SC_C_WHITE$SC_C_ITALIC"
        done
    else sc_line "$(sc_t checks_count): $SC_COMPLETED/$total" "$SC_C_MUTED"; fi
    ((total == 3)) || sc_line "$(sc_t scope_selected)" "$SC_C_MUTED"
    if ((SC_FOLLOWUPS_INTERRUPTED)); then sc_line "$(sc_t followup_interrupted)" "$SC_C_AMBER"; fi
    if [[ $SC_ASSESSMENT == urgent ]]; then
        sc_line "$(sc_t next_urgent)" "$SC_C_RED"
    elif ((SC_FOLLOWUPS_DONE)); then
        if ((review)); then sc_line "$(sc_t next_final_review)"
        elif ((SC_INCOMPLETE == 0)); then sc_line "$(sc_t next_final_clear)"; fi
    elif ((review)); then sc_line "$(sc_t why_review)" "$SC_C_WHITE$SC_C_ITALIC"; fi
    sc_line "$(sc_t limits)" "$SC_C_MUTED$SC_C_ITALIC"
}

sc_render_short_report() {
    sc_brand
    sc_render_summary
    sc_line "$(sc_t short_report_help)" "$SC_C_MUTED"
}

# Group only the presentation, never the original evidence or its assessment.
# The first member has the highest priority. Ambiguous paths remain separate.
sc_detail_groups() {
    local technical=${1:-0} filter=${2:-all} priority i g first found group
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
    # Filter whole paths after grouping. A matching content check does not hide
    # an unresolved timestamp or permissions warning for that same path.
    local -a groups=("${SC_DETAIL_GROUPS[@]}")
    SC_DETAIL_GROUPS=()
    for group in "${groups[@]}"; do
        first=${group%% *}; priority=${SC_F_PRIORITY[first]}
        case $filter:$priority in
            all:*|attention:urgent|attention:review|suggestions:suggestion|explained:info)
                SC_DETAIL_GROUPS+=("$group");;
        esac
    done
}

# These explanations describe purpose, not legitimacy. They never clear a
# finding. Lynis mappings require both the test ID and the observed message.
sc_finding_guidance() {
    local i=$1 object=${SC_F_OBJECT[$1]} description=${SC_F_EVIDENCE[$1]%% | *}
    SC_GUIDANCE_MEANING='' SC_GUIDANCE_ACTION=''
    if [[ ${SC_F_MODULE[i]} == integrity ]]; then
        case $object in
            /etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/subuid|/etc/subgid)
                SC_GUIDANCE_MEANING=context_accounts; SC_GUIDANCE_ACTION=action_accounts;;
            /etc/resolv.conf|/etc/hosts)
                SC_GUIDANCE_MEANING=context_dns; SC_GUIDANCE_ACTION=action_dns;;
            /etc/pacman.conf|/etc/pacman.d/mirrorlist)
                SC_GUIDANCE_MEANING=context_repositories; SC_GUIDANCE_ACTION=action_repositories;;
            /etc/pam.d/*|/etc/sudoers|/etc/sudoers.d/*)
                SC_GUIDANCE_MEANING=context_login; SC_GUIDANCE_ACTION=action_login;;
            /etc/locale.gen|/etc/locale.conf|/etc/shells)
                SC_GUIDANCE_MEANING=context_preferences; SC_GUIDANCE_ACTION=action_preferences;;
        esac
    elif [[ ${SC_F_MODULE[i]} == lynis ]]; then
        case $object:$description in
            PKGS-7320:'Consider installing arch-audit to determine vulnerable packages'*|PKGS-7398:'Install a package audit tool to determine vulnerable packages'*)
                SC_GUIDANCE_MEANING=lynis_audit; SC_GUIDANCE_ACTION=lynis_action_audit;;
            PKGS-7312:'Perform update of system updates as this system uses rolling updates'*)
                SC_GUIDANCE_MEANING=lynis_updates; SC_GUIDANCE_ACTION=lynis_action_updates;;
            BOOT-5264:'Consider hardening system services'*)
                SC_GUIDANCE_MEANING=lynis_services; SC_GUIDANCE_ACTION=lynis_action_services;;
            KRNL-5820:'If not required, consider explicit disabling of core dump'*)
                SC_GUIDANCE_MEANING=lynis_dumps; SC_GUIDANCE_ACTION=lynis_action_dumps;;
            AUTH-9230:'Configure password hashing rounds'*|AUTH-9262:'Password hash rounds are not configured'*)
                SC_GUIDANCE_MEANING=lynis_passwords; SC_GUIDANCE_ACTION=lynis_action_passwords;;
            AUTH-9262:'Install a PAM module for password strength testing'*)
                SC_GUIDANCE_MEANING=lynis_password_strength; SC_GUIDANCE_ACTION=lynis_action_passwords;;
            AUTH-9282:'When possible set expire dates for all password protected accounts'*|AUTH-9286:'Configure minimum password age'*|AUTH-9286:'Configure maximum password age'*)
                SC_GUIDANCE_MEANING=lynis_password_expiry; SC_GUIDANCE_ACTION=lynis_action_password_expiry;;
            AUTH-9328:'Default umask'*|FILE-7524:'Consider restricting file permissions'*)
                SC_GUIDANCE_MEANING=lynis_permissions; SC_GUIDANCE_ACTION=lynis_action_permissions;;
            FILE-6310:'To decrease the impact of a full /var file system'*)
                SC_GUIDANCE_MEANING=lynis_storage; SC_GUIDANCE_ACTION=lynis_action_storage;;
            USB-1000:'Disable drivers like USB storage'*|STRG-1846:'Disable drivers like firewire storage'*|NETW-3200:'Determine if protocol '*' is really needed on this system'*)
                SC_GUIDANCE_MEANING=lynis_unused; SC_GUIDANCE_ACTION=lynis_action_unused;;
            NAME-4028:'Check DNS configuration for the dns domain name'*|NAME-4404:'Add the IP name and FQDN to /etc/hosts'*)
                SC_GUIDANCE_MEANING=lynis_dns; SC_GUIDANCE_ACTION=action_dns;;
            LOGG-2154:'Enable logging to an external logging host'*)
                SC_GUIDANCE_MEANING=lynis_remote_logs; SC_GUIDANCE_ACTION=lynis_action_optional;;
            LOGG-2190:'Check what deleted files are still in use and why.'*)
                SC_GUIDANCE_MEANING=lynis_deleted; SC_GUIDANCE_ACTION=lynis_action_deleted;;
            BANN-7126:'Add a legal banner to /etc/issue'*)
                SC_GUIDANCE_MEANING=lynis_banner; SC_GUIDANCE_ACTION=lynis_action_optional;;
            ACCT-9622:'Enable process accounting'*|ACCT-9626:'Enable sysstat'*|ACCT-9628:'Enable auditd'*)
                SC_GUIDANCE_MEANING=lynis_logging; SC_GUIDANCE_ACTION=lynis_action_optional;;
            CRYP-7902:'Check available certificates for expiration'*)
                SC_GUIDANCE_MEANING=lynis_certificates; SC_GUIDANCE_ACTION=lynis_action_certificates;;
            FINT-4350:'Install a file integrity tool'*)
                SC_GUIDANCE_MEANING=lynis_monitor; SC_GUIDANCE_ACTION=lynis_action_monitor;;
            TOOL-5002:'Determine if automation tools are present'*)
                SC_GUIDANCE_MEANING=lynis_automation; SC_GUIDANCE_ACTION=lynis_action_optional;;
            KRNL-6000:'One or more sysctl values differ from the scan profile'*)
                SC_GUIDANCE_MEANING=lynis_kernel; SC_GUIDANCE_ACTION=lynis_action_kernel;;
            HRDN-7222:'Harden compilers'*)
                SC_GUIDANCE_MEANING=lynis_compilers; SC_GUIDANCE_ACTION=lynis_action_compilers;;
            *)
                [[ ${SC_F_KEY[i]} == lynis_reboot ]] || {
                    SC_GUIDANCE_MEANING=lynis_unmapped; SC_GUIDANCE_ACTION=rkh_action_unknown;
                };;
        esac
    fi
}

sc_render_details() {
    local limit=${1:-0} offset=${2:-0} technical=${3:-0} filter=${4:-all} i j group shown=0 visited=0 priority object check action fields seen key config
    local -a members=()
    case $filter in attention) sc_heading attention;; suggestions) sc_heading suggestions;; explained) sc_heading explained_results;; *) sc_heading details;; esac
    sc_detail_groups "$technical" "$filter"
    ((${#SC_DETAIL_GROUPS[@]})) || { sc_line "$(sc_t no_filtered_findings)"; return 0; }
    for group in "${SC_DETAIL_GROUPS[@]}"; do
            read -r -a members <<< "$group"
            i=${members[0]}; priority=${SC_F_PRIORITY[i]}
            ((visited+=1)); ((visited > offset)) || continue
            if ((limit && shown >= limit)); then sc_line "$(sc_t more)"; return 0; fi
            ((shown+=1)); object=${SC_F_OBJECT[i]}
            sc_finding_guidance "$i"
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
                sc_line "$(sc_t "${SC_GUIDANCE_MEANING:-${SC_F_KEY[i]}}")"
            fi
            if ((${#members[@]} > 1)) && [[ -n $SC_GUIDANCE_MEANING ]]; then
                sc_line "$(sc_t "$SC_GUIDANCE_MEANING")"
            fi
            if [[ ${SC_F_KEY[i]} == rkh_dev_file && $object =~ ^/dev/shm/lsp-catalog-[A-Za-z0-9_.-]+\.(shm|lock)$ ]]; then
                sc_line "$(sc_t rkh_dev_lsp)" "$SC_C_MUTED"
            elif [[ ${SC_F_KEY[i]} == rkh_hidden_file && $object == /etc/.updated ]]; then
                sc_line "$(sc_t rkh_updated_context)" "$SC_C_MUTED"
            fi
            seen=' ' action=''
            for j in "${members[@]}"; do
                check=${SC_F_CHECK_KEY[j]}
                [[ -n $check && $seen != *" $check "* ]] || continue
                if ((technical == 0)) && [[ ${SC_F_MODULE[i]} == lynis && $check == followup_manual ]]; then continue; fi
                [[ ${SC_F_KEY[j]} == lynis_reboot && $check == followup_manual ]] && continue
                seen+="$check "
                sc_line "$(sc_t checked):" "$SC_C_PRIMARY$SC_C_BOLD"
                sc_line "$(sc_t "$check")"
                if ((technical)) || [[ $check == rkh_ssh_unknown || ${SC_F_KEY[j]} == rkh_dev_file ]]; then
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
                    rkh_dev_process) action=rkh_action_dev;;
                    rkh_dev_idle|rkh_dev_missing) action=rkh_action_dev_idle;;
                    *) action=rkh_action_unknown;;
                esac
            done
            [[ ${SC_F_KEY[i]} != lynis_reboot ]] || action=lynis_action_reboot
            if [[ -n $SC_GUIDANCE_ACTION && $priority != info ]]; then action=$SC_GUIDANCE_ACTION; fi
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
                if ((config)) && [[ -z $SC_GUIDANCE_MEANING ]]; then sc_line "$(sc_t file_config)"; fi
            fi
            if ((technical)); then
                sc_line "$(sc_t evidence): ${SC_F_EVIDENCE[i]}" "$SC_C_MUTED"
            fi
    done
}

sc_browse_details() {
    local filter=${1:-all}
    sc_detail_groups 0 "$filter"
    local page=0 pages=$(((${#SC_DETAIL_GROUPS[@]}+4)/5)) answer
    while :; do
        if ((pages)); then sc_line "$(sc_t page) $((page+1)) / $pages" "$SC_C_PRIMARY"; fi
        sc_render_details 5 "$((page*5))" 0 "$filter"
        [[ -t 0 ]] || return 0
        printf '\n'
        if ((pages)); then sc_line "$(sc_t pages_menu)"; else sc_line "$(sc_t empty_pages_menu)"; fi
        printf '  > '; IFS= read -r answer || return 0
        case $answer in
            1) ((page+1 < pages)) && ((page+=1));;
            2) ((page > 0)) && ((page-=1));;
            3) sc_line "$(sc_t report): $SC_RUN_DIR/report.txt"; sc_line "$(sc_t report_info)"; sc_render_report;;
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
    sc_header; sc_render_technical_summary; sc_render_details 0 0 1
    sc_heading scope_report
    sc_line "SecCheck=$SC_VERSION; started=${SC_STARTED:-demo}"
    ((${#SC_SELECTED[@]} != 3)) || sc_line "$(sc_t scope_full)"
    local module value
    for module in "${SC_SELECTED[@]}"; do
        sc_line "$module: version=${SC_MODULE_VERSION[$module]}; exit=${SC_MODULE_RC[$module]}; reason=${SC_MODULE_REASON[$module]}"
        sc_render_diagnostics "$module" 0
    done
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
    printf '%s\n' '  --lang en|it' '  --scan full|rkhunter|lynis|integrity' \
        '  --no-color' '  --ascii' \
        '  --demo [review|urgent|incomplete|clean]' '  --help' '  --version'
    printf '\n%s\n' "$(sc_t batch_usage)"
}

sc_parse_args() {
    SC_LANG='' SC_SCAN='' SC_DEMO=0 SC_SCENARIO=review SC_NO_COLOR=0 SC_ASCII=0 SC_ACTION=''
    while (($#)); do
        case $1 in
            --lang) (($# >= 2)) || return 64; case $2 in en|it) SC_LANG=$2;; *) return 64;; esac; shift;;
            --scan) (($# >= 2)) || return 64; case $2 in full|rkhunter|lynis|integrity) SC_SCAN=$2;; *) return 64;; esac; shift;;
            --no-color) SC_NO_COLOR=1;;
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
            sc_add_finding rkhunter suspicious info observation /usr/bin/example-tool rkh_script 'DEMO: The command is a script'
            SC_F_CHECK_KEY[${#SC_F_MODULE[@]}-1]=rkh_file_match
            SC_F_CHECK_DETAIL[${#SC_F_MODULE[@]}-1]='DEMO: example-package / SHA-256';;
    esac
    sc_assess; sc_header; sc_render_summary
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
    if [[ $mode == startup ]]; then sc_heading deps_startup
    else sc_heading deps; fi
    for package in rkhunter lynis pacutils; do
        missing_tool=0
        case $package in
            rkhunter) tool=rkhunter; purpose=menu_rkhunter;;
            lynis) tool=lynis; purpose=menu_lynis;;
            pacutils) tool=paccheck; purpose=deps_pacutils; command -v pacfile >/dev/null || missing_tool=1;;
        esac
        command -v "$tool" >/dev/null || missing_tool=1
        label=$(sc_t available); color=$SC_C_GREEN
        if ((missing_tool)); then missing+=("$package"); label=$(sc_t absent); color=$SC_C_AMBER; fi
        if [[ $mode != startup ]] || ((missing_tool)); then
            sc_line "$package: $label" "$color$SC_C_BOLD"
            sc_line "$(sc_t "$purpose")" "$SC_C_WHITE$SC_C_ITALIC"
        fi
    done
    if ((${#missing[@]} == 0)); then sc_line "$(sc_t deps_ready)" "$SC_C_GREEN"; return 0; fi
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
        if [[ ${SC_BASELINE_ACTIVE:-0} == 1 ]]; then
            SC_BASELINE_STATE=interrupted SC_BASELINE_REASON=interrupted
            sc_add_diagnostic rkhunter baseline_setup "interrupted; consent=$SC_BASELINE_CONFIRMED"
        fi
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
    for module in "${SC_SELECTED[@]}"; do
        ((step+=1)); printf '\n'
        sc_line "[$step/${#SC_SELECTED[@]}] $(sc_t scanning): $(sc_t "$module")" "$SC_C_PRIMARY"
        case $module in rkhunter) sc_run_rkhunter;; lynis) sc_run_lynis;; integrity) sc_run_integrity;; esac
        if [[ $module == rkhunter && ${SC_MODULE_REASON[$module]} == rkh_baseline_missing ]]; then
            sc_line "$(sc_t rkh_executed_no_history)" "$SC_C_AMBER"
        else
            sc_line "$(sc_t "${SC_MODULE_STATUS[$module]}")" "$(sc_status_color "${SC_MODULE_STATUS[$module]}")"
        fi
        [[ $module != rkhunter ]] || sc_offer_initial_baseline || return $?
    done
    sc_assess
    SC_RUN_ACTIVE=0
    trap - INT TERM
    sc_render_summary
    sc_save_report || { sc_line "$(sc_t save_error)"; return 73; }
    if [[ ! -t 0 ]]; then sc_line "$(sc_t report): $SC_RUN_DIR/report.txt"; fi
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
    sc_line "$(sc_t saved_report)" "$SC_C_MUTED"
}

sc_offer_followups() {
    local answer
    while :; do
        printf '\n'; sc_line "$(sc_t followup_question)" "$SC_C_WHITE$SC_C_BOLD"
        sc_line "$(sc_t analysis_choices)"
        printf '  > '; IFS= read -r answer || return 0
        case $answer in
            s|S|y|Y|1) sc_run_followups; return $?;;
            m|M|2) sc_browse_details attention;;
            0|n|N|'') return 0;;
            *) sc_line "$(sc_t invalid)";;
        esac
    done
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
    sc_scan_once; rc=$?
    [[ -t 0 && $rc -le 2 ]] || return "$rc"
    sc_offer_followups || return $?
    sc_result_code; rc=$?
    ((SC_FOLLOWUPS_DONE)) || return "$rc"
    while :; do
        printf '\n'; sc_line "$(sc_t result_menu)"
        printf '  > '; IFS= read -r answer || return "$rc"
        case $answer in
            1) sc_browse_details attention;;
            2) sc_other_results;;
            0) return "$rc";;
            *) sc_line "$(sc_t invalid)";;
        esac
    done
}

sc_other_results() {
    local answer
    while :; do
        sc_heading other_results
        sc_line "$(sc_t other_menu)"
        printf '  > '; IFS= read -r answer || return 0
        case $answer in
            1) sc_browse_details suggestions;;
            2) sc_browse_details explained;;
            3) sc_render_short_report;;
            4) sc_line "$(sc_t report): $SC_RUN_DIR/report.txt"; sc_line "$(sc_t report_info)"; sc_render_report;;
            0) return 0;;
            *) sc_line "$(sc_t invalid)";;
        esac
    done
}

sc_menu() {
    local answer
    while :; do
        SC_DEMO=0; sc_brand
        sc_heading welcome
        sc_line "1  $(sc_t menu_full)" "$SC_C_WHITE$SC_C_BOLD"
        sc_line "$(sc_t full_includes)" "$SC_C_WHITE$SC_C_ITALIC"
        sc_line "2  $(sc_t menu_single)"
        sc_line "3  $(sc_t main_tools)"
        sc_line "0  $(sc_t exit)"
        printf '\n  %s > ' "$(sc_t choose)"; IFS= read -r answer || return 0
        case $answer in
            1) SC_SCAN=full; sc_run_requested;;
            2) sc_single_menu;;
            3) sc_tools_menu;;
            0) return 0;;
            *) sc_line "$(sc_t invalid)";;
        esac
    done
}

sc_single_menu() {
    local answer
    sc_heading menu_single
    sc_line "1  $(sc_t menu_rkhunter)"
    sc_line "2  $(sc_t menu_lynis)"
    sc_line "3  $(sc_t menu_integrity)"
    sc_line "0  $(sc_t back)"
    while :; do
        printf '  > '; IFS= read -r answer || return 0
        case $answer in
            1) SC_SCAN=rkhunter;;
            2) SC_SCAN=lynis;;
            3) SC_SCAN=integrity;;
            0) return 0;;
            *) sc_line "$(sc_t invalid)"; continue;;
        esac
        sc_run_requested; return $?
    done
}

sc_tools_menu() {
    local answer
    sc_heading main_tools
    sc_line "1  $(sc_t menu_deps)"
    sc_line "2  $(sc_t menu_update)"
    sc_line "0  $(sc_t back)"
    while :; do
        printf '  > '; IFS= read -r answer || return 0
        case $answer in
            1) sc_dependencies; return $?;;
            2) sc_update_action; return $?;;
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

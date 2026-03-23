#!/usr/bin/env bash
# =============================================================================
#  seccheck.sh — Security & Integrity Checker for Arch Linux
#  Brand: KlodCripta | Italian Linux Society
#  Version: 1.0.0
#  License: MIT
#  Description: Strumento di verifica sicurezza e integrità per Arch Linux.
#               Combina auditing (lynis), analisi anomalie (rkhunter) e
#               controllo integrità file di sistema (pacman -Qkk) in un
#               unico flusso guidato con output narrativo bilingue IT/EN.
# -----------------------------------------------------------------------------
#  Nota: 'set -e' è omesso consapevolmente. Diversi comandi restituiscono
#  exit code non-zero in modo legittimo; i casi sono gestiti esplicitamente.
# =============================================================================

set -uo pipefail

# =============================================================================
#  COLORI & STILI
# =============================================================================
RESET="\033[0m"
BOLD="\033[1m"
DIM="\033[2m"
RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
MAGENTA="\033[1;35m"
WHITE="\033[1;37m"
BG_RED="\033[41m"
BG_GREEN="\033[42m"
BG_YELLOW="\033[43;30m"
ORANGE="\033[38;5;208m"
ITALIC="\033[3m"

# =============================================================================
#  CONFIGURAZIONE
# =============================================================================
VERSION="1.0.0"
LOG_DIR="/var/log/seccheck"
TIMESTAMP=""   # inizializzato in reset_session, non all'avvio
LOG_FILE=""    # inizializzato in reset_session

TEMP_RKH=""
TEMP_LYN=""
TEMP_PAC=""

# Contatori globali scoring
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
INFO_COUNT=0

# Flag categorie per scoring avanzato
HAS_ROOTKIT_SIG=0
HAS_KERNEL=0
HAS_HIDDEN=0
HAS_NETWORK=0
HAS_STARTUP=0
HAS_INTEGRITY=0
HAS_HARDENING=0

# Array risultati classificati: severity|category|source|message|hint
declare -a CLASSIFIED_RESULTS=()

# Risk level calcolato dall'ultimo summary (passato alla fase 2)
SECCHECK_RISK_LEVEL="clean"

# Debug mode: SECCHECK_DEBUG=1 bash seccheck.sh
# Stampa classificazione parser, scarto e motivo per ogni riga analizzata
SECCHECK_DEBUG="${SECCHECK_DEBUG:-0}"

# =============================================================================
#  CLEANUP
# =============================================================================
cleanup() {
    [[ -n "$TEMP_RKH" ]] && rm -f "$TEMP_RKH"
    [[ -n "$TEMP_LYN" ]] && rm -f "$TEMP_LYN"
    [[ -n "$TEMP_PAC" ]] && rm -f "$TEMP_PAC"
}
trap cleanup EXIT

# =============================================================================
#  HELPERS
# =============================================================================
separator() {
    echo -e "${DIM}──────────────────────────────────────────────────────────────${RESET}"
}

narrate() {
    # EN: grassetto bianco (principale) — primo argomento
    # IT: corsivo dim (secondario, rientrato) — secondo argomento
    # CHIAMATA: narrate "EN text" "IT text"
    echo -e "${BOLD}${WHITE}${1}${RESET}"
    echo -e "${ITALIC}${DIM}  ↳ ${2}${RESET}"
}

status_ok()   { echo -e "${GREEN}  ✔  ${1}${RESET}"; }
status_warn() { echo -e "${YELLOW}  ⚠  ${1}${RESET}"; }
status_err()  { echo -e "${RED}  ✖  ${1}${RESET}"; }
status_info() { echo -e "${CYAN}  ➤  ${1}${RESET}"; }

severity_color() {
    case "$1" in
        high)   printf '%s' "$RED"    ;;
        medium) printf '%s' "$YELLOW" ;;
        low)    printf '%s' "$CYAN"   ;;
        *)      printf '%s' "$DIM"    ;;
    esac
}

think() {
    printf "${DIM}  %s " "$1"
    for _ in 1 2 3; do printf "."; sleep 0.4; done
    echo -e "${RESET}"
}

log() {
    [[ -n "$LOG_FILE" ]] && echo "[$(date '+%H:%M:%S')] $*" >> "$LOG_FILE"
}

log_classified() {
    local severity="$1" category="$2" message="$3" hint="$4" raw="$5"
    [[ -z "$LOG_FILE" ]] && return
    {
        echo "  [${severity}] [${category}]"
        echo "    Message : ${message}"
        echo "    Hint    : ${hint}"
        echo "    Raw     : ${raw}"
    } >> "$LOG_FILE"
}

# =============================================================================
#  BANNER
# =============================================================================
show_banner() {
    clear
    # SEC = rosso bold, CHECK = bianco bold
    local SR="\033[1;31m"   # rosso bold
    local SW="\033[1;37m"   # bianco bold
    local R="\033[0m"
    echo ""
    echo -e "  ${SR}███████╗███████╗ ██████╗${R} ${SW}██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗${R}"
    echo -e "  ${SR}██╔════╝██╔════╝██╔════╝${R} ${SW}██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝${R}"
    echo -e "  ${SR}███████╗█████╗  ██║     ${R} ${SW}██║     ███████║█████╗  ██║     █████╔╝ ${R}"
    echo -e "  ${SR}╚════██║██╔══╝  ██║     ${R} ${SW}██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ${R}"
    echo -e "  ${SR}███████║███████╗╚██████╗${R} ${SW}╚██████╗██║  ██║███████╗╚██████╗██║  ██╗${R}"
    echo -e "  ${SR}╚══════╝╚══════╝ ╚═════╝${R} ${SW} ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝${R}"
    echo -e "${RESET}"
    echo -e "  ${CYAN}${BOLD}Security & Integrity Checker for Arch Linux${RESET}  ${DIM}v${VERSION} | KlodCripta${RESET}"
    [[ "${SECCHECK_DEBUG:-0}" == "1" ]] && echo -e "  ${YELLOW}${BOLD}  ⚑  DEBUG MODE ACTIVE — SECCHECK_DEBUG=1${RESET}" || true
    separator
    echo ""
}

# =============================================================================
#  CHECK ROOT — auto-riesecuzione con sudo
# =============================================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo ""
        status_warn "Privilegi di root richiesti / Root privileges required"
        narrate \
            "Re-launching automatically with sudo..." \
            "Rilancio automatico con sudo..."
        echo ""
        exec sudo "$0" "$@"
    fi
}

# =============================================================================
#  CHECK DISTRO — solo Arch Linux e derivate
# =============================================================================
check_distro() {
    separator
    narrate \
        "Checking system compatibility..." \
        "Verifico la compatibilità del sistema..."
    echo ""

    local distro_id=""
    local distro_name="Unknown"

    if [[ -f /etc/os-release ]]; then
        distro_id=$(grep "^ID=" /etc/os-release | cut -d= -f2 | tr -d '"' | tr '[:upper:]' '[:lower:]')
        distro_name=$(grep "^PRETTY_NAME=" /etc/os-release | cut -d= -f2 | tr -d '"')
        local id_like=""
        id_like=$(grep "^ID_LIKE=" /etc/os-release | cut -d= -f2 | tr -d '"' | tr '[:upper:]' '[:lower:]')

        # Verifica Arch o derivate (EndeavourOS, Manjaro, Garuda, CachyOS, ecc.)
        if [[ "$distro_id" == "arch" ]] || \
           [[ "$id_like" == *"arch"* ]] || \
           command -v pacman &>/dev/null; then
            status_ok "Compatible system${RESET} ${ITALIC}${DIM}/ Sistema compatibile: ${distro_name}"
            log "System: ${distro_name} (id: ${distro_id})"
            echo ""
            return 0
        fi
    fi

    # Distro non supportata
    echo ""
    status_err "Sistema non supportato / Unsupported system"
    narrate \
        "SecCheck officially supports only Arch Linux and Arch-based distributions." \
        "SecCheck supporta ufficialmente solo Arch Linux e le sue derivate."
    narrate \
        "Detected system: ${distro_name}" \
        "Sistema rilevato: ${distro_name}"
    echo ""
    exit 0
}

# =============================================================================
#  LOG SETUP — chiamato solo prima di una scansione
# =============================================================================
setup_log() {
    mkdir -p "$LOG_DIR" || {
        echo -e "${RED}  ✖  Impossibile creare ${LOG_DIR}${RESET}" >&2
        exit 1
    }
    chmod 700 "$LOG_DIR" 2>/dev/null || true
    : > "$LOG_FILE" || {
        echo -e "${RED}  ✖  Impossibile creare il file log: ${LOG_FILE}${RESET}" >&2
        exit 1
    }
    chmod 600 "$LOG_FILE" 2>/dev/null || true
    {
        echo "=============================================="
        echo "  SECCHECK Security Report — v${VERSION}"
        echo "  Date   : $(date '+%A %d %B %Y, %H:%M:%S')"
        echo "  Host   : $(hostnamectl --static 2>/dev/null || hostname 2>/dev/null || uname -n)"
        echo "  Kernel : $(uname -r)"
        echo "  User   : $(whoami)"
        echo "=============================================="
        echo ""
    } >> "$LOG_FILE"
}

# =============================================================================
#  DIPENDENZE — solo rkhunter e lynis (repo ufficiali Arch)
# =============================================================================
check_deps() {
    separator
    narrate \
        "Checking for required security tools..." \
        "Verifico la presenza degli strumenti necessari..."
    echo ""

    local missing=()
    command -v rkhunter &>/dev/null || missing+=("rkhunter")
    command -v lynis    &>/dev/null || missing+=("lynis")
    # pacman è sempre disponibile su Arch — nessun controllo necessario

    if [[ ${#missing[@]} -eq 0 ]]; then
        status_ok "rkhunter — found  ${ITALIC}${DIM}/ trovato"
        status_ok "lynis    — found  ${ITALIC}${DIM}/ trovato"
        status_ok "pacman   — available  ${ITALIC}${DIM}/ disponibile"
        echo ""
        return 0
    fi

    status_warn "Strumenti mancanti / Missing tools:"
    for pkg in "${missing[@]}"; do
        echo -e "    ${YELLOW}→ ${pkg}${RESET}"
    done
    echo ""
    narrate \
        "Both tools are available in the official Arch Linux repositories." \
        "Entrambi i tool sono disponibili nei repository ufficiali di Arch Linux."
    echo ""

    read -rp "$(echo -e "  ${BOLD}Installo i tool mancanti con pacman? / Install missing tools with pacman? [s/n]: ${RESET}")" answer
    echo ""

    if [[ "$answer" =~ ^[ssSyY]$ ]]; then
        narrate \
            "Installing..." \
            "Procedo con l'installazione..."
        echo ""
        if pacman -S --needed --noconfirm "${missing[@]}"; then
            echo ""
            status_ok "Installation complete  ${ITALIC}${DIM}/ Installazione completata"
            log "Installed: ${missing[*]}"
        else
            status_err "Installazione fallita / Installation failed"
            log "ERROR: Failed to install ${missing[*]}"
            exit 1
        fi
    else
        echo ""
        narrate \
            "Installation cancelled. Cannot continue without the required tools." \
            "Installazione annullata. Impossibile continuare senza i tool richiesti."
        exit 0
    fi
}

# =============================================================================
#  PARSER ENGINE — RKHUNTER
# =============================================================================
classify_rkhunter_line() {
    local line="$1"
    local l lw
    l="$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')"
    lw="$l"
    [[ "$lw" == "warning: "* ]] && lw="${lw#warning: }"

    # FASE 1 — descrittive/operative (non sono rilevamenti)
    case "$lw" in
        "checking "*|"checking for"*|"checking if"*|\
        "searching for"*|"performing "*|"running test"*|"running "*|\
        "testing for "*|"starting "*|"inspection started"*|\
        "scan running"*|"hash tables"*|"boot process"*)
            printf 'info|info|Descriptive scan output|Riga descrittiva del controllo in corso\n'
            return ;;
    esac
    case "$l" in
        *"[ info ]"*|*"info:"*)
            printf 'info|info|Descriptive scan output|Riga descrittiva\n'
            return ;;
    esac

    # FASE 2 — environment/missing/skipped
    case "$lw" in
        *"optional application"*|*"not installed"*|"test skipped"*|\
        *"skipped due to"*|"disabled test"*|*"missing command"*|*"not enabled"*)
            printf 'info|environment_or_missing_tools|Check incomplete or optional tool missing|Non si tratta di una minaccia ma di un controllo parziale\n'
            return ;;
    esac

    # FASE 3 — risultati puliti
    case "$lw" in
        *"not found"*|*"none found"*|*"nothing found"*|*"no issues"*|*"[ ok ]"*|*"[ok]"*)
            printf 'info|clean_or_neutral|No significant anomaly reported by this check|Nessuna azione necessaria\n'
            return ;;
    esac

    # FASE 4 — rootkit signature forti
    case "$lw" in
        *"warning:"*" rootkit"*|*"possible rootkit"*|*"suspect rootkit"*|\
        *"rootkit found"*|*"infected:"*|*"infected file detected"*)
            printf 'high|rootkit_signature|Possible match with a known rootkit signature|Verifica manuale raccomandata: questo risultato non va ignorato\n'
            return ;;
    esac

    # FASE 5 — classificazione per famiglia
    case "$lw" in
        *"kernel module"*|*"suspicious module"*|*"loaded module"*)
            printf 'medium|kernel_modules|Kernel module anomaly detected|Non prova da sola una compromissione, ma richiede attenzione\n'
            return ;;
        *"hidden file"*|*"hidden files"*|*"hidden directory"*|*"hidden directories"*)
            printf 'medium|hidden_artifacts|Hidden file or directory detected|La posizione del file è l elemento determinante da valutare\n'
            return ;;
        *"promiscuous"*|*"sniffer"*|*"promisc"*)
            printf 'medium|sniffer_or_promisc|Promiscuous interface or sniffing-related condition detected|Verificare se associata a software di rete noto\n'
            return ;;
        *"listening port"*|*"network interface"*|*"suspicious port"*)
            printf 'medium|network_anomaly|Network service or interface requires identification|Attribuire il servizio a un processo noto prima di trarre conclusioni\n'
            return ;;
        *"startup file"*|*"system startup"*|*"init file"*|\
        *"boot file"*|*"bootloader"*|*"boot sector"*)
            printf 'medium|startup_config|Startup or boot-related anomaly detected|Area sensibile: controllare se il cambiamento è atteso\n'
            return ;;
        *"suspicious string"*|*"suspicious entry"*|*"suspicious file"*)
            printf 'medium|suspicious_strings|Suspicious content or reference detected|Da solo non prova nulla; verificare nel contesto del sistema\n'
            return ;;
        *"file properties have changed"*|*"properties changed"*|\
        *"hash value"*|*"sha256"*|*"md5"*|\
        *"command replaced"*|*"script replaced"*)
            printf 'low|file_properties|System file properties or hashes differ from expected values|Comune dopo aggiornamenti; verificare solo se inatteso\n'
            return ;;
        *"permission"*|*"owner"*|*"group changed"*)
            printf 'low|permissions_ownership|Permissions or ownership differ from expected values|Controllare soprattutto file critici\n'
            return ;;
        *"hosts file"*|*"localhost"*|*"dns"*|*"name resolution"*|*"resolv"*)
            printf 'low|network_config|Network configuration anomaly detected|Verificare configurazione e modifiche recenti\n'
            return ;;
        *"warning"*)
            printf 'medium|heuristic_warning|Generic warning reported by rkhunter|Valutare il contesto; comune su sistemi rolling release\n'
            return ;;
    esac

    printf 'info|info|Informational output|Dettaglio registrato nel report completo\n'
}

adjust_severity_with_context() {
    local severity="$1" category="$2" raw_line="$3"
    local l
    l="$(printf '%s' "$raw_line" | tr '[:upper:]' '[:lower:]')"

    case "$category" in
        hidden_artifacts)
            case "$l" in
                *"/tmp/"*|*"/var/tmp/"*|*"/dev/"*|*"/run/"*|*"/.cache/"*)
                    [[ "$severity" == "medium" ]] && severity="low" ;;
                *"/bin/"*|*"/sbin/"*|*"/usr/bin/"*|*"/usr/sbin/"*|*"/etc/"*|*"/boot/"*)
                    [[ "$severity" == "low" ]] && severity="medium" ;;
            esac ;;
        file_properties)
            case "$l" in
                *"/bin/login"*|*"/bin/passwd"*|*"/bin/su"*|\
                *"/usr/bin/passwd"*|*"/usr/bin/sudo"*|*"/usr/bin/doas"*|\
                *"/usr/sbin/sshd"*|*"/etc/passwd"*|*"/etc/shadow"*|*"/etc/sudoers"*)
                    [[ "$severity" == "low" ]] && severity="medium" ;;
            esac ;;
        network_anomaly|sniffer_or_promisc)
            case "$l" in
                *"sshd"*|*"networkmanager"*|*"systemd-resolved"*|\
                *"dhclient"*|*"dhcpcd"*|*"wpa_supplicant"*)
                    [[ "$severity" == "medium" ]] && severity="low" ;;
            esac ;;
        permissions_ownership)
            case "$l" in
                *"/etc/passwd"*|*"/etc/shadow"*|*"/etc/sudoers"*|\
                *"/etc/ssh"*|*"/boot"*)
                    [[ "$severity" == "low" ]] && severity="medium" ;;
            esac ;;
    esac

    printf '%s\n' "$severity"
}

# =============================================================================
#  PARSER ENGINE — LYNIS
# =============================================================================
classify_lynis_line() {
    local line="$1"
    local l fragment
    l="$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')"

    # Estrae un frammento leggibile dalla riga (rimuove prefissi verbose lynis)
    # Lynis stampa spesso: "  [WARNING] Description text here"
    fragment="$(printf '%s' "$line" | sed 's/^[[:space:]]*//' | cut -c1-60)"
    [[ -z "$fragment" ]] && fragment="$line"

    # Lynis usa [WARNING], [SUGGESTION], [OK], [FOUND], [NOT FOUND]
    case "$l" in
        # Risultati puliti
        *"[ok]"*|*"[ ok ]"*|*"not found"*|*"no issues"*)
            printf 'info|clean_or_neutral|No issue reported by lynis|Nessuna azione necessaria
'
            return ;;
        # Warning espliciti — include frammento reale
        *"[warning]"*)
            printf 'medium|hardening_warning|%s|Verificare la raccomandazione nel report lynis
' "$fragment"
            return ;;
        # Suggerimenti — include frammento reale
        *"[suggestion]"*)
            printf 'low|hardening_suggestion|%s|Opportunità di hardening — azione opzionale
' "$fragment"
            return ;;
        # Anomalie/trovato — include frammento reale
        *"[found]"*|*"found:"*)
            printf 'medium|hardening_found|%s|Verificare il dettaglio nel report completo
' "$fragment"
            return ;;
        # Righe descrittive/intestazioni
        *"performing tests"*|*"checking "*|*"starting "*|*"test:"*|        *"---"*|*"==="*)
            printf 'info|info|Descriptive lynis output|Riga descrittiva
'
            return ;;
    esac

    printf 'info|info|Informational lynis output|Dettaglio nel report completo
'
}

# =============================================================================
#  PARSER ENGINE — PACMAN INTEGRITY (pacman -Qkk)
# =============================================================================
classify_pacman_line() {
    local line="$1"
    local l
    l="$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')"

    case "$l" in
        # File mancante
        *"missing file"*|*"file mancante"*)
            printf 'medium|integrity_missing|System file missing|Un file di sistema non è presente dove atteso\n'
            return ;;
        # Hash/dimensione modificata
        *"size"*"mismatch"*|*"md5"*"mismatch"*|*"sha256"*"mismatch"*)
            printf 'medium|integrity_modified|System file modified|Il file differisce dalla versione attesa dal pacchetto\n'
            return ;;
        # Warning generico di integrità
        *"warning"*)
            printf 'low|integrity_warning|Package integrity warning|Verificare il file segnalato\n'
            return ;;
        # Riga con errore esplicito
        *"error"*)
            printf 'medium|integrity_error|Package integrity check error|Errore durante la verifica; controllare il file\n'
            return ;;
    esac

    # Se la riga contiene il nome di un file con ": " → probabilmente un'anomalia
    if echo "$l" | grep -q "^[a-z0-9_-]*: /"; then
        printf 'low|integrity_anomaly|Package file anomaly|Il file potrebbe differire dalla versione del pacchetto\n'
        return
    fi

    printf 'info|info|Informational pacman output|Dettaglio nel report completo\n'
}

# =============================================================================
#  REGISTER & PARSE
# =============================================================================
register_result() {
    local source="$1" severity="$2" category="$3"
    local message="$4" hint="$5" raw="$6"

    # Debug mode: mostra ogni classificazione in tempo reale
    if [[ "${SECCHECK_DEBUG:-0}" == "1" ]]; then
        if [[ "$severity" == "info" ]]; then
            echo -e "  ${DIM}[DBG:${source}] info/${category} → ${raw:0:60}${RESET}" >&2
        else
            echo -e "  \033[38;5;208m[DBG:${source}] ${severity}/${category} → ${raw:0:60}\033[0m" >&2
        fi
    fi

    if [[ "$severity" == "info" ]]; then
        (( INFO_COUNT++ )) || true
        return
    fi

    case "$severity" in
        high)   (( HIGH_COUNT++   )) || true ;;
        medium) (( MEDIUM_COUNT++ )) || true ;;
        low)    (( LOW_COUNT++    )) || true ;;
    esac

    case "$category" in
        rootkit_signature)
            HAS_ROOTKIT_SIG=1 ;;
        kernel_modules)
            # HAS_KERNEL solo se HIGH — un MEDIUM kernel non è conferma sufficiente
            [[ "$severity" == "high" ]] && HAS_KERNEL=1 ;;
        hidden_artifacts)
            HAS_HIDDEN=1 ;;
        network_anomaly|sniffer_or_promisc)
            # HAS_NETWORK solo se HIGH — un MEDIUM network non è conferma sufficiente
            [[ "$severity" == "high" ]] && HAS_NETWORK=1 ;;
        startup_config)
            HAS_STARTUP=1 ;;
        integrity_missing|integrity_modified|integrity_error)
            HAS_INTEGRITY=1 ;;
        hardening_warning|hardening_found)
            HAS_HARDENING=1 ;;
    esac

    CLASSIFIED_RESULTS+=("${severity}|${category}|${source}|${message}|${hint}")
    log_classified "$severity" "$category" "$message" "$hint" "$raw"
}

parse_output() {
    local source="$1" file="$2"

    while IFS= read -r line; do
        [[ -z "${line// }" ]] && continue

        local result severity category message hint rest
        case "$source" in
            rkhunter) result="$(classify_rkhunter_line "$line")" ;;
            lynis)    result="$(classify_lynis_line    "$line")" ;;
            pacman)   result="$(classify_pacman_line   "$line")" ;;
            *) continue ;;
        esac

        severity="${result%%|*}";  rest="${result#*|}"
        category="${rest%%|*}";    rest="${rest#*|}"
        message="${rest%%|*}"
        hint="${rest#*|}"

        # Override contestuale (solo per rkhunter)
        [[ "$source" == "rkhunter" ]] && \
            severity="$(adjust_severity_with_context "$severity" "$category" "$line")"

        register_result "$source" "$severity" "$category" "$message" "$hint" "$line"

    done < "$file"
}

# =============================================================================
#  SEMAFORO — indicatore visivo stato complessivo
# =============================================================================
show_traffic_light() {
    local risk_level="$1"

    # Pallini: ● attivo (colorato), ○ inattivo (grigio)
    # Posizioni: [verde] [giallo] [arancione] [rosso]
    local dot_on="●"
    local dot_off="${DIM}○${RESET}"

    local g y o r label

    case "$risk_level" in
        clean)
            g="${GREEN}${dot_on}${RESET}"
            y="$dot_off" o="$dot_off" r="$dot_off"
            label="${GREEN}${BOLD}VERDE${RESET}     — sistema in stato coerente"
            ;;
        attention)
            g="$dot_off"
            y="${YELLOW}${dot_on}${RESET}"
            o="$dot_off" r="$dot_off"
            label="${YELLOW}${BOLD}GIALLO${RESET}    — avvisi tecnici da valutare"
            ;;
        review)
            g="$dot_off" y="$dot_off"
            o="${ORANGE}${dot_on}${RESET}"
            r="$dot_off"
            label="${ORANGE}${BOLD}● ARANCIONE${RESET} — alcune anomalie richiedono verifica"
            ;;
        relevant_anomaly)
            g="$dot_off" y="$dot_off" o="$dot_off"
            r="${RED}${dot_on}${RESET}"
            label="${RED}${BOLD}ROSSO${RESET}     — anomalia rilevante confermata"
            ;;
    esac

    echo -e "  ${DIM}Semaforo sicurezza / Security traffic light${RESET}"
    echo -e "  ${g}  ${y}  ${o}  ${r}    ${label}"
}

# =============================================================================
#  DISPLAY ENGINE — output sintetico a schermo, dettaglio completo nel log
# =============================================================================

# Conta risultati per fonte (non-info)
count_results_for() {
    local source="$1" count=0
    for entry in "${CLASSIFIED_RESULTS[@]:-}"; do
        local src rest
        rest="${entry#*|}"; rest="${rest#*|}"; src="${rest%%|*}"
        [[ "$src" == "$source" ]] && (( count++ )) || true
    done
    printf '%s\n' "$count"
}

# Stampa massimo N esempi per fonte, con contatore "...and X more"
# Priorità: high prima, poi medium, poi low
# Per HIGH rkhunter isolato aggiunge tag [low confidence]
print_limited_results_for() {
    local source="$1"
    local max="${2:-5}"
    local shown=0 total=0

    total="$(count_results_for "$source")"
    (( total == 0 )) && return

    # Determina se siamo nel caso HIGH rkhunter isolato (low confidence)
    local rkh_isolated=0
    if [[ "$source" == "rkhunter" ]]; then
        local h_rkh=0 h_other=0
        for entry in "${CLASSIFIED_RESULTS[@]:-}"; do
            local sev src rest
            sev="${entry%%|*}"; rest="${entry#*|}"
            rest="${rest#*|}";  src="${rest%%|*}"
            [[ "$sev" != "high" ]] && continue
            [[ "$src" == "rkhunter" ]] && (( h_rkh++ )) || true
            [[ "$src" != "rkhunter" ]] && (( h_other++ )) || true
        done
        (( h_rkh >= 1 && h_other == 0 && HAS_KERNEL == 0 && HAS_NETWORK == 0 )) && rkh_isolated=1
    fi

    for sev_filter in high medium low; do
        for entry in "${CLASSIFIED_RESULTS[@]:-}"; do
            local sev cat src msg hint rest
            sev="${entry%%|*}";  rest="${entry#*|}"
            cat="${rest%%|*}";   rest="${rest#*|}"
            src="${rest%%|*}";   rest="${rest#*|}"
            msg="${rest%%|*}";   hint="${rest#*|}"
            [[ "$src" != "$source" ]] && continue
            [[ "$sev" != "$sev_filter" ]] && continue
            (( shown >= max )) && break 2
            local col confidence_tag=""
            col="$(severity_color "$sev")"
            # Aggiunge tag low confidence per HIGH rkhunter isolato
            if [[ "$sev" == "high" && "$rkh_isolated" == "1" ]]; then
                # Tag confidence in grigio/dim — NON rosso, non allarmante
                confidence_tag=" ${DIM}(low confidence — rkhunter only)${RESET}"
            fi
            # [HIGH/MEDIUM/LOW] colorato per severity, testo sempre bianco
            local prefix=""
            [[ "$sev" == "high" ]]   && prefix=" ✖" || true
            [[ "$sev" == "medium" ]] && prefix=" ⚠" || true
            [[ "$sev" == "low" ]]    && prefix=" ↓" || true
            echo -e "  ${col}${BOLD}[${sev^^}]${prefix}${RESET} ${WHITE}${msg}${RESET}${confidence_tag}"
            (( shown++ )) || true
        done
    done

    local remaining=$(( total - shown ))
    if (( remaining > 0 )); then
        echo -e "  ${DIM}...e altri ${remaining} / ...and ${remaining} more (see full report)${RESET}"
    fi
}

# Riepilogo sintetico per modulo: contatori + esempi limitati
print_module_summary() {
    local source="$1"
    local label="$2"
    local max_examples="${3:-3}"

    local h=0 m=0 l=0
    for entry in "${CLASSIFIED_RESULTS[@]:-}"; do
        local sev src rest
        sev="${entry%%|*}"; rest="${entry#*|}"
        rest="${rest#*|}";  src="${rest%%|*}"
        [[ "$src" != "$source" ]] && continue
        case "$sev" in
            high)   (( h++ )) || true ;;
            medium) (( m++ )) || true ;;
            low)    (( l++ )) || true ;;
        esac
    done

    local total=$(( h + m + l ))

    if (( total == 0 )); then
        echo -e "  ${GREEN}✔${RESET}  ${BOLD}${label}${RESET}  ${DIM}Nessuna anomalia / No findings${RESET}"
        return
    fi

    # Label modulo in bold bianco, contatori colorati per severity
    # HIGH=rosso, MEDIUM=giallo, LOW=ciano — colore segue la severity, non il modulo
    local h_str m_str l_str
    (( h > 0 )) && h_str="${RED}High: ${h}${RESET}" || h_str="${DIM}High: 0${RESET}"
    (( m > 0 )) && m_str="${YELLOW}Medium: ${m}${RESET}" || m_str="${DIM}Medium: 0${RESET}"
    (( l > 0 )) && l_str="${CYAN}Low: ${l}${RESET}" || l_str="${DIM}Low: 0${RESET}"
    echo -e "  ${BOLD}${WHITE}${label}${RESET}  →  ${h_str}  ${m_str}  ${l_str}"
    print_limited_results_for "$source" "$max_examples"
}

# =============================================================================
#  MODULO 1 — RKHUNTER
# =============================================================================
run_rkhunter() {
    separator
    echo -e "  ${CYAN}${BOLD}MODULE 1 — rkhunter${RESET}  ${DIM}Anomaly & rootkit analysis  ${ITALIC}/ Analisi anomalie e rootkit${RESET}"
    separator
    echo ""
    narrate \
        "rkhunter inspects system binaries, kernel modules and configuration" \
        "rkhunter analizza i binari di sistema, i moduli del kernel e la configurazione"
    narrate \
        "for known rootkits, backdoors and anomalies." \
        "alla ricerca di rootkit, backdoor e anomalie note."
    echo ""

    narrate \
        "Updating the threat database before scanning..." \
        "Aggiorno il database delle minacce prima di procedere..."
    think "Updating / Aggiornamento"
    rkhunter --update --nocolors &>/dev/null || true
    status_ok "Database updated  ${ITALIC}${DIM}/ Database aggiornato"
    echo ""

    narrate \
        "Starting scan. This may take a few minutes." \
        "Avvio la scansione. Potrebbe richiedere qualche minuto."
    think "Scanning / Scansione in corso"

    TEMP_RKH=$(mktemp /tmp/seccheck_rkh.XXXXXX)
    log "--- rkhunter START ---"
    rkhunter --check --nocolors --sk 2>/dev/null > "$TEMP_RKH" || true
    cat "$TEMP_RKH" >> "$LOG_FILE"
    log "--- rkhunter END ---"

    parse_output "rkhunter" "$TEMP_RKH"

    echo ""
    separator

    local total
    total="$(count_results_for "rkhunter")"

    if (( total == 0 )); then
        status_ok "Nessun elemento rilevante / No relevant findings"
        log "rkhunter: CLEAN"
    else
        print_limited_results_for "rkhunter" 5
        if (( total > 0 )); then
            echo ""
            echo -e "  ${BOLD}${WHITE}Common warnings after rolling updates may be false positives.${RESET}"
            echo -e "  ${ITALIC}${DIM}  ↳ Avvisi comuni dopo aggiornamenti rolling possono essere falsi positivi.${RESET}"
        fi
        log "rkhunter: ${total} findings"
    fi
    echo ""
}

# =============================================================================
#  MODULO 2 — LYNIS
# =============================================================================
run_lynis() {
    separator
    echo -e "  ${CYAN}${BOLD}MODULE 2 — lynis${RESET}  ${DIM}Security audit & hardening  ${ITALIC}/ Audit sicurezza e hardening${RESET}"
    separator
    echo ""
    narrate \
        "lynis performs a full system audit: configurations, permissions," \
        "lynis esegue un audit completo del sistema: configurazioni, permessi,"
    narrate \
        "active services, kernel parameters and general security posture." \
        "servizi attivi, parametri del kernel e postura generale di sicurezza."
    echo ""
    narrate \
        "Running in --quick mode to reduce time while maintaining coverage." \
        "Esecuzione in modalità --quick per ridurre i tempi mantenendo la copertura."
    think "Auditing / Audit in corso"

    TEMP_LYN=$(mktemp /tmp/seccheck_lyn.XXXXXX)
    log "--- lynis START ---"
    lynis audit system --quick --no-colors --quiet 2>/dev/null > "$TEMP_LYN" || true
    cat "$TEMP_LYN" >> "$LOG_FILE"
    log "--- lynis END ---"

    parse_output "lynis" "$TEMP_LYN"

    echo ""
    separator

    local total
    total="$(count_results_for "lynis")"

    # Conta separatamente warning e suggestions per lynis
    local lyn_warn=0 lyn_sugg=0
    for entry in "${CLASSIFIED_RESULTS[@]:-}"; do
        local sev cat src rest
        sev="${entry%%|*}"; rest="${entry#*|}"
        cat="${rest%%|*}";  rest="${rest#*|}"
        src="${rest%%|*}"
        [[ "$src" != "lynis" ]] && continue
        [[ "$cat" == "hardening_warning" || "$cat" == "hardening_found" ]] && (( lyn_warn++ )) || true
        [[ "$cat" == "hardening_suggestion" ]] && (( lyn_sugg++ )) || true
    done

    if (( total == 0 )); then
        status_ok "Nessun elemento rilevante / No relevant findings"
        log "lynis: CLEAN"
    else
        echo -e "  ${YELLOW}Warnings: ${lyn_warn}${RESET}  ${CYAN}Suggestions: ${lyn_sugg}${RESET}"
        echo ""
        print_limited_results_for "lynis" 5
        echo ""
        echo -e "  ${DIM}I suggerimenti lynis indicano opportunità di hardening, non anomalie critiche.${RESET}"
        echo -e "  ${DIM}Lynis suggestions indicate hardening opportunities, not critical anomalies.${RESET}"
        log "lynis: ${total} findings (warn:${lyn_warn} sugg:${lyn_sugg})"
    fi
    echo ""
}

# =============================================================================
#  MODULO 3 — INTEGRITÀ PACMAN
# =============================================================================
run_pacman_integrity() {
    separator
    echo -e "  ${CYAN}${BOLD}MODULE 3 — package integrity${RESET}  ${DIM}pacman -Qkk  ${ITALIC}/ Integrità pacchetti${RESET}"
    separator
    echo ""
    narrate \
        "Checking system file integrity by comparing installed files" \
        "Verifico l'integrità dei file di sistema confrontando i file installati"
    narrate \
        "against package metadata: sizes, hashes and permissions." \
        "con i metadati dei pacchetti: dimensioni, hash e permessi."
    echo ""
    narrate \
        "This check is Arch-native and requires no external dependencies." \
        "Questo controllo è nativo Arch e non richiede dipendenze esterne."
    think "Checking integrity / Verifica integrità"

    TEMP_PAC=$(mktemp /tmp/seccheck_pac.XXXXXX)
    log "--- pacman integrity START ---"
    # -Qkk: verifica file con controllo hash (più approfondito di -Qk)
    # 2>&1 cattura anche gli avvisi su stderr
    pacman -Qkk 2>&1 | grep -v "^$" > "$TEMP_PAC" || true
    # Filtra solo le righe con anomalie (esclude i pacchetti OK)
    grep -v ": all files present and unmodified" "$TEMP_PAC" > "${TEMP_PAC}.filtered" 2>/dev/null || true
    cat "$TEMP_PAC" >> "$LOG_FILE"
    log "--- pacman integrity END ---"

    parse_output "pacman" "${TEMP_PAC}.filtered"
    rm -f "${TEMP_PAC}.filtered"

    echo ""
    separator

    local total
    total="$(count_results_for "pacman")"

    # Conta per tipo di anomalia integrità
    local pac_miss=0 pac_mod=0 pac_other=0
    for entry in "${CLASSIFIED_RESULTS[@]:-}"; do
        local sev cat src rest
        sev="${entry%%|*}"; rest="${entry#*|}"
        cat="${rest%%|*}";  rest="${rest#*|}"
        src="${rest%%|*}"
        [[ "$src" != "pacman" ]] && continue
        case "$cat" in
            integrity_missing) (( pac_miss++ )) || true ;;
            integrity_modified|integrity_error) (( pac_mod++ )) || true ;;
            *) (( pac_other++ )) || true ;;
        esac
    done

    if (( total == 0 )); then
        status_ok "Integrità verificata / Integrity verified"
        log "pacman integrity: CLEAN"
    else
        [[ $pac_miss  -gt 0 ]] && echo -e "  ${RED}File mancanti / Missing files: ${pac_miss}${RESET}"
        [[ $pac_mod   -gt 0 ]] && echo -e "  ${YELLOW}File modificati / Modified files: ${pac_mod}${RESET}"
        [[ $pac_other -gt 0 ]] && echo -e "  ${CYAN}Altri avvisi / Other warnings: ${pac_other}${RESET}"
        echo ""
        print_limited_results_for "pacman" 5
        echo ""
        echo -e "  ${DIM}Modifiche a file di configurazione sono spesso legittime.${RESET}"
        echo -e "  ${DIM}Configuration file changes are often legitimate.${RESET}"
        log "pacman integrity: ${total} findings (miss:${pac_miss} mod:${pac_mod})"
    fi
    echo ""
}

# =============================================================================
#  RISK CALCULATOR & SUMMARY
# =============================================================================
show_summary() {
    # Calcolo risk level
    local distinct_medium=0 seen_cats="|"
    for entry in "${CLASSIFIED_RESULTS[@]:-}"; do
        local sev cat rest
        sev="${entry%%|*}"; rest="${entry#*|}"
        cat="${rest%%|*}"
        if [[ "$sev" == "medium" && "$seen_cats" != *"|${cat}|"* ]]; then
            seen_cats="${seen_cats}${cat}|"
            (( distinct_medium++ )) || true
        fi
    done

    local risk_level="clean"
    local risk_message="Nessuna anomalia significativa rilevata."

    # ── Conta HIGH per fonte ────────────────────────────────────────────────────
    local high_rkh=0 high_lyn=0 high_pac=0
    for entry in "${CLASSIFIED_RESULTS[@]:-}"; do
        local sev src rest
        sev="${entry%%|*}"; rest="${entry#*|}"
        rest="${rest#*|}";  src="${rest%%|*}"
        [[ "$sev" != "high" ]] && continue
        case "$src" in
            rkhunter) (( high_rkh++ )) || true ;;
            lynis)    (( high_lyn++ )) || true ;;
            pacman)   (( high_pac++ )) || true ;;
        esac
    done

    # ── Conta MEDIUM per fonte ────────────────────────────────────────────────
    local med_rkh=0 med_lyn=0 med_pac=0
    for entry in "${CLASSIFIED_RESULTS[@]:-}"; do
        local sev src rest
        sev="${entry%%|*}"; rest="${entry#*|}"
        rest="${rest#*|}";  src="${rest%%|*}"
        [[ "$sev" != "medium" ]] && continue
        case "$src" in
            rkhunter) (( med_rkh++ )) || true ;;
            lynis)    (( med_lyn++ )) || true ;;
            pacman)   (( med_pac++ )) || true ;;
        esac
    done

    # ── REGOLE VERDETTO ───────────────────────────────────────────────────────
    #
    # REGOLA 1 — CRITICAL: più HIGH da fonti diverse, o HIGH confermato
    #   da indicatori forti correlati (kernel + network insieme)
    #
    # REGOLA 2 — REVIEW: HIGH rkhunter isolato (nessun altro HIGH,
    #   nessun flag kernel/network) → probabile falso positivo su Arch.
    #   I MEDIUM da soli NON promuovono mai a relevant_anomaly.
    #
    # REGOLA 3 — REVIEW: combinazioni di MEDIUM da categorie diverse
    #   su fonti diverse (non solo volume grezzo)
    #
    # REGOLA 4 — ATTENTION: solo LOW o MEDIUM generici isolati

    local cross_source_high=$(( (high_rkh > 0 ? 1 : 0) + (high_lyn > 0 ? 1 : 0) + (high_pac > 0 ? 1 : 0) ))

    if (( cross_source_high >= 2 )); then
        # HIGH confermato da più fonti indipendenti → segnale serio
        risk_level="relevant_anomaly"
        risk_message="Anomalie rilevate su più aree del sistema. Analisi manuale necessaria."

    elif (( high_rkh >= 1 || high_lyn >= 1 || high_pac >= 1 )); then
        # Qualsiasi HIGH da fonte singola su Arch rolling → probabile falso positivo
        # Non escalare a relevant_anomaly senza conferma da fonti diverse
        risk_level="review"
        risk_message="Potential anomaly detected. On Arch this warning may be a false positive — verification recommended."

    elif (( distinct_medium >= 3 )); then
        # Molte categorie medium diverse su più aree
        risk_level="review"
        risk_message="Diversi elementi da verificare in aree distinte del sistema."

    elif (( (med_rkh > 0 ? 1 : 0) + (med_lyn > 0 ? 1 : 0) + (med_pac > 0 ? 1 : 0) >= 2 )); then
        # MEDIUM su almeno 2 fonti diverse
        risk_level="review"
        risk_message="Elementi da verificare rilevati su più moduli."

    elif (( MEDIUM_COUNT >= 1 )); then
        risk_level="attention"
        risk_message="Presenti avvisi tecnici da valutare nel contesto del sistema."

    elif (( LOW_COUNT >= 1 )); then
        risk_level="attention"
        risk_message="Presenti avvisi tecnici comuni. Verifica consigliata solo se inattesi."
    fi

    # Contatori per fonte e categoria
    local rkh_h=0 rkh_m=0 rkh_l=0
    local lyn_h=0 lyn_m=0 lyn_l=0
    local pac_h=0 pac_m=0 pac_l=0

    for entry in "${CLASSIFIED_RESULTS[@]:-}"; do
        local sev src rest
        sev="${entry%%|*}"; rest="${entry#*|}"
        rest="${rest#*|}";  src="${rest%%|*}"
        case "$src" in
            rkhunter)
                case "$sev" in
                    high)   (( rkh_h++ )) || true ;;
                    medium) (( rkh_m++ )) || true ;;
                    low)    (( rkh_l++ )) || true ;;
                esac ;;
            lynis)
                case "$sev" in
                    high)   (( lyn_h++ )) || true ;;
                    medium) (( lyn_m++ )) || true ;;
                    low)    (( lyn_l++ )) || true ;;
                esac ;;
            pacman)
                case "$sev" in
                    high)   (( pac_h++ )) || true ;;
                    medium) (( pac_m++ )) || true ;;
                    low)    (( pac_l++ )) || true ;;
                esac ;;
        esac
    done

    echo ""
    separator
    echo -e "  ${CYAN}${BOLD}SUMMARY${RESET}  ${ITALIC}${DIM}/ Riepilogo${RESET}"
    separator
    echo ""

    # Dashboard sintetica per modulo
    print_module_summary "rkhunter" "Anomalies & Rootkit" 3
    echo ""
    print_module_summary "lynis"    "Hardening & Audit  " 3
    echo ""
    print_module_summary "pacman"   "System Integrity   " 3
    echo ""
    separator

    # Verdetto visivo — gerarchia colori:
    # clean      → sfondo verde
    # attention  → giallo testo (no sfondo)
    # review     → giallo bold con simbolo ⚠ (no sfondo rosso)
    # anomaly    → sfondo rosso SOLO per anomalie confermate da più fonti
    case "$risk_level" in
        clean)
            echo -e "  ${BG_GREEN}${BOLD}  ✔  SISTEMA PULITO / SYSTEM CLEAN  ${RESET}" ;;
        attention)
            echo -e "  ${YELLOW}${BOLD}  ⚠  ATTENZIONE / ATTENTION  ${RESET}" ;;
        review)
            echo -e "  ${YELLOW}${BOLD}  ⚠  ALCUNE ANOMALIE RICHIEDONO VERIFICA / ANOMALIES REQUIRE REVIEW  ${RESET}" ;;
        relevant_anomaly)
            echo -e "  ${BG_RED}${BOLD}  ✖  ANOMALIA RILEVANTE / RELEVANT ANOMALY  ${RESET}" ;;
    esac

    echo ""
    show_traffic_light "$risk_level"
    echo ""
    echo -e "  ${WHITE}${risk_message}${RESET}"
    # Versione italiana del risk_message in corsivo
    case "$risk_level" in
        review)
            echo -e "  ${ITALIC}${DIM}  ↳ Rilevata una potenziale anomalia. Su Arch questo tipo di avviso può essere un falso positivo — verifica consigliata prima di trarre conclusioni.${RESET}" ;;
        attention)
            echo -e "  ${ITALIC}${DIM}  ↳ Presenti avvisi tecnici — verifica consigliata solo se inattesi nel contesto.${RESET}" ;;
        relevant_anomaly)
            echo -e "  ${ITALIC}${DIM}  ↳ Anomalie rilevanti rilevate — analisi manuale raccomandata.${RESET}" ;;
    esac
    echo ""

    # Messaggio orientativo — sempre dim/neutro, mai colorato in rosso
    case "$risk_level" in
        clean)
            echo -e "  ${DIM}Sistema in stato coerente — nessuna anomalia rilevante.${RESET}" ;;
        attention)
            echo -e "  ${DIM}Avvisi tecnici presenti — verifica solo se inattesi.${RESET}" ;;
        review)
            echo -e "  ${BOLD}${WHITE}Check the full report to evaluate the flagged elements.${RESET}"
            echo -e "  ${ITALIC}${DIM}  ↳ Consulta il report completo per valutare gli elementi segnalati.${RESET}"
            ;;
        relevant_anomaly)
            echo -e "  ${DIM}Analisi manuale raccomandata. Verifica le aree segnalate.${RESET}" ;;
    esac

    echo ""
    status_info "Full report:  ${ITALIC}${DIM}/ Report completo${RESET}"
    echo -e "  ${DIM}${LOG_FILE}${RESET}"
    echo ""

    {
        echo ""
        echo "=============================================="
        echo "  SUMMARY"
        echo "=============================================="
        echo "  rkhunter  — High: ${rkh_h}  Medium: ${rkh_m}  Low: ${rkh_l}"
        echo "  lynis     — High: ${lyn_h}  Medium: ${lyn_m}  Low: ${lyn_l}"
        echo "  pacman    — High: ${pac_h}  Medium: ${pac_m}  Low: ${pac_l}"
        echo "  Informational: ${INFO_COUNT}"
        echo "  Risk level: ${risk_level}"
        echo "  Verdict: ${risk_message}"
        echo "  Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "=============================================="
    } >> "$LOG_FILE"

    # Espone il risk level per la fase 2 — DEVE stare qui, dopo il calcolo
    SECCHECK_RISK_LEVEL="$risk_level"

    separator
    echo ""
}


# =============================================================================
#  FASE 2 — VERIFICA CONTESTUALE GUIDATA
# =============================================================================

# Analizza un singolo pacchetto con tutti i suoi file sospetti raggruppati
# Restituisce: 0=ok/falso_positivo 1=da_verificare 2=sospetto
contextual_check_package() {
    local pkg="$1"
    local -a files=("${@:2}")

    echo ""
    echo -e "  ${BOLD}Package:${RESET}  ${CYAN}${BOLD}${pkg}${RESET}  ${DIM}(${#files[@]} files analyzed  ${ITALIC}/ file analizzati)${RESET}"

    # Verifica integrità del pacchetto con output dettagliato
    local qkk_out
    qkk_out="$(pacman -Qkk "$pkg" 2>&1)"
    local exit_code=$?

    # Conta file totali e alterati
    local total_files=0 altered_files=0
    local summary_line
    summary_line="$(echo "$qkk_out" | grep -E "^[0-9]+ file" | tail -1)"
    if [[ -n "$summary_line" ]]; then
        total_files="$(echo "$summary_line" | grep -oP '^\d+')"
        altered_files="$(echo "$summary_line" | grep -oP '\d+ file (alterati|altered)' | grep -oP '^\d+')"
        [[ -z "$altered_files" ]] && altered_files=0
    fi

    # Righe di anomalia reale (escludi riepilogo e righe ok)
    local real_issues
    real_issues="$(echo "$qkk_out" | grep -vE         "^[0-9]+ file|all files present|tutti i file|^$|Controllo dei file|Checking files"         | grep -vE "^\s*$" | head -5)"

    local verdict=0   # 0=ok 1=da_verificare 2=sospetto

    if (( altered_files == 0 && exit_code == 0 )); then
        # Pacchetto completamente integro
        echo -e "  ${GREEN}✔${RESET}  Integrità verificata — ${total_files} file, 0 alterati"
        log "  [ctx] ${pkg}: integrity OK (${total_files} files, 0 altered)"
        verdict=0

    elif (( altered_files == 0 && exit_code != 0 )); then
        # Exit code non-zero ma 0 file alterati → discrepanze minori (permessi, timestamp)
        # Comune su Arch dopo aggiornamenti — non è una vera anomalia
        if [[ -n "$real_issues" ]]; then
            local issue_type
            issue_type="$(echo "$real_issues" | head -1 | grep -oiP 'permess|timestamp|mtime|orario|time|size|dimensione' | head -1)"
            if [[ -n "$issue_type" ]]; then
                echo -e "  ${DIM}↳  Discrepanza minore (${issue_type}) — comune dopo aggiornamenti Arch${RESET}"
                log "  [ctx] ${pkg}: minor discrepancy (${issue_type})"
                verdict=0
            else
                echo -e "  ${YELLOW}⚠${RESET}  Discrepanza rilevata — 0 file alterati, dettaglio:"
                echo -e "  ${DIM}  → $(echo "$real_issues" | head -1)${RESET}"
                log "  [ctx] ${pkg}: discrepancy, 0 altered: ${real_issues}"
                verdict=1
            fi
        else
            echo -e "  ${DIM}↳  Verifica completata — nessuna modifica critica rilevata${RESET}"
            verdict=0
        fi

    elif (( altered_files > 0 )); then
        # File realmente modificati
        echo -e "  ${YELLOW}⚠${RESET}  ${altered_files} file modificati su ${total_files} totali"
        if [[ -n "$real_issues" ]]; then
            echo -e "  ${DIM}  → $(echo "$real_issues" | head -2 | tr '
' ' ')${RESET}"
        fi
        log "  [ctx] ${pkg}: ${altered_files} altered files"
        verdict=2
    fi

    # Classificazione percorso per i file segnalati
    local has_config=0 has_binary=0
    for f in "${files[@]}"; do
        case "$f" in
            /etc/*|/usr/share/*|/var/lib/*) has_config=1 ;;
            /usr/bin/*|/usr/sbin/*|/bin/*|/sbin/*|/usr/lib/*) has_binary=1 ;;
        esac
    done

    if (( has_config == 1 && has_binary == 0 )); then
        echo -e "  ${DIM}↳  File di configurazione — modifiche spesso legittime${RESET}"
    fi

    # Verdetto contestuale
    echo ""
    echo -e "  ${CYAN}${BOLD}Assessment:${RESET}  ${ITALIC}${DIM}/ Valutazione${RESET}"
    case $verdict in
        0)
            echo -e "  ${GREEN}→ Compatibile con comportamento normale${RESET} ${DIM}(probabile falso positivo)${RESET}"
            log "  [ctx] ${pkg}: assessment = likely false positive"
            ;;
        1)
            echo -e "  ${YELLOW}→ Discrepanza minore rilevata${RESET} ${DIM}— non critica, verifica consigliata solo se inattesa${RESET}"
            log "  [ctx] ${pkg}: assessment = unconfirmed anomaly"
            ;;
        2)
            echo -e "  ${YELLOW}→ Anomalia da verificare${RESET} ${DIM}— file modificati rispetto al pacchetto installato${RESET}"
            log "  [ctx] ${pkg}: assessment = anomaly requires verification"
            ;;
    esac

    return $verdict
}

# Funzione principale fase 2
run_contextual_check() {
    local risk_level="$1"

    # Attiva solo se ci sono sospetti rilevanti
    [[ "$risk_level" == "clean" ]] && return 0
    [[ "$risk_level" == "attention" && $MEDIUM_COUNT -eq 0 ]] && return 0

    echo ""
    separator
    echo -e "  ${CYAN}${BOLD}CONTEXTUAL VERIFICATION${RESET}  ${ITALIC}${DIM}/ Verifica contestuale${RESET}"
    separator
    echo ""
    narrate \
        "Some flagged elements may warrant further investigation." \
        "Sono stati rilevati elementi che potrebbero meritare approfondimento."
    narrate \
        "This analysis checks packages, files and paths involved" \
        "Questa analisi controlla pacchetti, file e percorsi coinvolti"
    narrate \
        "to help you distinguish false positives from real anomalies." \
        "per aiutarti a distinguere falsi positivi da anomalie reali."
    echo ""

    read -rp "$(echo -e "  ${BOLD}Run contextual check? / Vuoi eseguire la verifica contestuale? [s/n]: ${RESET}")" answer
    echo ""
    if [[ ! "$answer" =~ ^[ssSyY]$ ]]; then
        echo -e "  ${DIM}Verifica saltata. Consulta il report per i dettagli.${RESET}"
        echo ""
        return 0
    fi

    log "--- CONTEXTUAL CHECK START ---"

    # Contatori contestuali — basati sui verdetti reali di contextual_check_package
    # Questi SOSTITUISCONO real_altered nel decision engine finale
    local CTX_OK_COUNT=0
    local CTX_REVIEW_COUNT=0
    local CTX_SUSPICIOUS_COUNT=0

    # Contatori medium per fonte (usati nel confidence score)
    local med_rkh=0 med_pac=0
    for entry in "${CLASSIFIED_RESULTS[@]:-}"; do
        local sev src rest
        sev="${entry%%|*}"; rest="${entry#*|}"; rest="${rest#*|}"; src="${rest%%|*}"
        [[ "$sev" != "medium" ]] && continue
        case "$src" in rkhunter) (( med_rkh++ )) || true ;; pacman) (( med_pac++ )) || true ;; esac
    done

    # ── Raccoglie sospetti rkhunter e raggruppa per pacchetto ─────────────────
    declare -A pkg_files   # pkg → lista file separati da spazio
    local rkhunter_paths=()

    if [[ -n "${TEMP_RKH:-}" && -f "$TEMP_RKH" ]]; then
        while IFS= read -r line; do
            local path
            path="$(echo "$line" | grep -oP '/[a-zA-Z0-9_/.-]+'                   | grep -E '^/(usr|bin|sbin|lib|etc|opt|boot)' | head -1)"
            [[ -n "$path" && -e "$path" ]] || continue
            # Evita duplicati
            local dup=0
            for p in "${rkhunter_paths[@]:-}"; do [[ "$p" == "$path" ]] && dup=1; done
            (( dup == 0 )) && rkhunter_paths+=("$path")
        done < <(grep -iE "warning|infected|suspicious" "$TEMP_RKH" 2>/dev/null | head -10 || true)
    fi

    # Raggruppa per pacchetto proprietario
    for path in "${rkhunter_paths[@]:-}"; do
        local owner
        owner="$(pacman -Qo "$path" 2>/dev/null | awk '{print $(NF-1)}')"
        if [[ -n "$owner" ]]; then
            pkg_files["$owner"]="${pkg_files[$owner]:-} $path"
        else
            pkg_files["__unknown__"]="${pkg_files[__unknown__]:-} $path"
        fi
    done

    # ── Analisi sospetti rkhunter per pacchetto ───────────────────────────────
    if [[ ${#rkhunter_paths[@]} -gt 0 ]]; then
        echo -e "  ${CYAN}${BOLD}rkhunter suspects analysis${RESET}  ${ITALIC}${DIM}/ Analisi sospetti rkhunter${RESET}"
        local pkg_count=0
        for pkg in "${!pkg_files[@]}"; do
            (( pkg_count >= 4 )) && break
            local files_str="${pkg_files[$pkg]}"
            read -ra files_arr <<< "$files_str"

            if [[ "$pkg" == "__unknown__" ]]; then
                echo ""
                echo -e "  ${YELLOW}⚠${RESET}  File senza pacchetto proprietario / Files with no owner:"
                for f in "${files_arr[@]}"; do
                    [[ -n "$f" ]] && echo -e "  ${DIM}  → ${f}${RESET}"
                done
                log "  [ctx] unowned files: ${files_str}"
                # File senza proprietario → sospetto
                (( CTX_SUSPICIOUS_COUNT++ )) || true
            else
                contextual_check_package "$pkg" "${files_arr[@]}"
                case $? in
                    0) (( CTX_OK_COUNT++      )) || true ;;
                    1) (( CTX_REVIEW_COUNT++  )) || true ;;
                    2) (( CTX_SUSPICIOUS_COUNT++ )) || true ;;
                esac
            fi
            (( pkg_count++ )) || true
        done

        if (( ${#pkg_files[@]} == 0 )); then
            narrate                 "Nessun percorso specifico estratto dall output rkhunter."                 "No specific paths extracted from rkhunter output."
            narrate                 "Su Arch i warning rkhunter senza file specifici sono spesso rumore di fondo."                 "On Arch, rkhunter warnings without specific files are often background noise."
        fi
    fi

    # ── Analisi anomalie pacman -Qkk ─────────────────────────────────────────
    if [[ -n "${TEMP_PAC:-}" && -f "$TEMP_PAC" ]]; then
        # Filtra solo righe con anomalie reali (non "X file totali, 0 alterati")
        local pac_real_issues
        pac_real_issues="$(grep -vE             "all files present|tutti i file|^[a-z0-9_-]+: [0-9]+ file totali, 0 file|^\s*$"             "$TEMP_PAC" 2>/dev/null | head -6 || true)"

        if [[ -n "$pac_real_issues" ]]; then
            echo ""
            echo -e "  ${CYAN}${BOLD}Package discrepancies detected${RESET}  ${ITALIC}${DIM}/ Discrepanze rilevate${RESET}"
            echo -e "  ${DIM}Each item will be evaluated contextually — a discrepancy is not necessarily an anomaly.${RESET}"
            echo -e "  ${ITALIC}${DIM}  ↳ Ogni voce verrà valutata contestualmente — una discrepanza non è necessariamente un'anomalia.${RESET}"

            declare -A pac_pkgs
            while IFS= read -r issue_line; do
                [[ -z "${issue_line// }" ]] && continue
                local ipath
                ipath="$(echo "$issue_line" | grep -oP '/[a-zA-Z0-9_/.-]+' | head -1)"
                if [[ -n "$ipath" && -e "$ipath" ]]; then
                    local iowner
                    iowner="$(pacman -Qo "$ipath" 2>/dev/null | awk '{print $(NF-1)}')"
                    [[ -n "$iowner" ]] && pac_pkgs["$iowner"]="${pac_pkgs[$iowner]:-} $ipath"                                       || pac_pkgs["__unknown__"]="${pac_pkgs[__unknown__]:-} $ipath"
                else
                    # Riga senza percorso — mostra sinteticamente
                    echo -e "  ${DIM}→ ${issue_line}${RESET}"
                    case "${issue_line,,}" in
                        *"missing"*) echo -e "  ${DIM}  File mancante — verificare se rimosso intenzionalmente${RESET}" ;;
                        *"size"*|*"md5"*|*"sha256"*) echo -e "  ${DIM}  Hash/dimensione modificato — potrebbe essere file di config${RESET}" ;;
                    esac
                fi
            done <<< "$pac_real_issues"

            local p_count=0
            for pkg in "${!pac_pkgs[@]}"; do
                (( p_count >= 3 )) && break
                read -ra farr <<< "${pac_pkgs[$pkg]}"
                if [[ "$pkg" == "__unknown__" ]]; then
                    echo -e "\n  ${YELLOW}⚠${RESET}  File senza proprietario: ${pac_pkgs[$pkg]}"
                    (( CTX_SUSPICIOUS_COUNT++ )) || true
                else
                    contextual_check_package "$pkg" "${farr[@]}"
                    case $? in
                        0) (( CTX_OK_COUNT++       )) || true ;;
                        1) (( CTX_REVIEW_COUNT++   )) || true ;;
                        2) (( CTX_SUSPICIOUS_COUNT++ )) || true ;;
                    esac
                fi
                (( p_count++ )) || true
            done
        fi
    fi

    # ── Correlazione lynis ────────────────────────────────────────────────────
    local lyn_count
    lyn_count="$(count_results_for "lynis")"
    echo ""
    if (( lyn_count == 0 )); then
        echo -e "  ${GREEN}✔${RESET}  ${DIM}Lynis non ha rilevato anomalie correlate — riduce la probabilità di compromissione reale.${RESET}"
        log "  [ctx] lynis: clean — reduces compromise probability"
    else
        echo -e "  ${YELLOW}⚠${RESET}  ${DIM}Lynis ha rilevato ${lyn_count} elemento/i — valutare insieme agli altri sospetti.${RESET}"
        log "  [ctx] lynis: ${lyn_count} correlated findings"
    fi

    # ── OVERALL ASSESSMENT — basato SOLO sui contatori contestuali ─────────────
    # Logica a stati pulita: CTX_OK / CTX_REVIEW / CTX_SUSPICIOUS + lynis.
    # real_altered e HIGH_COUNT non determinano il verdetto finale.
    echo ""
    separator
    echo -e "  ${CYAN}${BOLD}Overall assessment${RESET}  ${ITALIC}${DIM}/ Valutazione complessiva${RESET}"
    separator
    echo ""

    local score=0
    local prob_label="" prob_label_it="" prob_color=""
    local recommendation_en="" recommendation_it=""

    if (( CTX_SUSPICIOUS_COUNT > 0 && lyn_count > 0 )); then
        score=75; prob_label="High"; prob_label_it="Alta"; prob_color="$RED"
        recommendation_en="Act — anomalies corroborated by contextual checks and other modules."
        recommendation_it="Intervenire — anomalie corroborate dalla verifica contestuale e da altri moduli."

    elif (( CTX_SUSPICIOUS_COUNT > 0 )); then
        score=45; prob_label="Medium"; prob_label_it="Media"; prob_color="$YELLOW"
        recommendation_en="Review — suspicious elements found, but without strong cross-confirmation."
        recommendation_it="Verificare — elementi sospetti rilevati, senza conferma incrociata forte."

    elif (( CTX_REVIEW_COUNT > 0 && lyn_count > 0 )); then
        score=35; prob_label="Medium"; prob_label_it="Media"; prob_color="$YELLOW"
        recommendation_en="Review — some elements merit attention."
        recommendation_it="Verificare — alcuni elementi meritano attenzione."

    elif (( CTX_REVIEW_COUNT > 0 )); then
        score=20; prob_label="Low"; prob_label_it="Bassa"; prob_color="$GREEN"
        recommendation_en="Monitor — minor inconsistencies detected, likely non-critical."
        recommendation_it="Monitorare — rilevate discrepanze minori, probabilmente non critiche."

    else
        score=10; prob_label="Low"; prob_label_it="Bassa"; prob_color="$GREEN"
        recommendation_en="No urgent action — findings compatible with normal system behavior."
        recommendation_it="Nessuna azione urgente — elementi compatibili con il normale comportamento del sistema."
    fi

    local bar="" filled=$(( score / 10 ))
    for (( i=0; i<10; i++ )); do
        (( i < filled )) && bar+="${prob_color}█${RESET}" || bar+="${DIM}░${RESET}"
    done

    echo -e "  Confidence score:  ${bar}  ${prob_color}${BOLD}${score}/100${RESET}"
    echo -e "  ${DIM}(${CTX_OK_COUNT} ok, ${CTX_REVIEW_COUNT} review, ${CTX_SUSPICIOUS_COUNT} suspicious, lynis findings: ${lyn_count})${RESET}"
    echo ""
    echo -e "  ${BOLD}${WHITE}Probability of real compromise:${RESET} ${prob_color}${BOLD}${prob_label}${RESET}"
    echo -e "  ${ITALIC}${DIM}  ↳ Probabilità di compromissione reale: ${prob_label_it}${RESET}"
    echo ""
    echo -e "  ${BOLD}${WHITE}Recommendation:${RESET} ${WHITE}${recommendation_en}${RESET}"
    echo -e "  ${ITALIC}${DIM}  ↳ Raccomandazione: ${recommendation_it}${RESET}"
    echo ""

    if (( lyn_count == 0 && CTX_SUSPICIOUS_COUNT == 0 )); then
        echo -e "  ${DIM}Note: on Arch Linux, isolated rkhunter warnings and minor package discrepancies${RESET}"
        echo -e "  ${DIM}are frequently compatible with false positives or normal post-update changes.${RESET}"
        echo -e "  ${ITALIC}${DIM}  ↳ Su Arch Linux, avvisi rkhunter isolati e discrepanze minori dei pacchetti${RESET}"
        echo -e "  ${ITALIC}${DIM}    sono spesso compatibili con falsi positivi o normali modifiche post-aggiornamento.${RESET}"
    fi

    log "  [ctx] CTX_OK=${CTX_OK_COUNT} CTX_REVIEW=${CTX_REVIEW_COUNT} CTX_SUSPICIOUS=${CTX_SUSPICIOUS_COUNT} lynis=${lyn_count} score=${score}"
    log "--- CONTEXTUAL CHECK END ---"
    echo ""
    separator
    echo ""
}


# =============================================================================
#  LEGGI ULTIMO REPORT
# =============================================================================
read_last_report() {
    separator
    narrate \
        "Looking for the latest available report..." \
        "Cerco l'ultimo report disponibile..."
    echo ""

    local last
    last=$(ls -t "${LOG_DIR}"/seccheck_*.log 2>/dev/null | head -1 || true)

    if [[ -z "$last" ]]; then
        status_warn "Nessun report trovato in ${LOG_DIR} / No reports found in ${LOG_DIR}"
    else
        status_info "Report: ${last}"
        echo ""
        separator
        cat "$last"
        separator
    fi
    echo ""
}

# =============================================================================
#  RESET SESSION — chiamato prima di ogni scansione
# =============================================================================
reset_session() {
    HIGH_COUNT=0; MEDIUM_COUNT=0; LOW_COUNT=0; INFO_COUNT=0
    HAS_ROOTKIT_SIG=0; HAS_KERNEL=0; HAS_HIDDEN=0
    HAS_NETWORK=0; HAS_STARTUP=0; HAS_INTEGRITY=0; HAS_HARDENING=0
    CLASSIFIED_RESULTS=()
    SECCHECK_RISK_LEVEL="clean"
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    LOG_FILE="${LOG_DIR}/seccheck_${TIMESTAMP}.log"
    setup_log
}

# =============================================================================
#  MENU
# =============================================================================
show_menu() {
    echo ""
    separator
    echo -e "  ${CYAN}${BOLD}MAIN MENU${RESET}  ${ITALIC}${DIM}/ Menu principale${RESET}"
    separator
    echo -e "  ${ORANGE}[1]${RESET}  ${BOLD}Full scan${RESET}  ${ITALIC}${DIM}/ Scansione completa${RESET}"
    echo -e "       ${DIM}rkhunter + lynis + pacman integrity${RESET}"
    echo -e "  ${ORANGE}[2]${RESET}  ${BOLD}rkhunter only${RESET}  ${ITALIC}${DIM}/ Solo rkhunter${RESET}"
    echo -e "  ${ORANGE}[3]${RESET}  ${BOLD}lynis only${RESET}  ${ITALIC}${DIM}/ Solo lynis${RESET}"
    echo -e "  ${ORANGE}[4]${RESET}  ${BOLD}Package integrity${RESET}  ${ITALIC}${DIM}/ Integrità pacchetti (pacman -Qkk)${RESET}"
    echo -e "  ${ORANGE}[5]${RESET}  ${BOLD}Read last report${RESET}  ${ITALIC}${DIM}/ Leggi ultimo report${RESET}"
    echo -e "  ${ORANGE}[0]${RESET}  ${BOLD}Exit${RESET}  ${ITALIC}${DIM}/ Esci${RESET}"
    separator
    echo ""
    read -rp "$(echo -e "  ${BOLD}Choice / Scelta: ${RESET}")" MENU_CHOICE
    echo ""
}

# =============================================================================
#  MAIN
# =============================================================================
main() {
    show_banner
    check_root "$@"
    check_distro
    check_deps

    while true; do
        show_menu
        case "$MENU_CHOICE" in
            1)
                reset_session
                run_rkhunter
                run_lynis
                run_pacman_integrity
                show_summary
                run_contextual_check "$SECCHECK_RISK_LEVEL"
                ;;
            2)
                reset_session
                run_rkhunter
                show_summary
                run_contextual_check "$SECCHECK_RISK_LEVEL"
                ;;
            3)
                reset_session
                run_lynis
                show_summary
                run_contextual_check "$SECCHECK_RISK_LEVEL"
                ;;
            4)
                reset_session
                run_pacman_integrity
                show_summary
                run_contextual_check "$SECCHECK_RISK_LEVEL"
                ;;
            5)
                read_last_report
                ;;
            0)
                echo ""
                narrate \
                    "Exiting SecCheck. Keep your system safe." \
                    "Uscita da SecCheck. Tieni il tuo sistema sotto controllo."
                echo ""
                exit 0
                ;;
            *)
                status_warn "Scelta non valida / Invalid choice"
                ;;
        esac
    done
}

# Guard: esegue main solo se lanciato direttamente (non con source)
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi

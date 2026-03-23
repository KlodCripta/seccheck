#!/usr/bin/env bash
# =============================================================================
#  seccheck_test.sh — Parser Test Harness
#  SecCheck v1.0.0 | KlodCripta
#  Uso: bash seccheck_test.sh [FILTRO]
#  Es.: bash seccheck_test.sh RK   (solo casi rkhunter)
#       bash seccheck_test.sh LY   (solo casi lynis)
#  Requisiti: seccheck.sh e seccheck_test_cases.txt nella stessa cartella
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KLODSEC="${SCRIPT_DIR}/seccheck.sh"
CASES_FILE="${SCRIPT_DIR}/seccheck_test_cases.txt"
FILTER="${1:-}"

[[ ! -f "$KLODSEC" ]]    && echo "ERRORE: seccheck.sh non trovato"            && exit 1
[[ ! -f "$CASES_FILE" ]] && echo "ERRORE: seccheck_test_cases.txt non trovato" && exit 1

LOG_DIR="/tmp/seccheck_test_$$"
LOG_FILE="/tmp/seccheck_test_$$.log"
mkdir -p "$LOG_DIR" && : > "$LOG_FILE"

source "$KLODSEC"

R="\033[1;31m"; G="\033[1;32m"; Y="\033[1;33m"
C="\033[1;36m"; W="\033[1;37m"; D="\033[2m"; B="\033[1m"; RST="\033[0m"

TOTAL=0; PASSED=0; FAILED=0
declare -a FAILURES=()

run_case() {
    local id="$1" fn="$2" input="$3" exp_sev="$4" exp_cat="$5"
    [[ -n "$FILTER" && "$id" != "${FILTER}"* ]] && return
    (( TOTAL++ )) || true

    local result sev cat rest
    case "$fn" in
        rkhunter) result="$(classify_rkhunter_line "$input")" ;;
        lynis)    result="$(classify_lynis_line    "$input")" ;;
        pacman)   result="$(classify_pacman_line   "$input")" ;;
        *) echo -e "${Y}[SKIP]${RST} ${id} — funzione: ${fn}"; return ;;
    esac

    sev="${result%%|*}"; rest="${result#*|}"; cat="${rest%%|*}"
    [[ "$fn" == "rkhunter" ]] && sev="$(adjust_severity_with_context "$sev" "$cat" "$input")"

    if [[ "$sev" == "$exp_sev" && "$cat" == "$exp_cat" ]]; then
        (( PASSED++ )) || true
        echo -e "${G}[PASS]${RST} ${B}${id}${RST}"
    else
        (( FAILED++ )) || true; FAILURES+=("$id")
        echo -e "${R}[FAIL]${RST} ${B}${id}${RST}"
        echo -e "  ${D}input   :${RST} ${input}"
        echo -e "  ${D}atteso  :${RST} ${Y}${exp_sev}${RST} | ${C}${exp_cat}${RST}"
        echo -e "  ${D}ottenuto:${RST} ${R}${sev}${RST} | ${R}${cat}${RST}"
    fi
}

echo ""
echo -e "${C}${B}  SecCheck — Parser Test Harness${RST}"
echo -e "${D}  ──────────────────────────────────────────────────────────────${RST}"
[[ -n "$FILTER" ]] && echo -e "  Filtro: ${FILTER}" || true
echo ""

current_group=""
while IFS='|' read -r id fn input exp_sev exp_cat; do
    id="${id## }"; id="${id%% }"
    [[ -z "$id" || "$id" == \#* ]] && continue
    group="${id:0:2}"
    if [[ "$group" != "$current_group" ]]; then
        current_group="$group"; echo ""
        case "$group" in
            RK) echo -e "  ${W}${B}── rkhunter: principali ──${RST}" ;;
            RB) echo -e "  ${W}${B}── rkhunter: borderline ──${RST}" ;;
            LY) echo -e "  ${W}${B}── lynis ──${RST}" ;;
            PA) echo -e "  ${W}${B}── pacman integrity ──${RST}" ;;
            *)  echo -e "  ${W}${B}── ${group} ──${RST}" ;;
        esac; echo ""
    fi
    run_case "$id" "$fn" "$input" "$exp_sev" "$exp_cat"
done < "$CASES_FILE"

echo ""
echo -e "${D}  ──────────────────────────────────────────────────────────────${RST}"
echo -e "  ${B}RISULTATI${RST}   Totale: ${W}${TOTAL}${RST}  |  ${G}PASS: ${PASSED}${RST}  |  ${R}FAIL: ${FAILED}${RST}"
echo ""

if (( FAILED > 0 )); then
    echo -e "  ${R}${B}Falliti:${RST}"
    for f in "${FAILURES[@]}"; do echo -e "    ${R}→ ${f}${RST}"; done
    echo -e "\n  Suggerimento: bash seccheck_test.sh RK"
else
    echo -e "  ${G}${B}  ✔  Tutti i casi superati.${RST}"
fi
echo ""

rm -rf "$LOG_DIR" "$LOG_FILE" 2>/dev/null || true
(( FAILED == 0 ))

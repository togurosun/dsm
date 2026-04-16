#!/bin/bash
set -euo pipefail

BASE_DIR="${BASE_DIR:-/volume1/FIRMA/PION}"
DOMAIN="${DOMAIN:-FIRMA}"
DRY_RUN="${DRY_RUN:-1}"
RESET_ACL="${RESET_ACL:-0}"
BREAK_INHERIT="${BREAK_INHERIT:-0}"
CREATE_MISSING="${CREATE_MISSING:-0}"

ADMINS_GROUPS=(
  "${DOMAIN}\\Administratorzy domeny"
  "${DOMAIN}\\Administratorzy przedsiębiorstwa"
  "administrators"
)

PERM_FULL="rwxpdDaARWcCo"
PERM_RW="rwxpd-aARWc--"
PERM_RO="r-x---a-R-c--"
PERM_TRAVERSE="--x----------"
INHERIT_DEFAULT="fd--"
INHERIT_TRAVERSE="---n"

usage() {
  cat <<USAGE
Użycie:
  BASE_DIR=/volume1/FIRMA/PION DOMAIN=FIRMA DRY_RUN=1 ./dsm_acl_auto_groups.sh

Zmienne:
  BASE_DIR        katalog bazowy do skanowania
  DOMAIN          prefiks domeny AD
  DRY_RUN         1 = tylko pokaż komendy, 0 = wykonaj
  RESET_ACL       1 = usuń istniejące ACL na katalogu docelowym przed nadaniem
  BREAK_INHERIT   1 = usuń bit is_inherit na katalogu docelowym
  CREATE_MISSING  1 = utwórz brakujące foldery wskazane w argumentach

Opcjonalnie możesz podać listę ścieżek jako argumenty. Bez argumentów skrypt skanuje BASE_DIR/*
USAGE
}

log() {
  echo "[$(date '+%F %T')] $*"
}

run_cmd() {
  if [[ "$DRY_RUN" == "1" ]]; then
    printf '[DRY-RUN]'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

group_exists() {
  local grp="$1"
  getent group "$grp" >/dev/null 2>&1 && return 0
  if command -v wbinfo >/dev/null 2>&1; then
    wbinfo --group-info="$grp" >/dev/null 2>&1 && return 0
  fi
  return 1
}

extract_token() {
  local folder_name="$1"
  echo "$folder_name" | grep -oE 'PRJ_[0-9]{4}[_-][0-9]{2}' | head -n1 || true
}

normalize_token_variants() {
  local token="$1"
  local a b
  a="${token//-/_}"
  b="${token//_/-}"
  printf '%s\n%s\n' "$a" "$b" | awk '!seen[$0]++'
}

find_first_existing_group() {
  local suffix="$1"
  shift
  local token candidate
  for token in "$@"; do
    candidate="${DOMAIN}\\GRP-S-${token}-${suffix}"
    if group_exists "$candidate"; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

prepare_folder() {
  local path="$1"
  if [[ ! -d "$path" ]]; then
    if [[ "$CREATE_MISSING" == "1" ]]; then
      run_cmd mkdir -p "$path"
    else
      log "Pominięto brakujący katalog: $path"
      return 1
    fi
  fi
  run_cmd synoacltool -set-archive "$path" has_ACL
  run_cmd synoacltool -set-archive "$path" is_support_ACL
  if [[ "$RESET_ACL" == "1" ]]; then
    run_cmd synoacltool -del "$path"
  fi
  if [[ "$BREAK_INHERIT" == "1" ]]; then
    run_cmd synoacltool -del-archive "$path" is_inherit
  fi
  return 0
}

grant_admins() {
  local path="$1"
  local g
  for g in "${ADMINS_GROUPS[@]}"; do
    if group_exists "$g" || [[ "$g" == "administrators" ]]; then
      run_cmd synoacltool -add "$path" "group:${g}:allow:${PERM_FULL}:${INHERIT_DEFAULT}"
    fi
  done
}

grant_traverse_parents() {
  local target="$1"
  local grp="$2"
  local current
  current="$(dirname "$target")"
  while [[ "$current" != "/" && "$current" != "/volume1" ]]; do
    run_cmd synoacltool -add "$current" "group:${grp}:allow:${PERM_TRAVERSE}:${INHERIT_TRAVERSE}"
    current="$(dirname "$current")"
  done
}

set_acl_for_path() {
  local path="$1"
  local folder_name token rw_group ro_group
  folder_name="$(basename "$path")"
  token="$(extract_token "$folder_name")"

  if [[ -z "$token" ]]; then
    log "Pominięto $path - brak wzorca PRJ_YYYY_MM lub PRJ_YYYY-MM"
    return 0
  fi

  mapfile -t variants < <(normalize_token_variants "$token")

  rw_group="$(find_first_existing_group T "${variants[@]}" || true)"
  ro_group="$(find_first_existing_group S "${variants[@]}" || true)"

  log "Folder: $folder_name"
  log "Token: $token"
  [[ -n "$rw_group" ]] && log "RW: $rw_group" || log "RW: brak dopasowanej grupy"
  [[ -n "$ro_group" ]] && log "RO: $ro_group" || log "RO: brak dopasowanej grupy"

  prepare_folder "$path" || return 0
  grant_admins "$path"

  if [[ -n "$rw_group" ]]; then
    run_cmd synoacltool -add "$path" "group:${rw_group}:allow:${PERM_RW}:${INHERIT_DEFAULT}"
    grant_traverse_parents "$path" "$rw_group"
  fi

  if [[ -n "$ro_group" ]]; then
    run_cmd synoacltool -add "$path" "group:${ro_group}:allow:${PERM_RO}:${INHERIT_DEFAULT}"
    grant_traverse_parents "$path" "$ro_group"
  fi

  run_cmd synoacltool -enforce-inherit "$path"
  run_cmd synoacltool -get "$path"
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  if [[ $# -gt 0 ]]; then
    for p in "$@"; do
      set_acl_for_path "$p"
    done
  else
    find "$BASE_DIR" -mindepth 1 -maxdepth 1 -type d | while read -r dir; do
      set_acl_for_path "$dir"
    done
  fi
}

main "$@"

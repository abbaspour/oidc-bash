#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2026-11-16
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/main/LICENSE)
#
# Auth0 Embedded Authorize (/e/authorize). Auth0 profile of OAuth 2.0 for First-Party Applications
# https://datatracker.ietf.org/doc/draft-ietf-oauth-first-party-apps/
#
# Drives the authorization challenge loop (identify, 1st factor, MFA) until an authorization_code
# is returned, which is exchanged at /oauth/token with code-exchange.sh
##########################################################################################

set -ueo pipefail

DIR="${BASH_SOURCE[0]%/*}"
[ "$DIR" = "${BASH_SOURCE[0]}" ] && DIR="."
readonly DIR

command -v curl >/dev/null || { echo >&2 "error: curl not found";  exit 3; }
command -v jq >/dev/null || { echo >&2 "error: jq not found";  exit 3; }

# every action the beta marks as available
declare -a default_capabilities=(
  'action:identify:email:v1'
  'action:challenge:email:v1'
  'action:challenge:phone:v1'
  'action:verify:otp:v1'
  'action:verify:recovery-code:v1'
  'action:confirm:recovery-code:v1'
)

function usage() {
  cat <<END >&2
USAGE: $0 [-e env] [-t tenant] [-d domain] [-c client_id] [-x client_secret] [-r connection] [-s scope] [-C capability]... [-E key=value]... [-H email] [-T] [-v|-h]
       $0 [-e env] [-t tenant] [-d domain] [-c client_id] -S auth_session -A action [-f key=value]...
        -e file        # .env file location (default cwd)
        -t tenant      # tenant@region shorthand (Auth0-style, appends .auth0.com)
        -d domain      # Auth0 domain
        -c client_id   # OAuth2/OIDC client ID
        -x secret      # client secret (optional for public clients)
        -r connection  # database connection name
        -s scope       # comma separated list of scopes (default is "${SCOPE}")
        -C capability  # action the client can display; repeatable (default all available beta actions)
        -E key=value   # extra parameter for the start request; repeatable (e.g. audience=https://api/)
        -H email       # login hint; default value for the email prompt
        -U endpoint    # endpoint path (default is '${endpoint_path}')
        -S session     # single step: auth_session from the previous response
        -A action      # single step: action to send. use 'start' (without -S) to only send the start request
        -f key=value   # single step: action field; repeatable (e.g. otp=123456, index=0)
        -T             # exchange the authorization_code for tokens with code-exchange.sh
        -D             # disable OIDC discovery in code-exchange.sh (with -T)
        -W             # force-renew discovery cache in code-exchange.sh (with -T)
        -h|?           # usage
        -v             # verbose

eg,
     $0 -t amin01@au -c aIioQEeY7nJdX78vcQWDBcAqTABgKnZl -x XXXXXX -r Username-Password-Authentication -T
     $0 -t amin01@au -c aIioQEeY7nJdX78vcQWDBcAqTABgKnZl -x XXXXXX -r Username-Password-Authentication -A start
     $0 -t amin01@au -c aIioQEeY7nJdX78vcQWDBcAqTABgKnZl -S "\${AUTH_SESSION}" -A action:identify:email:v1 -f email=jane@example.com
     $0 -t amin01@au -c aIioQEeY7nJdX78vcQWDBcAqTABgKnZl -S "\${AUTH_SESSION}" -A action:verify:otp:v1 -f type=oob -f otp=123456
END
  exit "$1"
}

declare DOMAIN=''
declare CLIENT_ID=''
declare CLIENT_SECRET=''
declare CONNECTION=''
declare SCOPE='openid profile'
declare endpoint_path='e/authorize'
declare login_hint=''
declare auth_session=''
declare step_action=''
declare -a capabilities=()
declare -a extra_params=()
declare -a step_fields=()
declare opt_exchange=0
declare opt_disable_discovery=0
declare opt_force_refresh=0
declare opt_verbose=0

[[ -f "${DIR}/.env" ]] && . "${DIR}/.env"

while getopts "e:t:d:c:x:r:s:C:E:H:U:S:A:f:TDWhv?" opt; do
  case ${opt} in
  e) source "${OPTARG}" ;;
  t) DOMAIN=$(echo "${OPTARG}.auth0.com" | tr '@' '.') ;;
  d) DOMAIN=${OPTARG} ;;
  c) CLIENT_ID=${OPTARG} ;;
  x) CLIENT_SECRET=${OPTARG} ;;
  r) CONNECTION=${OPTARG} ;;
  s) SCOPE=$(echo "${OPTARG}" | tr ',' ' ') ;;
  C) capabilities+=("${OPTARG}") ;;
  E) extra_params+=("${OPTARG}") ;;
  H) login_hint=${OPTARG} ;;
  U) endpoint_path=${OPTARG} ;;
  S) auth_session=${OPTARG} ;;
  A) step_action=${OPTARG} ;;
  f) step_fields+=("${OPTARG}") ;;
  T) opt_exchange=1 ;;
  D) opt_disable_discovery=1 ;;
  W) opt_force_refresh=1 ;;
  v) opt_verbose=1 ;; #set -x;;
  h | ?) usage 0 ;;
  *) usage 1 ;;
  esac
done

[[ -z "${DOMAIN}" ]] && { echo >&2 "ERROR: DOMAIN undefined"; usage 1; }
[[ -z "${CLIENT_ID}" ]] && { echo >&2 "ERROR: CLIENT_ID undefined"; usage 1; }
[[ -n "${auth_session}" && -z "${step_action}" ]] && { echo >&2 "ERROR: -S requires -A"; usage 1; }
[[ -z "${auth_session}" && -n "${step_action}" && "${step_action}" != 'start' ]] && { echo >&2 "ERROR: -A ${step_action} requires -S (use -A start to begin)"; usage 1; }
[[ -z "${auth_session}" && -z "${CONNECTION}" ]] && { echo >&2 "ERROR: connection (-r) undefined"; usage 1; }
[[ ${#step_fields[@]} -gt 0 && -z "${auth_session}" ]] && { echo >&2 "ERROR: -f requires -S"; usage 1; }
[[ ${opt_exchange} -eq 1 && -n "${step_action}" ]] && { echo >&2 "ERROR: -T is for interactive mode. run code-exchange.sh -u '' after the last step"; usage 1; }

for kv in "${extra_params[@]}" "${step_fields[@]}"; do
  [[ "${kv}" == *=* ]] || { echo >&2 "ERROR: '${kv}' is not key=value"; usage 1; }
done

[[ ${#capabilities[@]} -eq 0 ]] && capabilities=("${default_capabilities[@]}")

[[ ${DOMAIN} =~ ^http ]] || DOMAIN="https://${DOMAIN}"
DOMAIN="${DOMAIN%/}"
readonly DOMAIN

readonly endpoint="${DOMAIN}/${endpoint_path}"

# response holds auth_session (a secret); keep it off disk once done
response_file=$(mktemp)
readonly response_file
trap 'rm -f "${response_file}"' EXIT

declare http_status=''
declare response=''
declare error=''
declare step=''       # newest insufficient_authorization response; source of next[] and new_code
declare selected=''   # entry of next[] being answered
declare fields='{}'   # action specific fields for the next request

# key=value list to JSON object. index is the only numeric field; everything else stays a string
# so OTPs with leading zeros (012345) survive
function kv_json() {
  jq -n '[$ARGS.positional[] | capture("^(?<k>[^=]+)=(?<v>.*)$")
          | {(.k): (if .k == "index" then (.v | tonumber) else .v end)}] | add // {}' --args "$@"
}

function start_body() {
  local extra
  extra=$(kv_json "${extra_params[@]}")
  jq -n \
    --arg client_id "${CLIENT_ID}" \
    --arg client_secret "${CLIENT_SECRET}" \
    --arg connection "${CONNECTION}" \
    --arg scope "${SCOPE}" \
    --argjson extra "${extra}" \
    '{
      client_id: $client_id,
      client_secret: $client_secret,
      connection: $connection,
      capabilities: $ARGS.positional,
      scope: $scope
    } | with_entries(select(.value != "")) + $extra' \
    --args "${capabilities[@]}"
}

# client_id is required on every continuation, auth_session must be the newest one
function continue_body() {
  jq -n \
    --arg client_id "${CLIENT_ID}" \
    --arg auth_session "${auth_session}" \
    --arg action "$1" \
    --argjson fields "$2" \
    '{client_id: $client_id, auth_session: $auth_session, action: $action} + $fields'
}

function post() {
  if [[ ${opt_verbose} -eq 1 ]]; then
    echo >&2 "> POST ${endpoint}"
    jq . <<< "$1" >&2
  fi

  http_status=$(curl -s -o "${response_file}" -w '%{http_code}' --request POST \
    --url "${endpoint}" \
    --header 'content-type: application/json' \
    --data "$1")
  response=$(cat "${response_file}")
  error=$(jq -r '.error // empty' <<< "${response}" 2>/dev/null || true)

  if [[ ${opt_verbose} -eq 1 ]]; then
    echo >&2 "< HTTP ${http_status}"
    jq . <<< "${response}" >&2 2>/dev/null || echo >&2 "${response}"
  fi
}

function fail() {
  local hint=''
  case "${http_status}:${error}" in
  403:access_denied) hint='flow cannot continue (too many attempts, no eligible factor, or consent_required). start again' ;;
  403:unauthorized_client) hint='Embedded Authorize is not enabled for this application' ;;
  401:*) hint='client is unknown or not valid for this tenant. check client_id and client_secret' ;;
  400:invalid_grant) hint='auth_session expired, is not valid, or does not match client_id. start again' ;;
  400:invalid_request) hint='auth_session malformed or action not in the current next list' ;;
  404:*) hint='Embedded Authorize is not enabled for this tenant' ;;
  429:*) hint='too many requests. wait before retrying' ;;
  501:*) hint='action is not implemented in this beta. do not declare it in capabilities' ;;
  esac

  [[ ${opt_verbose} -eq 1 ]] || { jq . <<< "${response}" >&2 2>/dev/null || echo >&2 "${response}"; }
  echo >&2 "ERROR: HTTP ${http_status} ${error}${hint:+ - ${hint}}"
  exit 1
}

# reads from the terminal so stdout stays clean JSON. called as $(prompt ...), where set -e does not
# apply, so a failed read must exit explicitly; otherwise an empty answer is sent and retried forever
function prompt() {
  local value=''
  local label="> $1: "
  [[ -n "${2:-}" ]] && label="> $1 [$2]: "
  read -r -p "${label}" value < /dev/tty || { echo >&2; echo >&2 "ERROR: no terminal to read '$1' (use -S/-A/-f single step mode)"; exit 1; }
  echo "${value:-${2:-}}"
}

# one line summary of a next[] entry: action, type/channel and masked identifier
readonly describe='"\(.action)\(if .type then " type=\(.type)" else "" end)\(if .channel then " channel=\(.channel)" else "" end)\(if .identifier then " \(.identifier)" else "" end)"'

function choose_next() {
  local -i count
  local choice=''
  count=$(jq '.next | length' <<< "${step}")
  [[ ${count} -eq 0 ]] && { echo >&2 "ERROR: empty next list"; exit 1; }

  if [[ ${count} -eq 1 ]]; then
    selected=$(jq -c '.next[0]' <<< "${step}")
    echo >&2 "next: $(jq -r "${describe}" <<< "${selected}")"
    return
  fi

  echo >&2 "next:"
  jq -r ".next | to_entries[] | \"  [\(.key + 1)] \" + (.value | ${describe})" <<< "${step}" >&2
  while true; do
    choice=$(prompt "choose [1-${count}]")
    [[ ${choice} =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= count )) && break
    echo >&2 "invalid choice: ${choice}"
  done
  selected=$(jq -c --argjson i "$((choice - 1))" '.next[$i]' <<< "${step}")
}

# collect from the user the fields the selected action needs
function answer() {
  local action index type channel value
  action=$(jq -r '.action' <<< "${selected}")
  index=$(jq -r '.index // 0' <<< "${selected}")

  case "${action}" in
  action:identify:email:v1)
    value=$(prompt 'email' "${login_hint}")
    fields=$(jq -n --arg email "${value}" '{email: $email}') ;;
  action:challenge:email:v1)
    fields=$(jq -n --argjson index "${index}" '{index: $index}') ;;
  action:challenge:phone:v1)
    value=$(prompt 'delivery_method (text|voice)' 'text')
    fields=$(jq -n --argjson index "${index}" --arg delivery_method "${value}" '{index: $index, delivery_method: $delivery_method}') ;;
  action:verify:otp:v1)
    # oob for email/SMS/voice codes (entry has a channel), totp for authenticator apps
    type=$(jq -r '.type // (if .channel then "oob" else "totp" end)' <<< "${selected}")
    channel=$(jq -r '.channel // empty' <<< "${selected}")
    value=$(prompt "otp (${type}${channel:+, ${channel}})")
    fields=$(jq -n --arg type "${type}" --arg otp "${value}" '{type: $type, otp: $otp}') ;;
  action:verify:recovery-code:v1)
    value=$(prompt 'recovery code')
    fields=$(jq -n --arg code "${value}" '{code: $code}') ;;
  action:confirm:recovery-code:v1)
    # the accepted recovery code is used up; Auth0 returns its replacement in new_code
    echo >&2 "new recovery code: $(jq -r '.new_code // "<not returned>"' <<< "${step}")"
    prompt 'save it, then press Enter to confirm' >/dev/null
    fields='{}' ;;
  *)
    echo >&2 "ERROR: action not supported by this script: $(jq -r "${describe}" <<< "${selected}")"
    exit 1 ;;
  esac
}

declare body=''

## single step mode: one request, raw response to stdout
if [[ -n "${step_action}" ]]; then
  if [[ -z "${auth_session}" ]]; then
    body=$(start_body)
  else
    fields=$(kv_json "${step_fields[@]}")
    body=$(continue_body "${step_action}" "${fields}")
  fi
  post "${body}"
  echo >&2 "< HTTP ${http_status}"
  jq . <<< "${response}" 2>/dev/null || echo "${response}"
  # 403 insufficient_authorization is progress, not failure
  [[ ${http_status} == 200 || "${http_status}:${error}" == '403:insufficient_authorization' ]] || exit 1
  exit 0
fi

## interactive mode: loop until authorization_code
declare authorization_code=''
body=$(start_body)

while true; do
  post "${body}"

  if [[ ${http_status} == 200 ]]; then
    authorization_code=$(jq -r '.authorization_code // empty' <<< "${response}" 2>/dev/null || true)
    [[ -n "${authorization_code}" ]] && break
    fail
  fi

  case "${http_status}:${error}" in
  403:insufficient_authorization)
    step="${response}"
    auth_session=$(jq -r '.auth_session' <<< "${step}")
    choose_next
    ;;
  403:invalid_code | 403:invalid_identifier_or_code)
    echo >&2 "rejected (${error}). try again"
    # keep the previous step unless the server issued a fresh one
    if jq -e '.auth_session' <<< "${response}" >/dev/null 2>&1; then
      auth_session=$(jq -r '.auth_session' <<< "${response}")
    fi
    if jq -e '.next' <<< "${response}" >/dev/null 2>&1; then
      step="${response}"
      choose_next
    fi
    ;;
  *)
    fail
    ;;
  esac

  answer
  body=$(continue_body "$(jq -r '.action' <<< "${selected}")" "${fields}")
done

if [[ ${opt_exchange} -eq 0 ]]; then
  jq -n --arg code "${authorization_code}" '{authorization_code: $code}'
  exit 0
fi

# no front-channel redirect in this flow, hence no redirect_uri (-u '')
declare -a exchange_args=(-d "${DOMAIN}" -c "${CLIENT_ID}" -a "${authorization_code}" -u '')
[[ -n "${CLIENT_SECRET}" ]] && exchange_args+=(-x "${CLIENT_SECRET}")
[[ ${opt_disable_discovery} -eq 1 ]] && exchange_args+=(-D)
[[ ${opt_force_refresh} -eq 1 ]] && exchange_args+=(-W)
[[ ${opt_verbose} -eq 1 ]] && exchange_args+=(-v)

"${DIR}/code-exchange.sh" "${exchange_args[@]}"

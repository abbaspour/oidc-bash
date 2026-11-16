#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2026-10-13
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/main/LICENSE)
##########################################################################################

set -eo pipefail

DIR="${BASH_SOURCE[0]%/*}"
[ "$DIR" = "${BASH_SOURCE[0]}" ] && DIR="."
readonly DIR

command -v curl >/dev/null || { echo >&2 "error: curl not found";  exit 3; }
command -v jq >/dev/null || { echo >&2 "error: jq not found";  exit 3; }

function usage() {
  cat <<END >&2
USAGE: $0 [-e env] [-t tenant] [-d domain] [-c client_id] [-x client_secret] [-B] [-a audience] [-s scope] [-m key=value] [-S token|-R] [-j jar] [-v|-h]
        -e file        # .env file location (default cwd)
        -t tenant      # tenant@region shorthand (Auth0-style, appends .auth0.com)
        -d domain      # OIDC provider domain or edge location
        -c client_id   # OAuth2/OIDC client ID
        -x secret      # client secret (client_secret_post)
        -B             # send client_id:secret as HTTP Basic (client_secret_basic)
        -k kid         # client public key jwt id (private_key_jwt)
        -K private.pem # client private key pem file (private_key_jwt)
        -a audience    # API audience (default: tenant default_audience)
        -s scope       # scope, space or comma separated
        -m key=value   # session metadata entry; repeatable. Exclusive with -S/-R
        -S token       # existing session_token (JWE) to renew
        -R             # renew using the session_token stored in the cookie jar
        -j file        # curl cookie jar to read/write (default ${cookie_jar})
        -h|?           # usage
        -v             # verbose

eg,
     $0 -t amin01@au -c aIioQEeY7nJdX78vcQWDBcAqTABgKnZl -x XXXXXX -a https://api.myapp.com/ -s read:catalog -m plan=trial -m region=us
     $0 -t amin01@au -c aIioQEeY7nJdX78vcQWDBcAqTABgKnZl -x XXXXXX -R
END
  exit "$1"
}

declare DOMAIN=''
declare CLIENT_ID=''
declare CLIENT_SECRET=''
declare AUDIENCE=''
declare SCOPE=''
declare session_token=''
declare cookie_jar='anon-cookie.txt'
declare kid=''
declare private_pem=''
declare assertion=''
declare -a metadata=()
declare opt_basic=''
declare opt_renew=''
declare opt_verbose=''

[[ -f "${DIR}/.env" ]] && . "${DIR}/.env"

while getopts "e:t:d:c:x:Bk:K:a:s:m:S:Rj:hv?" opt; do
  case ${opt} in
  e) source "${OPTARG}" ;;
  t) DOMAIN=$(echo "${OPTARG}.auth0.com" | tr '@' '.') ;;
  d) DOMAIN=${OPTARG} ;;
  c) CLIENT_ID=${OPTARG} ;;
  x) CLIENT_SECRET=${OPTARG} ;;
  B) opt_basic=1 ;;
  k) kid=${OPTARG} ;;
  K) private_pem=${OPTARG} ;;
  a) AUDIENCE=${OPTARG} ;;
  s) SCOPE=$(echo "${OPTARG}" | tr ',' ' ') ;;
  m) metadata+=("${OPTARG}") ;;
  S) session_token=${OPTARG} ;;
  R) opt_renew=1 ;;
  j) cookie_jar=${OPTARG} ;;
  v) opt_verbose=1 ;; #set -x;;
  h | ?) usage 0 ;;
  *) usage 1 ;;
  esac
done

[[ -z "${DOMAIN}" ]] && { echo >&2 "ERROR: DOMAIN undefined"; usage 1; }
[[ -z "${CLIENT_ID}" ]] && { echo >&2 "ERROR: CLIENT_ID undefined"; usage 1; }

[[ -n "${private_pem}" && -n "${CLIENT_SECRET}" ]] && { echo >&2 "ERROR: -K and -x are mutually exclusive"; usage 1; }
[[ -n "${opt_basic}" && -n "${private_pem}" ]] && { echo >&2 "ERROR: -B and -K are mutually exclusive"; usage 1; }
[[ -n "${opt_basic}" && -z "${CLIENT_SECRET}" ]] && { echo >&2 "ERROR: -B requires client secret (-x)"; usage 1; }
[[ -n "${session_token}" && -n "${opt_renew}" ]] && { echo >&2 "ERROR: -S and -R are mutually exclusive"; usage 1; }
[[ ${#metadata[@]} -gt 0 && ( -n "${session_token}" || -n "${opt_renew}" ) ]] && { echo >&2 "ERROR: -m is mutually exclusive with -S/-R"; usage 1; }

for kv in "${metadata[@]}"; do
  [[ "${kv}" == *=* ]] || { echo >&2 "ERROR: metadata '${kv}' is not key=value"; usage 1; }
done

if [[ -n "${opt_renew}" ]]; then
  # curl cookie jar is tab separated: domain, flag, path, secure, expiry, name, value
  [[ -f "${cookie_jar}" ]] || { echo >&2 "ERROR: cookie jar ${cookie_jar} not found"; exit 1; }
  session_token=$(awk -F'\t' '$6 == "auth0_anon" { print $7 }' "${cookie_jar}" | tail -n 1)
  [[ -z "${session_token}" ]] && { echo >&2 "ERROR: auth0_anon cookie not found in ${cookie_jar}"; exit 1; }
fi

[[ ${DOMAIN} =~ ^http ]] || DOMAIN=https://${DOMAIN}
[[ ${DOMAIN} =~ /$ ]] || DOMAIN="${DOMAIN}/"

readonly anonymous_endpoint="${DOMAIN}anonymous/token"

if [[ -n "${private_pem}" ]]; then
  assertion=$("${DIR}"/jwt/client-assertion.sh -a "${DOMAIN}" -i "${CLIENT_ID}" -k "${kid}" -f "${private_pem}")
  readonly assertion
fi

declare metadata_json='null'
if [[ ${#metadata[@]} -gt 0 ]]; then
  metadata_json=$(jq -n '[$ARGS.positional[] | capture("^(?<k>[^=]+)=(?<v>.*)$") | {(.k): .v}] | add' --args "${metadata[@]}")
fi

# basic auth carries client credentials in the header, otherwise they go in the body
declare body_client_id="${CLIENT_ID}"
declare body_client_secret="${CLIENT_SECRET}"
declare -a auth_args=()
if [[ -n "${opt_basic}" ]]; then
  body_client_id=''
  body_client_secret=''
  auth_args=(-u "${CLIENT_ID}:${CLIENT_SECRET}")
fi

BODY=$(jq -n \
  --arg client_id "${body_client_id}" \
  --arg client_secret "${body_client_secret}" \
  --arg client_assertion "${assertion}" \
  --arg audience "${AUDIENCE}" \
  --arg scope "${SCOPE}" \
  --arg session_token "${session_token}" \
  --argjson metadata "${metadata_json}" \
  '{
    client_id: $client_id,
    client_secret: $client_secret,
    client_assertion: $client_assertion,
    client_assertion_type: (if $client_assertion != "" then "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" else "" end),
    audience: $audience,
    scope: $scope,
    session_token: $session_token,
    metadata: $metadata
  } | with_entries(select(.value != "" and .value != null))')
readonly BODY

if [[ -n "${opt_verbose}" ]]; then
  echo >&2 "> POST ${anonymous_endpoint}"
  echo "${BODY}" | jq . >&2
  echo >&2 "> cookie jar: ${cookie_jar}"
fi

# -c writes the Set-Cookie (auth0_anon) in curl's Netscape cookie format; -b replays it on renewal
declare -a cookie_args=(-c "${cookie_jar}")
[[ -f "${cookie_jar}" && -n "${opt_renew}" ]] && cookie_args+=(-b "${cookie_jar}")

curl -s -k --header 'content-type: application/json' "${auth_args[@]}" "${cookie_args[@]}" -d "${BODY}" "${anonymous_endpoint}" | jq .

echo

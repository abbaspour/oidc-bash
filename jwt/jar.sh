#!/usr/bin/env bash
# shellcheck disable=SC2034

##########################################################################################
# Author: Amin Abbaspour
# Date: 2026-08-17
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/main/LICENSE)
#
# jar.sh: builds and signs a JWT-Secured Authorization Request (JAR) per RFC 9101.
##########################################################################################

set -euo pipefail

DIR="${BASH_SOURCE[0]%/*}"
[ "$DIR" = "${BASH_SOURCE[0]}" ] && DIR="."
readonly DIR

command -v jq >/dev/null || { echo >&2 "error: jq not found"; exit 3; }

declare alg='PS256'
declare TTL=300

function usage() {
    cat <<END >&2
USAGE: $0 -a audience -i client_id -p pem -P params [-k kid] [-A alg] [-t ttl] [-v|-h]
        -a audience    # authorization server issuer (used as JWT aud)
        -i client_id   # client_id (used as JWT iss)
        -k kid         # signing key id
        -p pem         # private key PEM file
        -P params      # authorize request params as a URL query string, eg "response_type=code&scope=openid"
        -A alg         # signing algorithm. default ${alg}
        -t ttl         # TTL in seconds. default is ${TTL}
        -h|?           # usage
        -v             # verbose

eg,
     $0 -a https://my-tenant.auth0.com/ -i 6KS0YSEQwsvE9qRqtzonX8SEgJEYVzVH -k mykid -p ../ca/mydomain.local.key -P "response_type=code&scope=openid"
END
    exit "$1"
}

function urldecode() {
    local data=${1//+/ }
    printf '%b' "${data//%/\\x}"
}

declare opt_verbose=''
declare AUDIENCE=''
declare client_id=''
declare pem_file=''
declare kid=''
declare params=''

while getopts "a:i:p:k:P:A:t:hv?" opt; do
    case ${opt} in
    a) AUDIENCE=${OPTARG} ;;
    i) client_id=${OPTARG} ;;
    p) pem_file=${OPTARG} ;;
    k) kid=${OPTARG} ;;
    P) params=${OPTARG} ;;
    A) alg=${OPTARG} ;;
    t) TTL=${OPTARG} ;;
    v) opt_verbose=1 ;; #set -x;;
    h | ?) usage 0 ;;
    *) usage 1 ;;
    esac
done

[[ -z "${AUDIENCE}" ]] && { echo >&2 "ERROR: AUDIENCE undefined"; usage 1; }
[[ -z "${client_id}" ]] && { echo >&2 "ERROR: client_id undefined"; usage 1; }
[[ -z "${kid}" ]] && { echo >&2 "ERROR: kid undefined"; usage 1; }
[[ -z "${pem_file}" ]] && { echo >&2 "ERROR: pem_file undefined"; usage 1; }
[[ -f "${pem_file}" ]] || { echo >&2 "ERROR: pem_file missing: ${pem_file}"; usage 1; }
[[ -z "${params}" ]] && { echo >&2 "ERROR: params undefined"; usage 1; }

declare now
now=$(date +%s)
readonly now
declare -r exp=$((now + TTL))

# decode "k1=v1&k2=v2&..." into tab/newline separated pairs, then let jq build the JSON object
declare -a pairs
IFS='&' read -ra pairs <<<"${params}"

declare decoded_pairs=''
for kv in "${pairs[@]}"; do
    [[ -z "${kv}" ]] && continue
    key=${kv%%=*}
    val=$(urldecode "${kv#*=}")
    decoded_pairs+="${key}"$'\t'"${val}"$'\n'
done
readonly decoded_pairs

declare claims_json
claims_json=$(jq -R -s '
    split("\n") | map(select(length > 0) | split("\t")) | map({(.[0]): (.[1] // "")}) | add // {}
' <<<"${decoded_pairs}")
readonly claims_json

declare body
body=$(jq --argjson iat "${now}" --argjson exp "${exp}" '. + {iat: $iat, exp: $exp, nbf: $iat}' <<<"${claims_json}")
readonly body

[[ -n "${opt_verbose}" ]] && echo >&2 "${body}"

declare json
json=$(mktemp --suffix=.json)
readonly json
echo "${body}" >"${json}"

"${DIR}/sign-rs256.sh" -a "${AUDIENCE}" -i "${client_id}" -k "${kid}" -f "${json}" -p "${pem_file}" -A "${alg}" -t oauth-authz-req+jwt

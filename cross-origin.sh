#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2022-06-12
# License: MIT (https://github.com/abbaspour/oidc-bash/blob/master/LICENSE)
##########################################################################################
# Auth0-specific: targets Auth0's legacy /co/authenticate cross-origin endpoint.

set -eo pipefail

DIR="${BASH_SOURCE[0]%/*}"
[ "$DIR" = "${BASH_SOURCE[0]}" ] && DIR="."
readonly DIR

urlencode() {
    local length="${#1}"
    for ((i = 0; i < length; i++)); do
        local c="${1:i:1}"
        case $c in
        [a-zA-Z0-9.~_-]) printf "$c" ;;
        *) printf '%s' "$c" | xxd -p -c1 |
            while read c; do printf '%%%s' "$c"; done ;;
        esac
    done
}

declare REDIRECT_URI='https://jwt.io' # add this to "Allowed Callback URLs" of your application
declare ORIGIN='https://jwt.io'       # add this to "Allowed Web Origins" of your application
declare CONNECTION='Username-Password-Authentication'
declare SCOPE='openid profile email'

declare -r CLIENT_META_B64=$(echo -n '{"name":"auth0.js","version":"9.0.2"}' | base64)

function usage() {
    cat <<END >&2
USAGE: $0 [-e env] [-t tenant] [-d domain] [-c client_id] [-u username] [-p password] [-r connection] [-o origin] [-U callback] [-v|-h]
        -e file        # .env file location (default cwd)
        -t tenant      # tenant@region shorthand (Auth0-style, appends .auth0.com)
        -d domain      # OIDC provider domain
        -c client_id   # OAuth2/OIDC client ID
        -u username    # Username
        -p password    # Password
        -r realm       # Connection (default ${CONNECTION})
        -o origin      # Allowed Origin (default ${ORIGIN})
        -U callback    # callback URL (default ${REDIRECT_URI})
        -a audience    # audience
        -S state       # state
        -n nonce       # nonce
        -s scopes      # scopes (comma-separated, default "${SCOPE}")
        -M             # Management API audience
        -h|?           # usage
        -v             # verbose

eg,
     $0 -t amin01@au -u somebody@gmail.com  -p XXXXX -c 1iSgx01LN27oEgpFfGvG2UASbpSndtXg -M
END
    exit $1
}

declare DOMAIN=''
declare CLIENT_ID=''
declare AUDIENCE=''
declare USERNAME=''
declare PASSWORD=''
declare opt_mgmnt=''
declare opt_verbose=0
declare opt_state=''
declare opt_nonce=''

[[ -f "${DIR}/.env" ]] && . "${DIR}/.env"

while getopts "e:t:d:c:a:u:p:r:o:U:s:S:n:Mhv?" opt; do
    case ${opt} in
    e) source "${OPTARG}" ;;
    t) DOMAIN=$(echo "${OPTARG}.auth0.com" | tr '@' '.') ;;
    d) DOMAIN=${OPTARG} ;;
    c) CLIENT_ID=${OPTARG} ;;
    a) AUDIENCE=${OPTARG} ;;
    u) USERNAME=${OPTARG} ;;
    p) PASSWORD=${OPTARG} ;;
    r) CONNECTION=${OPTARG} ;;
    o) ORIGIN=${OPTARG} ;;
    U) REDIRECT_URI=${OPTARG} ;;
    s) SCOPE=$(echo "${OPTARG}" | tr ',' ' ') ;;
    S) opt_state=${OPTARG} ;;
    n) opt_nonce=${OPTARG} ;;
    M) opt_mgmnt=1 ;;
    v) opt_verbose=1 ;; #set -x;;
    h | ?) usage 0 ;;
    *) usage 1 ;;
    esac
done

[[ -z "${DOMAIN}" ]] && {  echo >&2 "ERROR: DOMAIN undefined";  usage 1;  }
[[ -z "${CLIENT_ID}" ]] && { echo >&2 "ERROR: CLIENT_ID undefined";  usage 1; }

[[ -z "${USERNAME}" ]] && { echo >&2 "ERROR: USERNAME undefined";  usage 1; }

[[ -z "${PASSWORD}" ]] && { echo >&2 "ERROR: PASSWORD undefined";  usage 1; }


[[ -n "${opt_mgmnt}" ]] && AUDIENCE="https://${DOMAIN}/api/v2/"

declare BODY=$(cat <<EOL
{
    "client_id":"${CLIENT_ID}",
    "username":"${USERNAME}",
    "password":"${PASSWORD}",
    "realm":"${CONNECTION}",
    "credential_type":"http://auth0.com/oauth/grant-type/password-realm"
}
EOL
)

if [[ -n "${opt_verbose}" ]]; then
    echo >&2 "> POST https://${DOMAIN}/co/authenticate"
    echo "${BODY}" | jq . >&2
fi

declare co_response=$(curl -s -c cookie.txt -H "Content-Type: application/json" \
    -H "origin: ${ORIGIN}" \
    -H "auth0-clients: ${CLIENT_META_B64}" \
    -d "${BODY}" https://${DOMAIN}/co/authenticate)

echo "CO Response: ${co_response}"

## TODO: check `jq` installed
declare login_ticket=$(echo "${co_response}" | jq -cr .login_ticket)
echo "login_ticket=${login_ticket}"

[[ ${login_ticket} == "null" ]] && { echo >&2 "login_ticket collection failed"; exit 3; }

declare authorize_url="https://${DOMAIN}/authorize?client_id=${CLIENT_ID}&response_type=$(urlencode "token id_token")&redirect_uri=$(urlencode ${REDIRECT_URI})&login_ticket=${login_ticket}&nonce=n1" # &auth0Client=${CLIENT_META_B64}

[[ -n "${AUDIENCE}" ]] && authorize_url+="&audience=$(urlencode ${AUDIENCE})"
[[ -n "${CONNECTION}" ]] && authorize_url+="&connection=${CONNECTION}"
[[ -n "${SCOPE}" ]] && authorize_url+="&scope=$(urlencode "${SCOPE}")"
[[ -n "${opt_state}" ]] && authorize_url+="&state=$(urlencode ${opt_state})"
[[ -n "${opt_nonce}" ]] && authorize_url+="&nonce=$(urlencode ${opt_nonce})"

echo "authorize_url: ${authorize_url}"

[[ -n "${opt_verbose}" ]] && echo >&2 "> GET ${authorize_url}"

declare location=$(curl -s -b cookie.txt $authorize_url | awk 'IGNORECASE = 1;/^location: /{print $2}')

echo "Redirect location: ${location}"

[[ ${location} =~ ^/u/ ]] && { echo >&2 "WARNING: MFA enabled. CO not possible without user interaction"; exit 3; }
[[ ${location} =~ ^/mf ]] && { echo >&2 "WARNING: MFA enabled. CO not possible without user interaction"; exit 3; }
[[ ${location} =~ ^/decision ]] && { echo >&2 "WARNING: Consent required. CO not possible without user interaction. Try normal ./authorize.sh first."; exit 3; }

declare access_token=$(echo "${location}" | grep -oE "access_token=([^&]+)" | awk -F= '{print $2}')
declare id_token=$(echo "${location}" | grep -oE "id_token=([^&]+)" | awk -F= '{print $2}')
declare state=$(echo "${location}" | grep -oE "state=([^&]+)" | awk -F= '{print $2}')

## TODO: check if `base64` installed
declare id_token_json=$(echo "${id_token}" | awk -F. '{print $2}' | base64 -di 2>/dev/null)

echo "Access Token: ${access_token}"
echo "ID     Token: ${id_token_json}"
echo "state       : ${state}"

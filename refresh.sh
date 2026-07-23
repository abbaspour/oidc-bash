#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2022-06-12
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/master/LICENSE)
# Reference: https://auth0.com/docs/authenticate/single-sign-on/native-to-web/configure-implement-native-to-web
##########################################################################################

set -ueo pipefail

DIR="${BASH_SOURCE[0]%/*}"
[ "$DIR" = "${BASH_SOURCE[0]}" ] && DIR="."
readonly DIR

function usage() {
    cat <<END >&2
USAGE: $0 [-e env] [-t tenant] [-d domain] [-c client_id] [-x client_secret] [-r refresh_token] [-s scopes] [-a audience] [-P dpop.pem] [-g] [-v|-h]
        -e file        # .env file location (default cwd)
        -t tenant      # tenant@region shorthand (Auth0-style, appends .auth0.com)
        -d domain      # OIDC provider domain
        -c client_id   # OAuth2/OIDC client ID
        -x secret      # OAuth2/OIDC client secret (optional for public clients)
        -r token       # refresh_token
        -a audience    # Audience (for MRRT)
        -s scopes      # comma separated list of scopes
        -P private.pem # DPoP EC private key PEM file
        -g             # enable session_transfer audience for native to web
        -D             # disable OIDC discovery; use default endpoints
        -h|?           # usage
        -v             # verbose

eg,
     $0 -t amin01@au -c aIioQEeY7nJdX78vcQWDBcAqTABgKnZl -x XXXXXX -r RRRRRRR
END
    exit $1
}

declare DOMAIN=''
declare CLIENT_ID=''
declare CLIENT_SECRET=''
declare AUDIENCE=''
declare opt_verbose=''
declare refresh_token=''
declare SCOPE=''
declare enable_session_transfer=0
declare token_endpoint_path='oauth/token'
declare opt_disable_discovery=0
declare dpop_pem_file=''

[[ -f "${DIR}/.env" ]] && . "${DIR}/.env"

while getopts "e:t:d:c:r:a:x:s:P:Dghv?" opt; do
    case ${opt} in
    e) source "${OPTARG}" ;;
    t) DOMAIN=$(echo "${OPTARG}.auth0.com" | tr '@' '.') ;;
    d) DOMAIN=${OPTARG} ;;
    c) CLIENT_ID=${OPTARG} ;;
    x) CLIENT_SECRET=${OPTARG} ;;
    r) refresh_token=${OPTARG} ;;
    a) AUDIENCE=${OPTARG} ;;
    s) SCOPE=$(echo "${OPTARG}" | tr ',' ' ') ;;
    P) dpop_pem_file=${OPTARG} ;;
    D) opt_disable_discovery=1 ;;
    g) enable_session_transfer=1 ;;
    v) opt_verbose=1 ;; #set -x;;
    h | ?) usage 0 ;;
    *) usage 1 ;;
    esac
done

[[ -z "${DOMAIN}" ]] && {  echo >&2 "ERROR: DOMAIN undefined";  usage 1;  }
[[ -z "${CLIENT_ID}" ]] && { echo >&2 "ERROR: CLIENT_ID undefined";  usage 1; }
[[ -z "${refresh_token}" ]] && { echo >&2 "ERROR: refresh_token undefined";  usage 1; }

[[ ${DOMAIN} =~ ^http ]] || DOMAIN=https://${DOMAIN}
declare token_endpoint="${DOMAIN}/${token_endpoint_path}"

# OIDC Discovery to resolve token endpoint (unless disabled via -D)
if [[ ${opt_disable_discovery} -eq 0 ]]; then
  declare discovery_json
  discovery_json=$(curl -s -k --header "accept: application/json" --url "${DOMAIN}/.well-known/openid-configuration" || true)
  declare d_token=$(echo "${discovery_json}" | jq -r '.token_endpoint // empty')
  [[ -n "${d_token}" ]] && token_endpoint="${d_token}"
fi

declare secret=''
[[ -n "${CLIENT_SECRET}" ]] && secret="\"client_secret\":\"${CLIENT_SECRET}\","

declare scope=''
[[ -n "${SCOPE}" ]] && scope="\"scope\":\"${SCOPE}\","

declare audience=''
[[ -n "${AUDIENCE}" ]] && audience="\"audience\":\"${AUDIENCE}\","

[[ ${enable_session_transfer} -eq 1 ]] && audience="\"audience\":\"urn:${DOMAIN}:session_transfer\","

declare BODY=$(cat <<EOL
{
    "client_id":"${CLIENT_ID}",
    ${secret}
    "refresh_token": "${refresh_token}",
    ${scope}
    ${audience}
    "grant_type":"refresh_token"
}
EOL
)

[[ "${opt_verbose}" ]] && echo "${BODY}"

declare dpop_header=''
if [[ -n "${dpop_pem_file}" ]]; then
    dpop_header="DPoP: $("${DIR}"/jwt/dpop.sh -r "${dpop_pem_file}" -m POST -u "${token_endpoint}")"
    [[ -n "${opt_verbose}" ]] && echo "${dpop_header}"
fi

if [[ -n "${dpop_pem_file}" ]]; then
  declare _dpop_hdr_file
  _dpop_hdr_file=$(mktemp)
  declare _dpop_body
  _dpop_body=$(curl -s -D "${_dpop_hdr_file}" --request POST \
    -H "${dpop_header}" \
    --url "${token_endpoint}" \
    --header 'content-type: application/json' \
    --data "${BODY}")
  declare _dpop_nonce
  _dpop_nonce=$(grep -i '^dpop-nonce:' "${_dpop_hdr_file}" | awk '{print $2}' | tr -d '\r\n' || true)
  rm -f "${_dpop_hdr_file}"
  if [[ -n "${_dpop_nonce}" ]]; then
    dpop_header="DPoP: $("${DIR}"/jwt/dpop.sh -r "${dpop_pem_file}" -m POST -u "${token_endpoint}" -n "${_dpop_nonce}")"
    [[ -n "${opt_verbose}" ]] && echo "${dpop_header}"
    curl -s --request POST \
      -H "${dpop_header}" \
      --url "${token_endpoint}" \
      --header 'content-type: application/json' \
      --data "${BODY}" | jq .
  else
    echo "${_dpop_body}" | jq .
  fi
else
  curl -s --request POST \
    --url "${token_endpoint}" \
    --header 'content-type: application/json' \
    --data "${BODY}" | jq .
fi

echo

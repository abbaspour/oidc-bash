#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2022-06-12
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/main/LICENSE)
# Reference: https://auth0.com/docs/authenticate/single-sign-on/native-to-web/configure-implement-native-to-web
##########################################################################################

set -ueo pipefail

DIR="${BASH_SOURCE[0]%/*}"
[ "$DIR" = "${BASH_SOURCE[0]}" ] && DIR="."
readonly DIR
declare alg='RS256'

function usage() {
    cat <<END >&2
USAGE: $0 [-e env] [-t tenant] [-d domain] [-c client_id] [-x client_secret] [-k kid] [-K private.pem] [-A alg] [-r refresh_token] [-s scopes] [-a audience] [-R resource] [-P dpop.pem] [-g] [-v|-h]
        -e file        # .env file location (default cwd)
        -t tenant      # tenant@region shorthand (Auth0-style, appends .auth0.com)
        -d domain      # OIDC provider domain
        -c client_id   # OAuth2/OIDC client ID
        -x secret      # OAuth2/OIDC client secret (optional for public clients)
        -k kid         # JWT-CA (private_key_jwt) key id
        -K private.pem # JWT-CA client private key file for client assertion
        -A alg         # JWT-CA algorithm. default ${alg}. supports: RS256, ES256, PS256
        -r token       # refresh_token
        -a audience    # Audience (for MRRT)
        -R resource    # RFC 8707 resource indicator: a token for this resource only
        -s scopes      # comma separated list of scopes
        -P private.pem # DPoP EC private key PEM file
        -g             # enable session_transfer audience for native to web
        -D             # disable OIDC discovery; use default endpoints
        -W             # force-renew discovery cache (bypass any cached openid-configuration)
        -h|?           # usage
        -v             # verbose

eg,
     $0 -t amin01@au -c aIioQEeY7nJdX78vcQWDBcAqTABgKnZl -x XXXXXX -r RRRRRRR
     $0 -d tenant.auth0.com -c https://agent.example/cimd.json -k KID -K ec-private.pem -A ES256 -r RRRRRRR
END
    exit "$1"
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
declare opt_force_refresh=0
declare dpop_pem_file=''
declare kid=''
declare private_pem=''
declare RESOURCE=''

# OIDC_BASH_NO_DOTENV=1 skips the automatic .env, eg. when another tool calls this script
[[ -z "${OIDC_BASH_NO_DOTENV:-}" && -f "${DIR}/.env" ]] && . "${DIR}/.env"

while getopts "e:t:d:c:r:a:x:s:P:k:K:A:R:DWghv?" opt; do
    case ${opt} in
    e) source "${OPTARG}" ;;
    t) DOMAIN=$(echo "${OPTARG}.auth0.com" | tr '@' '.') ;;
    d) DOMAIN=${OPTARG} ;;
    c) CLIENT_ID=${OPTARG} ;;
    x) CLIENT_SECRET=${OPTARG} ;;
    r) refresh_token=${OPTARG} ;;
    a) AUDIENCE=${OPTARG} ;;
    R) RESOURCE=${OPTARG} ;;
    k) kid=${OPTARG} ;;
    K) private_pem=${OPTARG} ;;
    A) alg=${OPTARG} ;;
    s) SCOPE=$(echo "${OPTARG}" | tr ',' ' ') ;;
    P) dpop_pem_file=${OPTARG} ;;
    D) opt_disable_discovery=1 ;;
    W) opt_force_refresh=1 ;;
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
declare issuer="${DOMAIN}"
[[ ${issuer} =~ /$ ]] || issuer="${issuer}/"

# OIDC Discovery to resolve token endpoint (unless disabled via -D); -W forces a cache-bypassing re-fetch
if [[ ${opt_disable_discovery} -eq 0 ]]; then
  declare -a discovery_args=(-d "${DOMAIN}" -f issuer -f token_endpoint)
  [[ ${opt_force_refresh} -eq 1 ]] && discovery_args+=(-W)

  declare -a discovery_vals
  mapfile -t discovery_vals < <("${DIR}/discover.sh" "${discovery_args[@]}")

  d_issuer="${discovery_vals[0]}"
  d_token="${discovery_vals[1]}"
  [[ -n "${d_issuer}" ]] && issuer="${d_issuer}"
  [[ -n "${d_token}" ]] && token_endpoint="${d_token}"
fi

# one client authentication method per request (RFC 6749 §2.3): JWT-CA (-K) wins over a secret
declare secret=''
[[ -n "${CLIENT_SECRET}" && -z "${private_pem}" ]] && secret="\"client_secret\":\"${CLIENT_SECRET}\","

declare scope=''
[[ -n "${SCOPE}" ]] && scope="\"scope\":\"${SCOPE}\","

declare audience=''
[[ -n "${AUDIENCE}" ]] && audience="\"audience\":\"${AUDIENCE}\","

[[ ${enable_session_transfer} -eq 1 ]] && audience="\"audience\":\"urn:${DOMAIN}:session_transfer\","

declare resource=''
[[ -n "${RESOURCE}" ]] && resource="\"resource\":\"${RESOURCE}\","

# JWT-CA (private_key_jwt, RFC 7523): the assertion's aud is the issuer
declare client_assertion=''
if [[ -n "${private_pem}" ]]; then
  [[ -f "${private_pem}" ]] || { echo >&2 "ERROR: private key missing: ${private_pem}"; usage 1; }
  assertion=$("${DIR}"/jwt/client-assertion.sh -a "${issuer}" -i "${CLIENT_ID}" -k "${kid}" -f "${private_pem}" -A "${alg}")
  readonly assertion
  client_assertion="\"client_assertion_type\":\"urn:ietf:params:oauth:client-assertion-type:jwt-bearer\",\"client_assertion\":\"${assertion}\","
fi
readonly client_assertion

declare BODY
BODY=$(cat <<EOL
{
    "client_id":"${CLIENT_ID}",
    ${secret}
    "refresh_token": "${refresh_token}",
    ${scope}
    ${audience}
    ${resource}
    ${client_assertion}
    "grant_type":"refresh_token"
}
EOL
)

if [[ -n "${opt_verbose}" ]]; then
    echo >&2 "> POST ${token_endpoint}"
    echo >&2 "${BODY}"
fi

declare dpop_header=''
if [[ -n "${dpop_pem_file}" ]]; then
    dpop_header="DPoP: $("${DIR}"/jwt/dpop.sh -r "${dpop_pem_file}" -m POST -u "${token_endpoint}")"
    echo >&2 "${dpop_header}"
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
    echo >&2 "${dpop_header}"
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

#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2022-06-12
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/main/LICENSE)
##########################################################################################

set -ueo pipefail

DIR="${BASH_SOURCE[0]%/*}"
[ "$DIR" = "${BASH_SOURCE[0]}" ] && DIR="."
readonly DIR
declare alg='RS256'

function usage() {
    cat <<END >&2
USAGE: $0 [-e env] [-t tenant] [-d domain] [-c client_id] [-k kid] [-K private.pem] [-A alg] [-s scopes] [-a audience] [-R resource] [-M|-D|-W|-v|-h]
        -e file        # .env file location (default cwd)
        -t tenant      # tenant@region shorthand (Auth0-style, appends .auth0.com)
        -d domain      # OIDC provider domain
        -c client_id   # OAuth2/OIDC client ID
        -k kid         # JWT-CA (private_key_jwt) key id
        -K private.pem # JWT-CA client private key file for client assertion (confidential clients)
        -A alg         # JWT-CA algorithm. default ${alg}. supports: RS256, ES256, PS256
        -s scopes      # scope1,scope2,etc
        -a audience    # API audience
        -R resource    # RFC 8707 resource indicator (repeatable; several are sent as a JSON array)
        -M             # Management API audience
        -D             # disable OIDC discovery; use default endpoint oauth/device/code
        -W             # force-renew discovery cache (bypass any cached openid-configuration)
        -h|?           # usage
        -v             # verbose

eg,
     $0 -t amin01@au -c aIioQEeY7nJdX78vcQWDBcAqTABgKnZl
     $0 -d tenant.auth0.com -c https://agent.example/cimd.json -k KID -K ec-private.pem -A ES256 -s openid,offline_access
END
    exit "$1"
}

declare DOMAIN=''
declare CLIENT_ID=''

declare opt_verbose=0
declare opt_mgmnt=''
declare opt_disable_discovery=0
declare opt_force_refresh=0

declare audience_field=''
declare -a resources=()
declare kid=''
declare private_pem=''
declare scopes_field=''

while getopts "e:t:d:c:a:s:k:K:A:R:MDWhv?" opt; do
    case ${opt} in
    e) source "${OPTARG}" ;;
    t) DOMAIN=$(echo "${OPTARG}.auth0.com" | tr '@' '.') ;;
    d) DOMAIN=${OPTARG} ;;
    c) CLIENT_ID=${OPTARG} ;;
    s)
        scopes=$(echo "${OPTARG}" | tr ',' ' ')
        scopes_field=",\"scope\":\"${scopes}\""
        ;;
    a) audience_field=",\"audience\":\"${OPTARG}\"" ;;
    k) kid=${OPTARG} ;;
    R) resources+=("${OPTARG}") ;;
    K) private_pem=${OPTARG} ;;
    A) alg=${OPTARG} ;;
    M) opt_mgmnt=1 ;;
    D) opt_disable_discovery=1 ;;
    W) opt_force_refresh=1 ;;
    v) opt_verbose=1 ;; #set -x;;
    h | ?) usage 0 ;;
    *) usage 1 ;;
    esac
done

[[ -z "${DOMAIN}" ]] && {  echo >&2 "ERROR: DOMAIN undefined";  usage 1;  }
[[ -z "${CLIENT_ID}" ]] && { echo >&2 "ERROR: CLIENT_ID undefined";  usage 1; }


[[ -n "${opt_mgmnt}" ]] && audience_field=",\"audience\":\"https://${DOMAIN}/api/v2/\""

declare device_authorization_endpoint="https://${DOMAIN}/oauth/device/code"
declare issuer="https://${DOMAIN}/"

# OIDC Discovery to resolve device authorization endpoint (unless disabled via -D); -W forces a cache-bypassing re-fetch
if [[ ${opt_disable_discovery} -eq 0 ]]; then
    declare -a discovery_args=(-d "${DOMAIN}" -f issuer -f device_authorization_endpoint)
    [[ ${opt_force_refresh} -eq 1 ]] && discovery_args+=(-W)

    declare -a discovery_vals
    mapfile -t discovery_vals < <("${DIR}/discover.sh" "${discovery_args[@]}")

    d_issuer="${discovery_vals[0]}"
    d_device_endpoint="${discovery_vals[1]}"
    [[ -n "${d_issuer}" ]] && issuer="${d_issuer}"
    [[ -n "${d_device_endpoint}" ]] && device_authorization_endpoint="${d_device_endpoint}"
fi

# JWT-CA (private_key_jwt, RFC 7523): the assertion's aud is the issuer
declare assertion_field=''
if [[ -n "${private_pem}" ]]; then
    [[ -f "${private_pem}" ]] || { echo >&2 "ERROR: private key missing: ${private_pem}"; usage 1; }
    assertion=$("${DIR}"/jwt/client-assertion.sh -a "${issuer}" -i "${CLIENT_ID}" -k "${kid}" -f "${private_pem}" -A "${alg}")
    readonly assertion
    assertion_field=",\"client_assertion_type\":\"urn:ietf:params:oauth:client-assertion-type:jwt-bearer\",\"client_assertion\":\"${assertion}\""
fi
readonly assertion_field

# one resource as a string, several as an array
declare resource_field=''
if [[ ${#resources[@]} -eq 1 ]]; then
    resource_field=",\"resource\":$(jq -n --arg r "${resources[0]}" '$r')"
elif [[ ${#resources[@]} -gt 1 ]]; then
    resource_field=",\"resource\":$(printf '%s\n' "${resources[@]}" | jq -R . | jq -sc .)"
fi
readonly resource_field

declare BODY
BODY=$(cat <<EOL
{
    "client_id":"${CLIENT_ID}"
    ${audience_field}
    ${scopes_field}
    ${resource_field}
    ${assertion_field}
}
EOL
)

if [[ ${opt_verbose} -eq 1 ]]; then
    echo >&2 "> POST ${device_authorization_endpoint}"
    echo "${BODY}" | jq . >&2
fi

curl -ss --header 'content-type: application/json' -d "${BODY}" "${device_authorization_endpoint}" | jq .

# a hint for interactive use; on stderr so stdout stays JSON
declare jwt_ca_args=''
[[ -n "${private_pem}" ]] && jwt_ca_args=" -k ${kid} -K ${private_pem} -A ${alg}"
echo >&2 -e "\n Polling:\n ./code-exchange.sh -d ${DOMAIN} -c ${CLIENT_ID}${jwt_ca_args} -C DEVICE_CODE"

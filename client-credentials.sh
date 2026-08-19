#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2022-06-12
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/main/LICENSE)
##########################################################################################

set -eo pipefail

DIR="${BASH_SOURCE[0]%/*}"
[ "$DIR" = "${BASH_SOURCE[0]}" ] && DIR="."
readonly DIR

command -v curl >/dev/null || { echo >&2 "error: curl not found";  exit 3; }

function usage() {
  cat <<END >&2
USAGE: $0 [-e env] [-t tenant] [-d domain] [-c client_id] [-x client_secret] [-a audience] [-M|-O|-v|-h]
        -e file        # .env file location (default cwd)
        -t tenant      # tenant@region shorthand (Auth0-style, appends .auth0.com)
        -d domain      # OIDC provider domain or edge location
        -c client_id   # OAuth2/OIDC client ID
        -x secret      # OAuth2/OIDC client secret
        -a audience    # API audience
        -o org_id      # Organization ID
        -k kid         # client public key jwt id
        -K private.pem # client private key pem file
        -M             # Management API audience
        -O             # MyOrg API audience
        -n api_key     # cname_api_key
        -C cert.pem    # client certificate for mTLS
        -S             # mark request as CA signed
        -D             # disable OIDC discovery; use default endpoint oauth/token
        -W             # force-renew discovery cache (bypass any cached openid-configuration)
        -h|?           # usage
        -v             # verbose

eg,
     $0 -t amin01@au -c aIioQEeY7nJdX78vcQWDBcAqTABgKnZl -x XXXXXX -M
END
  exit "$1"
}

declare DOMAIN=''
declare CLIENT_ID=''
declare CLIENT_SECRET=''
declare AUDIENCE=''
declare ORGANIZATION=''
declare secret=''
declare organization=''
declare kid=''
declare private_pem=''
declare client_assertion=''
declare cname_api_key=''
declare client_certificate=''
declare ca_signed='FAILED: self signed certificate'
declare opt_mgmnt=''
declare opt_myorg=''
declare opt_verbose=''
declare opt_disable_discovery=0
declare opt_force_refresh=0

[[ -f "${DIR}/.env" ]] && . "${DIR}/.env"

while getopts "e:t:d:c:a:o:x:k:K:n:C:OSMDWhv?" opt; do
  case ${opt} in
  e) source "${OPTARG}" ;;
  t) DOMAIN=$(echo "${OPTARG}.auth0.com" | tr '@' '.') ;;
  d) DOMAIN=${OPTARG} ;;
  c) CLIENT_ID=${OPTARG} ;;
  x) CLIENT_SECRET=${OPTARG} ;;
  a) AUDIENCE=${OPTARG} ;;
  o) ORGANIZATION=${OPTARG} ;;
  k) kid=${OPTARG} ;;
  K) private_pem=${OPTARG} ;;
  n) cname_api_key=${OPTARG} ;;
  C) client_certificate=$(jq -sRr @uri "${OPTARG}") ;;
  S) ca_signed='SUCCESS' ;;
  M) opt_mgmnt=1 ;;
  O) opt_myorg=1 ;;
  D) opt_disable_discovery=1 ;;
  W) opt_force_refresh=1 ;;
  v) opt_verbose=1 ;; #set -x;;
  h | ?) usage 0 ;;
  *) usage 1 ;;
  esac
done

[[ -z "${DOMAIN}" ]] && { echo >&2 "ERROR: DOMAIN undefined"; usage 1; }
[[ -z "${CLIENT_ID}" ]] && { echo >&2 "ERROR: CLIENT_ID undefined"; usage 1; }

[[ ${DOMAIN} =~ ^http ]] || DOMAIN=https://${DOMAIN}
[[ ${DOMAIN} =~ /$ ]] || DOMAIN="${DOMAIN}/"

[[ -n "${CLIENT_SECRET}" ]] && secret="\"client_secret\":\"${CLIENT_SECRET}\","
[[ -n "${ORGANIZATION}" ]] && organization="\"organization\":\"${ORGANIZATION}\","

[[ -n "${opt_mgmnt}" ]] && AUDIENCE="${DOMAIN}api/v2/"
[[ -n "${opt_myorg}" ]] && AUDIENCE="${DOMAIN}my-org/"

declare token_endpoint="${DOMAIN}oauth/token"

# OIDC Discovery to resolve token endpoint (unless disabled via -D); -W forces a cache-bypassing re-fetch
if [[ ${opt_disable_discovery} -eq 0 ]]; then
  declare -a discovery_args=(-d "${DOMAIN}" -f token_endpoint)
  [[ ${opt_force_refresh} -eq 1 ]] && discovery_args+=(-W)

  declare -a discovery_vals
  mapfile -t discovery_vals < <("${DIR}/discover.sh" "${discovery_args[@]}")

  d_token="${discovery_vals[0]}"
  [[ -n "${d_token}" ]] && token_endpoint="${d_token}"
fi

if [[ -n "${private_pem}" ]]; then
  assertion=$("${DIR}"/jwt/client-assertion.sh -a "${DOMAIN}" -i "${CLIENT_ID}" -k "${kid}" -f "${private_pem}")
  readonly assertion
  client_assertion=$(
    cat <<EOL
  , "client_assertion" : "${assertion}",
  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
EOL
  )
fi

BODY=$(cat <<EOL
{
    "client_id":"${CLIENT_ID}", ${secret}
    "audience":"${AUDIENCE}", ${organization}
    "grant_type":"client_credentials" ${client_assertion}
}
EOL
)
readonly BODY

if [[ -n "${opt_verbose}" ]]; then
  echo >&2 "> POST ${token_endpoint}"
  echo "${BODY}" | jq . >&2
fi

if [[ -z "${cname_api_key}"  ]]; then
  curl -s -k --header 'content-type: application/json' -d "${BODY}" "${token_endpoint}" | jq .
else
  curl -s -k --header 'content-type: application/json' -d "${BODY}" \
    --header "cname-api-key: ${cname_api_key}" \
    --header "client-certificate: ${client_certificate}" \
    --header "client-certificate-ca-verified: ${ca_signed}" \
    "${token_endpoint}" | jq .
fi

echo
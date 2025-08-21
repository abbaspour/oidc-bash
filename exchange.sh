#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2022-06-12
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/master/LICENSE)
#
# This script exchanges authorization_code obtained from authorization server to token assets
##########################################################################################

set -ueo pipefail

readonly DIR=$(dirname "${BASH_SOURCE[0]}")
declare alg='RS256'

function usage() {
  cat <<END >&2
USAGE: $0 [-e env] [-t tenant] [-d domain] [-c client_id] [-x client_secret] [-X code_verifier] [-P dpop.pem] [-u callback] [-a authorization_code] [-p] [-D] [-v|-h]
        -e file        # .env file location (default cwd)
        -t tenant      # Auth0 tenant@region
        -d domain      # Auth0 domain
        -c client_id   # Auth0 client ID
        -x secret      # Auth0 client secret
        -X verifier    # PKCE code_verifier
        -a code        # Authorization Code to exchange
        -r req_id      # back channel authorization (CIBA) auth_req_id
        -C code        # Device Code to exchange
        -u callback    # callback URL
        -U endpoint    # token endpoint URI (default is 'oauth/token')
        -k kid         # client public key JWT-CA key id
        -K private.pem # JWT-CA client private key file for client assertion
        -A alg         # JWT-CA algorithm. default ${alg}. supports: RS256, ES256, PS256
        -P private.pem # DPoP EC private key PEM file
        -b             # HTTP Basic authentication (default is secret in payload)
        -p             # HTTP form post (default is application/json)
        -D             # disable OIDC discovery; use default endpoints
        -h|?           # usage
        -v             # verbose

eg,
     $0 -t amin01@au -c aIioQEeY7nJdX78vcQWDBcAqTABgKnZl -x XXXXXX -a 803131zx232
END
  exit $1
}

declare AUTH0_DOMAIN=''
declare AUTH0_CLIENT_ID=''
declare AUTH0_CLIENT_SECRET=''
declare AUTH0_REDIRECT_URI='https://jwt.io'
declare authorization_code=''
declare code_verifier=''
declare grant_type='authorization_code'
declare auth_req_id=''
declare http_basic=0
declare form_post=0
declare kid=''
declare private_pem=''
declare dpop_pem_file=''
declare token_endpoint_path='oauth/token'
declare code_type='code'
declare opt_verbose=''
declare opt_disable_discovery=0
declare content_type='application/json'

[[ -f "${DIR}/.env" ]] && . "${DIR}/.env"

while getopts "e:t:d:c:u:a:x:X:P:C:r:U:k:K:A:Dbphv?" opt; do
  case ${opt} in
  e) source "${OPTARG}" ;;
  t) AUTH0_DOMAIN=$(echo ${OPTARG}.auth0.com | tr '@' '.') ;;
  d) AUTH0_DOMAIN=${OPTARG} ;;
  c) AUTH0_CLIENT_ID=${OPTARG} ;;
  x) AUTH0_CLIENT_SECRET=${OPTARG} ;;
  u) AUTH0_REDIRECT_URI=${OPTARG} ;;
  a) authorization_code=${OPTARG} ;;
  X) code_verifier=${OPTARG} ;;
  P) dpop_pem_file=${OPTARG} ;;
  U) token_endpoint_path=${OPTARG} ;;
  k) kid=${OPTARG} ;;
  K) private_pem=${OPTARG} ;;
  A) alg=${OPTARG} ;;
  C) code_type='device_code'; grant_type='urn:ietf:params:oauth:grant-type:device_code'; authorization_code=${OPTARG} ;;
  r) code_type='auth_req_id'; grant_type='urn:openid:params:grant-type:ciba'; authorization_code=${OPTARG} ;;
  D) opt_disable_discovery=1 ;;
  b) http_basic=1 ;;
  p) form_post=1; content_type='application/x-www-form-urlencoded' ;;
  v) opt_verbose=1;; #set -x ;;
  h | ?) usage 0 ;;
  *) usage 1 ;;
  esac
done

[[ -z "${AUTH0_DOMAIN}" ]] && { echo >&2 "ERROR: AUTH0_DOMAIN undefined"; usage 1; }
[[ -z "${AUTH0_CLIENT_ID}" ]] && { echo >&2 "ERROR: AUTH0_CLIENT_ID undefined"; usage 1; }
[[ -z "${AUTH0_REDIRECT_URI}" ]] && { echo >&2 "ERROR: AUTH0_REDIRECT_URI undefined"; usage 1; }
[[ -z "${authorization_code}" ]] && { echo >&2 "ERROR: authorization_code undefined"; usage 1; }

[[ ${AUTH0_DOMAIN} =~ ^http ]] || AUTH0_DOMAIN=https://${AUTH0_DOMAIN}

declare token_endpoint="${AUTH0_DOMAIN}/${token_endpoint_path}"
declare issuer="${AUTH0_DOMAIN}"
[[ ${issuer} =~ /$ ]] || issuer="${issuer}/"

declare secret=''
declare authorization_header=''
declare dpop_header=''

declare assertion=''

# OIDC Discovery to resolve token endpoint (unless disabled via -D)
if [[ ${opt_disable_discovery} -eq 0 ]]; then
  declare discovery_json
  discovery_json=$(curl -s -k --header "accept: application/json" --url "${AUTH0_DOMAIN}/.well-known/openid-configuration" || true)

  declare d_token=$(echo "${discovery_json}" | jq -r '.token_endpoint // empty')
  declare d_issuer=$(echo "${discovery_json}" | jq -r '.issuer // empty')

  [[ -n "${d_issuer}" ]] && issuer="${d_issuer}"
  [[ -n "${d_token}" ]] && token_endpoint="${d_token}"
fi

if [[ ${http_basic} -eq 1 ]]; then
  authorization_header="Authorization: Basic "
  authorization_header+=$(printf "%s:%s" "${AUTH0_CLIENT_ID}" "${AUTH0_CLIENT_SECRET}" | openssl base64 -e -A)
else
  [[ -n "${AUTH0_CLIENT_SECRET}" ]] && secret="\"client_secret\":\"${AUTH0_CLIENT_SECRET}\","
  [[ -n "${code_verifier}" ]] && secret+="\"code_verifier\":\"${code_verifier}\","
fi

if [[ -n "${kid}" && -n "${private_pem}" && -f "${private_pem}" ]]; then
  readonly assertion=$(./client-assertion.sh -a "${issuer}" -i "${AUTH0_CLIENT_ID}" -k "${kid}" -f "${private_pem}" -A "${alg}" )
  readonly client_assertion=$(cat <<EOL
    , "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion" : "${assertion}"
EOL
  )
else
  readonly client_assertion=''
fi

declare BODY=$(cat <<EOL
{
    "client_id":"${AUTH0_CLIENT_ID}",
    ${secret}
    "${code_type}": "${authorization_code}",
    "grant_type":"${grant_type}",
    "scope":"openid",
    "redirect_uri": "${AUTH0_REDIRECT_URI}"
${client_assertion}
}
EOL
)

if [[ -n "${dpop_pem_file}" ]]; then
    dpop_header="DPoP: $(./dpop.sh -r "${dpop_pem_file}" -m POST -u "${token_endpoint}")"
    [[ -n "${opt_verbose}" ]] && echo "${dpop_header}"
fi

if [[ ${form_post} -eq 1 ]]; then
  BODY=$(echo "${BODY}" | jq -r 'to_entries | map("\(.key)=\(.value|tostring|@uri)") | join("&")')
fi

# Verbose output of body
if [[ -n "${opt_verbose}" ]]; then
  echo "${BODY}"
fi

curl -s --request POST \
  -H "${authorization_header}" \
  -H "${dpop_header}" \
  --url "${token_endpoint}" \
  --header "content-type: ${content_type}" \
  --data "${BODY}" | jq .

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
USAGE: $0 [-e env] [-t tenant] [-d domain] [-c client_id] [-x client_secret] [-X code_verifier] [-P dpop.pem] [-u callback] [-a authorization_code] [-p] [-v|-h]
        -e file        # .env file location (default cwd)
        -t tenant      # Auth0 tenant@region
        -d domain      # Auth0 domain
        -c client_id   # Auth0 client ID
        -x secret      # Auth0 client secret
        -X verifier    # PKCE code_verifier
        -a code        # Authorization Code to exchange
        -r req_id      # back channel authorization (CIBA) auth_req_id
        -D code        # Device Code to exchange
        -u callback    # callback URL
        -U endpoint    # token endpoint URI (default is 'oauth/token')
        -k kid         # client public key JWT-CA key id
        -K private.pem # JWT-CA client private key file for client assertion
        -A alg         # JWT-CA algorithm. default ${alg}. supports: RS256, ES256, PS256
        -P private.pem # DPoP EC private key PEM file
        -b             # HTTP Basic authentication (default is secret in payload)
        -p             # HTTP form post (default is application/json)
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
declare token_endpoint='oauth/token'
declare code_type='code'
declare opt_verbose=''

[[ -f "${DIR}/.env" ]] && . "${DIR}/.env"

while getopts "e:t:d:c:u:a:x:X:P:D:r:U:k:K:A:bphv?" opt; do
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
  U) token_endpoint=${OPTARG} ;;
  k) kid=${OPTARG} ;;
  K) private_pem=${OPTARG} ;;
  A) alg=${OPTARG} ;;
  D) code_type='device_code'; grant_type='urn:ietf:params:oauth:grant-type:device_code'; authorization_code=${OPTARG} ;;
  r) code_type='auth_req_id'; grant_type='urn:openid:params:grant-type:ciba'; authorization_code=${OPTARG} ;;
  b) http_basic=1 ;;
  p) form_post=1 ;;
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
#[[ ${AUTH0_DOMAIN} =~ /$ ]] || AUTH0_DOMAIN="${AUTH0_DOMAIN}/" # conflicts with jwt-ca audience

declare secret=''
declare authorization_header=''
declare dpop_header=''

declare assertion=''

if [[ ${http_basic} -eq 1 ]]; then
  authorization_header=$(printf "%s:%s" "${AUTH0_CLIENT_ID}" "${AUTH0_CLIENT_SECRET}" | openssl base64 -e -A)
else
  [[ -n "${AUTH0_CLIENT_SECRET}" ]] && secret="\"client_secret\":\"${AUTH0_CLIENT_SECRET}\","
  [[ -n "${code_verifier}" ]] && secret+="\"code_verifier\":\"${code_verifier}\","
fi

if [[ -n "${kid}" && -n "${private_pem}" && -f "${private_pem}" ]]; then
  readonly assertion=$(./client-assertion.sh -a "${AUTH0_DOMAIN}" -i "${AUTH0_CLIENT_ID}" -k "${kid}" -f "${private_pem}" -A "${alg}" )
  readonly client_assertion=$(cat <<EOL
    , "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion" : "${assertion}"
EOL
  )
else
  readonly client_assertion=''
fi

declare -r BODY=$(cat <<EOL
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
    dpop_header="DPoP: $(./dpop.sh -r "${dpop_pem_file}" -m POST -u "${AUTH0_DOMAIN}${token_endpoint}")"
    [[ -n "${opt_verbose}" ]] && echo "${dpop_header}"
fi

# Verbose output of body
if [[ -n "${opt_verbose}" ]]; then
  echo "${BODY}"
fi

if [[ ${form_post} -eq 1 ]]; then
  # FORM-ENCODED request
  readonly BODY_FORM=$(echo "${BODY}" | jq -r 'to_entries | map("\(.key)=\(.value|tostring|@uri)") | join("&")')
  [[ -n "${opt_verbose}" ]] && echo "${BODY_FORM}"

  if [[ ${http_basic} -eq 1 ]]; then
    curl -s --request POST \
      -H "Authorization: Basic ${authorization_header}" \
      -H "${dpop_header}" \
      --url "${AUTH0_DOMAIN}/${token_endpoint}" \
      --header 'content-type: application/x-www-form-urlencoded' \
      --data "${BODY_FORM}" | jq .
  else
    curl -v --request POST \
      -H "${dpop_header}" \
      --url "${AUTH0_DOMAIN}/${token_endpoint}" \
      --header 'content-type: application/x-www-form-urlencoded' \
      --data "${BODY_FORM}" | jq .
  fi
else
  # JSON request (default)
  if [[ ${http_basic} -eq 1 ]]; then
    curl -s --request POST \
      -H "Authorization: Basic ${authorization_header}" \
      -H "${dpop_header}" \
      --url "${AUTH0_DOMAIN}/${token_endpoint}" \
      --header 'content-type: application/json' \
      --data "${BODY}" | jq .
  else
    curl -s --request POST \
      -H "${dpop_header}" \
      --url "${AUTH0_DOMAIN}/${token_endpoint}" \
      --header 'content-type: application/json' \
      --data "${BODY}" | jq .
  fi
fi

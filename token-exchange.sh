#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2022-06-12
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/main/LICENSE)
##########################################################################################

set -eo pipefail

command -v curl >/dev/null || { echo >&2 "error: curl not found";  exit 3; }
command -v jq >/dev/null || {  echo >&2 "error: jq not found";  exit 3; }
DIR="${BASH_SOURCE[0]%/*}"
[ "$DIR" = "${BASH_SOURCE[0]}" ] && DIR="."
readonly DIR

declare SCOPE='openid profile email'

function usage() {
    cat <<END >&2
USAGE: $0 [-e env] [-t tenant] [-d domain] [-c client_id] [-x client_secret] [-k kid] [-K private.pem] [-i subject_token] [-I type] [-u name] [-U name] [-g grant_type] [-G name] [-A assertion] [-a audience] [-r resource] [-s scope] [-R|-J|-f realm|-p|-D|-h|-v]
        -e file               # .env file location (default cwd)
        -t tenant             # tenant@region shorthand (Auth0-style, appends .auth0.com)
        -d domain             # OIDC provider domain
        -c client_id          # OAuth2/OIDC client ID
        -x secret             # OAuth2/OIDC client secret
        -k kid                # client public key JWT-CA key id
        -K private.pem        # JWT-CA client private key file for client assertion
        -i subject_token      # subject_token value
        -I type               # full subject_token_type (URN or custom URI, e.g. http://acme.com/legacy-token)
        -u name               # shortcut: subject_token_type   = urn:ietf:params:oauth:token-type:\$name
        -U name               # shortcut: requested_token_type = urn:ietf:params:oauth:token-type:\$name
        -g grant_type         # full grant_type (URN or custom URI)
        -G name               # shortcut: grant_type = urn:ietf:params:oauth:grant-type:\$name
        -A assertion          # assertion value (added as "assertion" in request body)
        -R                    # shortcut: subject is refresh_token (= -u refresh_token)
        -J                    # ID-JAG mode: subject=id_token, requested=id-jag
        -f realm              # FCAT (Token Vault) mode + connection name (Auth0-specific grant/token-type)
        -p                    # HTTP form post (default is application/json)
        -D                    # disable OIDC discovery; use default endpoint /oauth/token
        -a audience           # Audience
        -r resource           # Resource (RFC-8707 / RFC-8693 resource parameter)
        -s scopes             # comma separated list of scopes (default is "${SCOPE}")
        -h|?                  # usage
        -v                    # verbose

eg,
     $0 -t amin01@au -c client_id -x client_secret -i ey... -A -a newapi -s read:things
END
    exit "$1"
}

declare DOMAIN=''
declare CLIENT_ID=''
declare CLIENT_SECRET=''
declare AUDIENCE=''

declare subject_token=''
declare subject_token_type=''
declare requested_token_type=''
declare realm=''
declare resource=''
declare assertion=''
declare kid=''
declare private_pem=''

declare grant_type='urn:ietf:params:oauth:grant-type:token-exchange'
declare opt_verbose=''
declare form_post=0
declare content_type='application/json'
declare opt_disable_discovery=0

[[ -f "${DIR}/.env" ]] && . "${DIR}/.env"

while getopts "e:t:d:c:x:k:K:a:i:I:u:U:g:G:A:s:f:r:RJpDhv?" opt; do
    case ${opt} in
    e) source "${OPTARG}" ;;
    t) DOMAIN=$(echo "${OPTARG}.auth0.com" | tr '@' '.') ;;
    d) DOMAIN=${OPTARG} ;;
    c) CLIENT_ID=${OPTARG} ;;
    x) CLIENT_SECRET=${OPTARG} ;;
    k) kid=${OPTARG} ;;
    K) private_pem=${OPTARG} ;;
    a) AUDIENCE=${OPTARG} ;;
    r) resource=${OPTARG} ;;
    i) subject_token=${OPTARG} ;;
    I) subject_token_type=${OPTARG} ;;
    u) subject_token_type="urn:ietf:params:oauth:token-type:${OPTARG}" ;;
    U) requested_token_type="urn:ietf:params:oauth:token-type:${OPTARG}" ;;
    g) grant_type=${OPTARG} ;;
    G) grant_type="urn:ietf:params:oauth:grant-type:${OPTARG}" ;;
    A) assertion=${OPTARG} ;;
    R) subject_token_type='urn:ietf:params:oauth:token-type:refresh_token' ;;
    J) subject_token_type='urn:ietf:params:oauth:token-type:id_token';
       requested_token_type='urn:ietf:params:oauth:token-type:id-jag' ;;
    s) SCOPE=$(echo "${OPTARG}" | tr ',' ' ') ;;
    f) grant_type='urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token';
       requested_token_type='http://auth0.com/oauth/token-type/federated-connection-access-token';
       realm=${OPTARG} ;;
    p) form_post=1; content_type='application/x-www-form-urlencoded' ;;
    D) opt_disable_discovery=1 ;;
    v) opt_verbose=1 ;; #set -x;;
    h | ?) usage 0 ;;
    *) usage 1 ;;
    esac
done

[[ -z "${DOMAIN}" ]] && {  echo >&2 "ERROR: DOMAIN undefined";  usage 1;  }
[[ -z "${CLIENT_ID}" ]] && { echo >&2 "ERROR: CLIENT_ID undefined";  usage 1; }

[[ ${DOMAIN} =~ ^http ]] || DOMAIN=https://${DOMAIN}

declare token_endpoint="${DOMAIN}/oauth/token"
declare issuer="${DOMAIN}"
[[ ${issuer} =~ /$ ]] || issuer="${issuer}/"

if [[ ${opt_disable_discovery} -eq 0 ]]; then
  declare discovery_json
  discovery_json=$(curl -s -k --header "accept: application/json" --url "${DOMAIN}/.well-known/openid-configuration" || true)
  declare d_token
  d_token=$(echo "${discovery_json}" | jq -r '.token_endpoint // empty')
  declare d_issuer
  d_issuer=$(echo "${discovery_json}" | jq -r '.issuer // empty')
  [[ -n "${d_token}" ]] && token_endpoint="${d_token}"
  [[ -n "${d_issuer}" ]] && issuer="${d_issuer}"
fi

if [[ "${subject_token_type}" == 'urn:ietf:params:oauth:token-type:saml2' && -n "${subject_token}" ]]; then
  declare saml_raw_xml=0
  declare saml_xml=''

  if [[ "${subject_token}" == '<'* ]]; then
    saml_raw_xml=1
    saml_xml="${subject_token}"
  else
    saml_xml=$(printf '%s' "${subject_token}" | base64 -d 2>/dev/null) || saml_xml=''
  fi

  if [[ -n "${saml_xml}" && "${saml_xml}" =~ \<[A-Za-z0-9]*:?Response ]]; then
    command -v xmllint >/dev/null || { echo >&2 "error: xmllint not found (required to extract SAML2 Assertion from Response)"; exit 3; }
    declare saml_assertion
    saml_assertion=$(printf '%s' "${saml_xml}" | xmllint --nsclean --xpath "//*[local-name()='Assertion']" - 2>/dev/null) || saml_assertion=''
    [[ -z "${saml_assertion}" ]] && { echo >&2 "ERROR: unable to locate <Assertion> element inside SAML2 Response"; exit 1; }
    subject_token=$(printf '%s' "${saml_assertion}" | base64 | tr -d '\n')
  elif [[ ${saml_raw_xml} -eq 1 ]]; then
    subject_token=$(printf '%s' "${subject_token}" | base64 | tr -d '\n')
  fi
  # else: subject_token is already a base64-encoded SAML2 Assertion; pass through unchanged
fi

declare client_assertion=''
declare client_assertion_type=''
if [[ -n "${kid}" && -n "${private_pem}" && -f "${private_pem}" ]]; then
  declare jwt_ca_assertion
  # TODO: remove hardcoded /oauth2/v1/token
  jwt_ca_assertion=$("${DIR}"/jwt/client-assertion.sh -a "${issuer}/oauth2/v1/token" -i "${CLIENT_ID}" -k "${kid}" -f "${private_pem}")
  client_assertion="${jwt_ca_assertion}"
  client_assertion_type='urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
fi

declare BODY
BODY=$(jq -n \
  --arg grant_type "${grant_type}" \
  --arg client_id "${CLIENT_ID}" \
  --arg client_secret "${CLIENT_SECRET}" \
  --arg subject_token "${subject_token}" \
  --arg subject_token_type "${subject_token_type}" \
  --arg requested_token_type "${requested_token_type}" \
  --arg audience "${AUDIENCE}" \
  --arg resource "${resource}" \
  --arg connection "${realm}" \
  --arg scope "${SCOPE}" \
  --arg assertion "${assertion}" \
  --arg client_assertion "${client_assertion}" \
  --arg client_assertion_type "${client_assertion_type}" \
  '{
     grant_type: $grant_type,
     client_id: $client_id,
     client_secret: $client_secret,
     subject_token: $subject_token,
     subject_token_type: $subject_token_type,
     requested_token_type: $requested_token_type,
     audience: $audience,
     resource: $resource,
     connection: $connection,
     scope: $scope,
     assertion: $assertion,
     client_assertion: $client_assertion,
     client_assertion_type: $client_assertion_type
   } | with_entries(select(.value != ""))')

if [[ -n "${opt_verbose}" ]]; then
  echo >&2 "> POST ${token_endpoint}"
  echo "$BODY" | jq . >&2
fi

if [[ ${form_post} -eq 1 ]]; then
  BODY=$(echo "${BODY}" | jq -r 'to_entries | map("\(.key)=\(.value|tostring|@uri)") | join("&")')
fi

curl -s -k -H "content-type: ${content_type}" \
    -d "${BODY}" \
    --url "${token_endpoint}" | jq .

echo

#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2022-06-12
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/master/LICENSE)
##########################################################################################

set -eo pipefail

command -v curl >/dev/null || { echo >&2 "error: curl not found";  exit 3; }
command -v jq >/dev/null || {  echo >&2 "error: jq not found";  exit 3; }
readonly DIR=$(dirname "${BASH_SOURCE[0]}")

declare AUTH0_SCOPE='openid profile email'

function usage() {
    cat <<END >&2
USAGE: $0 [-e env] [-t tenant] [-d domain] [-c client_id] [-x client_secret] [-i subject_token] [-I type] [-u name] [-U name] [-a audience] [-r resource] [-s scope] [-A|-R|-J|-f realm|-p|-D|-h|-v]
        -e file               # .env file location (default cwd)
        -t tenant             # Auth0 tenant@region
        -d domain             # Auth0 domain
        -c client_id          # Auth0 client ID
        -x secret             # Auth0 client secret
        -i subject_token      # subject_token value
        -I type               # full subject_token_type (URN or custom URI, e.g. http://acme.com/legacy-token)
        -u name               # shortcut: subject_token_type   = urn:ietf:params:oauth:token-type:\$name
        -U name               # shortcut: requested_token_type = urn:ietf:params:oauth:token-type:\$name
        -A                    # shortcut: subject is access_token  (= -u access_token)
        -R                    # shortcut: subject is refresh_token (= -u refresh_token)
        -J                    # ID-JAG mode: subject=id_token, requested=id-jag
        -f realm              # FCAT (Token Vault) mode + connection name
        -p                    # HTTP form post (default is application/json)
        -D                    # disable OIDC discovery; use default endpoint /oauth/token
        -a audience           # Audience
        -r resource           # Resource (RFC-8707 / RFC-8693 resource parameter)
        -s scopes             # comma separated list of scopes (default is "${AUTH0_SCOPE}")
        -h|?                  # usage
        -v                    # verbose

eg,
     $0 -t amin01@au -c client_id -x client_secret -i ey... -A -a newapi -s read:things
END
    exit $1
}

declare AUTH0_DOMAIN=''
declare AUTH0_CLIENT_ID=''
declare AUTH0_CLIENT_SECRET=''
declare AUTH0_AUDIENCE=''

declare subject_token=''
declare subject_token_type=''
declare requested_token_type=''
declare realm=''
declare resource=''

declare grant_type='urn:ietf:params:oauth:grant-type:token-exchange'
declare opt_verbose=0
declare form_post=0
declare content_type='application/json'
declare opt_disable_discovery=0

[[ -f "${DIR}/.env" ]] && . "${DIR}/.env"

while getopts "e:t:d:c:x:a:i:I:u:U:s:f:r:ARJpDhv?" opt; do
    case ${opt} in
    e) source "${OPTARG}" ;;
    t) AUTH0_DOMAIN=$(echo "${OPTARG}.auth0.com" | tr '@' '.') ;;
    d) AUTH0_DOMAIN=${OPTARG} ;;
    c) AUTH0_CLIENT_ID=${OPTARG} ;;
    x) AUTH0_CLIENT_SECRET=${OPTARG} ;;
    a) AUTH0_AUDIENCE=${OPTARG} ;;
    r) resource=${OPTARG} ;;
    i) subject_token=${OPTARG} ;;
    I) subject_token_type=${OPTARG} ;;
    u) subject_token_type="urn:ietf:params:oauth:token-type:${OPTARG}" ;;
    U) requested_token_type="urn:ietf:params:oauth:token-type:${OPTARG}" ;;
    A) subject_token_type='urn:ietf:params:oauth:token-type:access_token' ;;
    R) subject_token_type='urn:ietf:params:oauth:token-type:refresh_token' ;;
    J) subject_token_type='urn:ietf:params:oauth:token-type:id_token';
       requested_token_type='urn:ietf:params:oauth:token-type:id-jag' ;;
    s) AUTH0_SCOPE=$(echo "${OPTARG}" | tr ',' ' ') ;;
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

[[ -z "${AUTH0_DOMAIN}" ]] && {  echo >&2 "ERROR: AUTH0_DOMAIN undefined";  usage 1;  }
[[ -z "${AUTH0_CLIENT_ID}" ]] && { echo >&2 "ERROR: AUTH0_CLIENT_ID undefined";  usage 1; }

[[ -z "${subject_token_type}" ]] && { echo >&2 "ERROR: subject_token_type undefined";  usage 1; }
[[ -z "${subject_token}" ]] && { echo >&2 "ERROR: subject_token undefined";  usage 1; }

declare secret_field=''
[[ -n "${AUTH0_CLIENT_SECRET}" ]] && secret_field="\"client_secret\": \"${AUTH0_CLIENT_SECRET}\", "

declare audience_field=''
[[ -n "${AUTH0_AUDIENCE}" ]] && audience_field="\"audience\": \"${AUTH0_AUDIENCE}\", "

declare requested_token_type_field=''
[[ -n "${requested_token_type}" ]] && requested_token_type_field="\"requested_token_type\": \"${requested_token_type}\", "

declare realm_field=''
[[ -n "${realm}" ]] && realm_field="\"connection\": \"${realm}\", "

declare resource_field=''
[[ -n "${resource}" ]] && resource_field="\"resource\": \"${resource}\", "

[[ ${AUTH0_DOMAIN} =~ ^http ]] || AUTH0_DOMAIN=https://${AUTH0_DOMAIN}

declare token_endpoint="${AUTH0_DOMAIN}/oauth/token"

if [[ ${opt_disable_discovery} -eq 0 ]]; then
  declare discovery_json
  discovery_json=$(curl -s -k --header "accept: application/json" --url "${AUTH0_DOMAIN}/.well-known/openid-configuration" || true)
  declare d_token=$(echo "${discovery_json}" | jq -r '.token_endpoint // empty')
  [[ -n "${d_token}" ]] && token_endpoint="${d_token}"
fi

#            "scope": "${AUTH0_SCOPE}",

declare BODY=$(cat <<EOL
{
            "grant_type": "${grant_type}",
            "subject_token" : "${subject_token}",
            "subject_token_type" : "${subject_token_type}",
            ${audience_field}
            ${resource_field}
            ${requested_token_type_field}
            ${secret_field}
            ${realm_field}
            "client_id": "${AUTH0_CLIENT_ID}"
}
EOL
)

echo $BODY | jq .

if [[ ${form_post} -eq 1 ]]; then
  BODY=$(echo "${BODY}" | jq -r 'to_entries | map("\(.key)=\(.value|tostring|@uri)") | join("&")')
fi

curl -k -H "content-type: ${content_type}" \
    -d "${BODY}" \
    --url "${token_endpoint}"

echo
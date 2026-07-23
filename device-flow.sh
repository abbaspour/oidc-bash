#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2022-06-12
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/master/LICENSE)
##########################################################################################

set -ueo pipefail

function usage() {
    cat <<END >&2
USAGE: $0 [-e env] [-t tenant] [-d domain] [-c client_id] [-s scopes] [-a audience] [-M|-v|-h]
        -e file        # .env file location (default cwd)
        -t tenant      # tenant@region shorthand (Auth0-style, appends .auth0.com)
        -d domain      # OIDC provider domain
        -c client_id   # OAuth2/OIDC client ID
        -s scopes      # scope1,scope2,etc
        -a audience    # API audience
        -M             # Management API audience
        -h|?           # usage
        -v             # verbose

eg,
     $0 -t amin01@au -c aIioQEeY7nJdX78vcQWDBcAqTABgKnZl
END
    exit $1
}

declare DOMAIN=''
declare CLIENT_ID=''

declare opt_verbose=0
declare opt_mgmnt=''

declare audience_field=''
declare scopes_field=''

while getopts "e:t:d:c:a:s:Mhv?" opt; do
    case ${opt} in
    e) source "${OPTARG}" ;;
    t) DOMAIN=$(echo "${OPTARG}.auth0.com" | tr '@' '.') ;;
    d) DOMAIN=${OPTARG} ;;
    c) CLIENT_ID=${OPTARG} ;;
    s)
        scopes=$(echo ${OPTARG} | tr , ' ')
        scopes_field=",\"scope\":\"${scopes}\""
        ;;
    a) audience_field=",\"audience\":\"${OPTARG}\"" ;;
    M) opt_mgmnt=1 ;;
    v) opt_verbose=1 ;; #set -x;;
    h | ?) usage 0 ;;
    *) usage 1 ;;
    esac
done

[[ -z "${DOMAIN}" ]] && {  echo >&2 "ERROR: DOMAIN undefined";  usage 1;  }
[[ -z "${CLIENT_ID}" ]] && { echo >&2 "ERROR: CLIENT_ID undefined";  usage 1; }


[[ -n "${opt_mgmnt}" ]] && audience_field=",\"audience\":\"https://${DOMAIN}/api/v2/\""

declare BODY
BODY=$(cat <<EOL
{
    "client_id":"${CLIENT_ID}"
    ${audience_field}
    ${scopes_field}
}
EOL
)

if [[ -n "${opt_verbose}" ]]; then
    echo >&2 "> POST https://${DOMAIN}/oauth/device/code"
    echo "${BODY}" | jq . >&2
fi

curl -ss --header 'content-type: application/json' -d "${BODY}" https://${DOMAIN}/oauth/device/code | jq .

echo -e "\n Polling:\n ./exchange.sh -d ${DOMAIN} -c ${CLIENT_ID} -D DEVICE_CODE"

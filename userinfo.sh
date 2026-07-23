#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2022-06-12
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/master/LICENSE)
##########################################################################################

function usage() {
    cat <<END >&2
USAGE: $0 [-e env] [-t tenant] [-d domain] [-a access_token] [-v|-h]
        -e file        # .env file location (default cwd)
        -t tenant      # tenant@region shorthand (Auth0-style, appends .auth0.com) (for opaque tokens)
        -d domain      # OIDC provider domain (for opaque tokens)
        -a token       # Access Token (default is access_token env variable)
        -h|?           # usage
        -v             # verbose

eg,
     $0 -t amin01@au -a J7REwk4c6tJo29jmMV0AZZ79vBd8_qTz
END
    exit "$1"
}

declare DOMAIN=''

declare opt_verbose=0

while getopts "e:t:d:a:hv?" opt; do
    case ${opt} in
    e) source "${OPTARG}" ;;
    t) DOMAIN=$(echo "${OPTARG}.auth0.com" | tr '@' '.') ;;
    d) DOMAIN=${OPTARG} ;;
    a) access_token=${OPTARG} ;;
    v) opt_verbose=1 ;; #set -x;;
    h | ?) usage 0 ;;
    *) usage 1 ;;
    esac
done

[[ -z "${access_token}" ]] && { echo >&2 "ERROR: access_token undefined. export access_token='PASTE' ";  usage 1; }

declare DOMAIN_URL
DOMAIN_URL=$(jq -Rr 'split(".")[1] | gsub("-";"+") | gsub("_";"/") | gsub("%3D";"=") | @base64d | fromjson | .iss // empty' <<< "${access_token}")

if [[ -z "${DOMAIN_URL}" ]]; then
  [[ -z "${DOMAIN}" ]] && {  echo >&2 "ERROR: DOMAIN undefined";  usage 1;  }
  [[ ${DOMAIN} =~ ^http ]] || DOMAIN=https://${DOMAIN}
  DOMAIN_URL="${DOMAIN}/"
fi

[[ -n "${opt_verbose}" ]] && echo >&2 "> GET ${DOMAIN_URL}userinfo"

curl -s -H "Authorization: Bearer ${access_token}" "${DOMAIN_URL}userinfo" | jq '.'

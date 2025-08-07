#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2022-06-12
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/master/LICENSE)
##########################################################################################

function usage() {
    cat <<END >&2
USAGE: $0 [-e env] [-a access_token] [-o|-h]
        -e file        # .env file location (default cwd)
        -t tenant      # Auth0 tenant@region (for opaque tokens)
        -d domain      # Auth0 domain (for opaque tokens)
        -a token       # Access Token (default is access_token env variable)
        -h|?           # usage
        -v             # verbose

eg,
     $0 -t amin01@au -a J7REwk4c6tJo29jmMV0AZZ79vBd8_qTz
END
    exit $1
}

declare AUTH0_DOMAIN=''

declare opt_verbose=0

while getopts "e:t:d:a::hv?" opt; do
    case ${opt} in
    e) source ${OPTARG} ;;
    t) AUTH0_DOMAIN=$(echo ${OPTARG}.auth0.com | tr '@' '.') ;;
    d) AUTH0_DOMAIN=${OPTARG} ;;
    a) access_token=${OPTARG} ;;
    v) opt_verbose=1 ;; #set -x;;
    h | ?) usage 0 ;;
    *) usage 1 ;;
    esac
done

[[ -z "${access_token}" ]] && { echo >&2 "ERROR: access_token undefined. export access_token='PASTE' ";  usage 1; }

declare -r AUTH0_DOMAIN_URL=$(jq -Rr 'split(".") | .[1] | @base64d | fromjson | .iss // empty' <<< "${access_token}")

if [[ -z "${AUTH0_DOMAIN_URL}" ]]; then
  [[ -z "${AUTH0_DOMAIN}" ]] && {  echo >&2 "ERROR: AUTH0_DOMAIN undefined";  usage 1;  }
  [[ ${AUTH0_DOMAIN} =~ ^http ]] || AUTH0_DOMAIN=https://${AUTH0_DOMAIN}
  AUTH0_DOMAIN_URL="${AUTH0_DOMAIN}/"
fi

curl -s -H "Authorization: Bearer ${access_token}" "${AUTH0_DOMAIN_URL}userinfo" | jq '.'

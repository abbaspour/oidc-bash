#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2024-06-27
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/main/LICENSE)
#
##########################################################################################

# TODO: add a flag to read from apple CDN cache: https://app-site-association.cdn-apple.com/a/v1/{website}

set -eo pipefail

command -v curl >/dev/null || { echo >&2 "error: curl not found";  exit 3; }
command -v jq >/dev/null || {  echo >&2 "error: jq not found";  exit 3; }

function usage() {
    cat <<END >&2
USAGE: $0 [-e file] [-t tenant] [-d domain]
        -e file        # .env file location (default cwd)
        -t tenant      # tenant@region shorthand (Auth0-style, appends .auth0.com)
        -d domain      # OIDC provider domain
        -h|?           # usage
        -v             # verbose

eg,
     $0 -t amin01@au
END
    exit "$1"
}

declare DOMAIN=''
declare opt_verbose=0

while getopts "e:t:d:hv?" opt; do
    case ${opt} in
    e) source "${OPTARG}" ;;
    t) DOMAIN=$(echo "${OPTARG}.auth0.com" | tr '@' '.') ;;
    d) DOMAIN=${OPTARG} ;;
    v) opt_verbose=1 ;; #set -x;;
    h | ?) usage 0 ;;
    *) usage 1 ;;
    esac
done

[[ -z "${DOMAIN}" ]] && {  echo >&2 "ERROR: DOMAIN undefined";  usage 1;  }

[[ -n "${opt_verbose}" ]] && echo >&2 "> GET https://${DOMAIN}/.well-known/apple-app-site-association"

curl -s "https://${DOMAIN}/.well-known/apple-app-site-association" | jq '.'

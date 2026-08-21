#!/usr/bin/env bash
# shellcheck disable=SC2154

##########################################################################################
# Author: Amin Abbaspour
# Date: 2022-06-12
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/main/LICENSE)
##########################################################################################

command -v jq >/dev/null || { echo >&2 "error: jq not found"; exit 3; }

if [[ $# -ge 1 ]]; then
    jwt=$1
elif [[ ! -t 0 ]]; then
    read -r jwt
else
    jwt=$access_token
fi

jq -Rr 'split(".")[1] | gsub("-";"+") | gsub("_";"/") | gsub("%3D";"=") | @base64d | fromjson' <<<"${jwt}"

#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2022-06-12
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/master/LICENSE)
##########################################################################################

set -eo pipefail

command -v jq >/dev/null || {  echo >&2 "error: jq not found";  exit 3; }

function usage() {
    cat <<END >&2
USAGE: $0 [-e env] [-t tenant] [-d domain] [-c client_id] [-i id_token] [-b browser] [-f|-C|-o|-h]
        -e file        # .env file location (default cwd)
        -t tenant      # tenant@region shorthand (Auth0-style, appends .auth0.com)
        -d domain      # OIDC provider domain
        -c client_id   # OAuth2/OIDC client ID
        -u callback    # callback URL (returnTo)
        -f             # federated logout
        -i id_token    # id_token_hint (for RP initiated logout)
        -s hint        # sid or user_id logout hint (for RP initiated logout)
        -C             # copy to clipboard
        -o             # Open URL
        -b browser     # Choose browser to open (firefox, chrome, safari)
        -h|?           # usage
        -v             # verbose

eg,
     $0 -t amin01@au -f -o -b firefox
END
    exit "$1"
}

declare opt_federated=0
declare opt_rp_initiated=0
declare id_token_hint=''
declare logout_hint=''
declare -a opt_browser=()

while getopts "e:t:d:c:u:b:i:s:fCohv?" opt; do
    case ${opt} in
    e) source "${OPTARG}" ;;
    t) DOMAIN=$(echo "${OPTARG}.auth0.com" | tr '@' '.') ;;
    d) DOMAIN=${OPTARG} ;;
    c) CLIENT_ID=${OPTARG} ;;
    u) REDIRECT_URI=${OPTARG} ;;
    i) id_token_hint=${OPTARG}; opt_rp_initiated=1 ;;
    s) logout_hint=${OPTARG}; opt_rp_initiated=1 ;;
    C) opt_clipboard=1 ;;
    o) opt_open=1 ;;
    f) opt_federated=1 ;;
    b) opt_browser=(-a "${OPTARG}") ;;
    v) ;; #set -x;;
    h | ?) usage 0 ;;
    *) usage 1 ;;
    esac
done

[[ -z ${DOMAIN+x} ]] && {
  if [[ -n "${id_token_hint}" ]]; then
      DOMAIN=$(jq -Rr 'split(".")[1] | gsub("-";"+") | gsub("_";"/") | gsub("%3D";"=") | @base64d | fromjson | .iss' <<<"${id_token_hint}")
  else
    echo >&2 "ERROR: DOMAIN undefined";  usage 1;
  fi
}

[[ ${DOMAIN} =~ ^http ]] || DOMAIN=https://${DOMAIN}
[[ ${DOMAIN} =~ \/$ ]] || DOMAIN+='/'

declare logout_url

if [[ -n "${opt_rp_initiated}" ]]; then
  logout_url="${DOMAIN}oidc/logout?"

  [[ -n "${id_token_hint}" ]] && logout_url+="id_token_hint=${id_token_hint}&"
  [[ -n "${logout_hint}" ]] && {
    [[ -n "${CLIENT_ID}" ]] || { echo >&2 "ERROR: client_id required for logout with logout_hint";  usage 1;  }
    logout_url+="client_id=${CLIENT_ID}&logout_hint=${logout_hint}&"
  }
else
  logout_url="${DOMAIN}v2/logout?"

  [[ ${opt_federated} -ne 0 ]] && logout_url+="federated&"
  [[ -n "${CLIENT_ID}" ]] && logout_url+="client_id=${CLIENT_ID}&"
  [[ -n "${REDIRECT_URI}" ]] && logout_url+="returnTo=$(urlencode "${REDIRECT_URI}")&"
fi


echo "${logout_url}"

[[ -n "${opt_clipboard}" ]] && echo "${logout_url}" | pbcopy
[[ -n "${opt_open}" ]] && open "${opt_browser[@]}" "${logout_url}"

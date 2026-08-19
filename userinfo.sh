#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2022-06-12
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/main/LICENSE)
##########################################################################################

DIR="${BASH_SOURCE[0]%/*}"
[ "$DIR" = "${BASH_SOURCE[0]}" ] && DIR="."
readonly DIR

function usage() {
    cat <<END >&2
USAGE: $0 [-e env] [-t tenant] [-d domain] [-a access_token] [-D|-W|-v|-h]
        -e file        # .env file location (default cwd)
        -t tenant      # tenant@region shorthand (Auth0-style, appends .auth0.com) (for opaque tokens)
        -d domain      # OIDC provider domain (for opaque tokens)
        -a token       # Access Token (default is access_token env variable)
        -D             # disable OIDC discovery; use default endpoint userinfo
        -W             # force-renew discovery cache (bypass any cached openid-configuration)
        -h|?           # usage
        -v             # verbose

eg,
     $0 -t amin01@au -a J7REwk4c6tJo29jmMV0AZZ79vBd8_qTz
END
    exit "$1"
}

declare DOMAIN=''

declare opt_verbose=0
declare opt_disable_discovery=0
declare opt_force_refresh=0

while getopts "e:t:d:a:DWhv?" opt; do
    case ${opt} in
    e) source "${OPTARG}" ;;
    t) DOMAIN=$(echo "${OPTARG}.auth0.com" | tr '@' '.') ;;
    d) DOMAIN=${OPTARG} ;;
    a) access_token=${OPTARG} ;;
    D) opt_disable_discovery=1 ;;
    W) opt_force_refresh=1 ;;
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

declare userinfo_endpoint="${DOMAIN_URL}userinfo"

# OIDC Discovery to resolve userinfo endpoint (unless disabled via -D); -W forces a cache-bypassing re-fetch
if [[ ${opt_disable_discovery} -eq 0 ]]; then
  declare -a discovery_args=(-d "${DOMAIN_URL}" -f userinfo_endpoint)
  [[ ${opt_force_refresh} -eq 1 ]] && discovery_args+=(-W)

  declare -a discovery_vals
  mapfile -t discovery_vals < <("${DIR}/discover.sh" "${discovery_args[@]}")

  d_userinfo="${discovery_vals[0]}"
  [[ -n "${d_userinfo}" ]] && userinfo_endpoint="${d_userinfo}"
fi

[[ -n "${opt_verbose}" ]] && echo >&2 "> GET ${userinfo_endpoint}"

curl -s -H "Authorization: Bearer ${access_token}" "${userinfo_endpoint}" | jq '.'

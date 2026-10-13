#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2026-10-13
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/main/LICENSE)
##########################################################################################

set -eo pipefail

DIR="${BASH_SOURCE[0]%/*}"
[ "$DIR" = "${BASH_SOURCE[0]}" ] && DIR="."
readonly DIR

command -v curl >/dev/null || { echo >&2 "error: curl not found";  exit 3; }

function usage() {
  cat <<END >&2
USAGE: $0 [-e env] [-t tenant] [-d domain] [-c client_id] [-j jar] [-v|-h]
        -e file        # .env file location (default cwd)
        -t tenant      # tenant@region shorthand (Auth0-style, appends .auth0.com)
        -d domain      # OIDC provider domain or edge location
        -c client_id   # OAuth2/OIDC client ID
        -j file        # curl cookie jar holding auth0_anon (default ${cookie_jar})
        -h|?           # usage
        -v             # verbose

eg,
     $0 -t amin01@au -c aIioQEeY7nJdX78vcQWDBcAqTABgKnZl
END
  exit "$1"
}

declare DOMAIN=''
declare CLIENT_ID=''
declare cookie_jar='anon-cookie.txt'
declare opt_verbose=''

[[ -f "${DIR}/.env" ]] && . "${DIR}/.env"

while getopts "e:t:d:c:j:hv?" opt; do
  case ${opt} in
  e) source "${OPTARG}" ;;
  t) DOMAIN=$(echo "${OPTARG}.auth0.com" | tr '@' '.') ;;
  d) DOMAIN=${OPTARG} ;;
  c) CLIENT_ID=${OPTARG} ;;
  j) cookie_jar=${OPTARG} ;;
  v) opt_verbose=1 ;; #set -x;;
  h | ?) usage 0 ;;
  *) usage 1 ;;
  esac
done

[[ -z "${DOMAIN}" ]] && { echo >&2 "ERROR: DOMAIN undefined"; usage 1; }
[[ -z "${CLIENT_ID}" ]] && { echo >&2 "ERROR: CLIENT_ID undefined"; usage 1; }

[[ ${DOMAIN} =~ ^http ]] || DOMAIN=https://${DOMAIN}
[[ ${DOMAIN} =~ /$ ]] || DOMAIN="${DOMAIN}/"

readonly logout_endpoint="${DOMAIN}anonymous/logout"
readonly BODY="{ \"client_id\": \"${CLIENT_ID}\" }"

if [[ -n "${opt_verbose}" ]]; then
  echo >&2 "> POST ${logout_endpoint}"
  echo "${BODY}" | jq . >&2
  echo >&2 "> cookie jar: ${cookie_jar}"
fi

# replay the session cookie so the server can end the session
declare -a cookie_args=()
[[ -f "${cookie_jar}" ]] && cookie_args=(-b "${cookie_jar}")

declare http_code
http_code=$(curl -s -k -o /dev/null -w '%{http_code}' --header 'content-type: application/json' "${cookie_args[@]}" -d "${BODY}" "${logout_endpoint}")

echo >&2 "< HTTP ${http_code}"

if [[ ! ${http_code} =~ ^2 ]]; then
  echo >&2 "ERROR: logout failed, cookie jar left untouched"
  exit 1
fi

# drop auth0_anon from the jar (curl jar is tab separated: domain, flag, path, secure, expiry, name, value)
if [[ -f "${cookie_jar}" ]]; then
  declare tmp_jar
  tmp_jar=$(mktemp "${cookie_jar}.XXXXXX")
  awk -F'\t' '$6 != "auth0_anon"' "${cookie_jar}" >"${tmp_jar}" || true
  mv "${tmp_jar}" "${cookie_jar}"
  [[ -n "${opt_verbose}" ]] && echo >&2 "> removed auth0_anon from ${cookie_jar}"
fi

exit 0

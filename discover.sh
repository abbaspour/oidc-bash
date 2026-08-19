#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2026-08-19
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/main/LICENSE)
##########################################################################################

# https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
#
# Shared OIDC discovery helper with local caching. Other root scripts shell out to this
# instead of duplicating the curl+jq discovery logic.

set -eo pipefail

command -v curl >/dev/null || { echo >&2 "error: curl not found"; exit 3; }
command -v jq >/dev/null || { echo >&2 "error: jq not found"; exit 3; }

DIR="${BASH_SOURCE[0]%/*}"
[ "$DIR" = "${BASH_SOURCE[0]}" ] && DIR="."
readonly DIR

function usage() {
    cat <<END >&2
USAGE: $0 [-e file] [-t tenant] [-d domain] [-f field]... [-W] [-h|?] [-v]
        -e file        # .env file location (default cwd)
        -t tenant      # tenant@region shorthand (Auth0-style, appends .auth0.com)
        -d domain      # OIDC provider domain (bare host; scheme/path is stripped if present)
        -f field       # JSON field to extract from openid-configuration (repeatable; omit to dump full JSON)
        -W             # wipe/force-renew cache before reading
        -h|?           # usage
        -v             # verbose

eg,
     $0 -t amin01@au -f token_endpoint -f issuer
     $0 -d tenant.us.auth0.com -W -f token_endpoint
END
    exit "$1"
}

declare DOMAIN=''
declare -a FIELDS=()
declare opt_force=0
declare opt_verbose=0

while getopts "e:t:d:f:Whv?" opt; do
    case ${opt} in
    e) source "${OPTARG}" ;;
    t) DOMAIN=$(echo "${OPTARG}.auth0.com" | tr '@' '.') ;;
    d) DOMAIN=${OPTARG} ;;
    f) FIELDS+=("${OPTARG}") ;;
    W) opt_force=1 ;;
    v) opt_verbose=1 ;;
    h | ?) usage 0 ;;
    *) usage 1 ;;
    esac
done

[[ -z "${DOMAIN}" ]] && { echo >&2 "ERROR: DOMAIN undefined"; usage 1; }

# normalize to a bare host: strip scheme and any trailing path/slash
DOMAIN=${DOMAIN#https://}
DOMAIN=${DOMAIN#http://}
DOMAIN=${DOMAIN%%/*}
readonly DOMAIN

readonly CACHE_DIR="${DIR}/.cache/${DOMAIN}"
readonly CACHE_FILE="${CACHE_DIR}/openid-configuration"

declare discovery_json=''

if [[ ${opt_force} -eq 0 && -s "${CACHE_FILE}" ]]; then
    [[ ${opt_verbose} -eq 1 ]] && echo >&2 "> using cache ${CACHE_FILE}"
    discovery_json=$(cat "${CACHE_FILE}")
else
    [[ ${opt_verbose} -eq 1 ]] && echo >&2 "> GET https://${DOMAIN}/.well-known/openid-configuration"
    discovery_json=$(curl -s -k --header "accept: application/json" --url "https://${DOMAIN}/.well-known/openid-configuration" || true)

    # only cache well-formed JSON (pretty-printed for readability); silently ignore
    # any failure to create the cache dir/file
    declare pretty_json
    if pretty_json=$(echo "${discovery_json}" | jq . 2>/dev/null); then
        if mkdir -p "${CACHE_DIR}" 2>/dev/null && echo "${pretty_json}" >"${CACHE_FILE}.tmp" 2>/dev/null; then
            mv "${CACHE_FILE}.tmp" "${CACHE_FILE}" 2>/dev/null || rm -f "${CACHE_FILE}.tmp"
        fi
    fi
fi

if [[ ${#FIELDS[@]} -eq 0 ]]; then
    echo "${discovery_json}" | jq '.'
else
    for field in "${FIELDS[@]}"; do
        # note: use `// ""` (not `// empty`) so a missing field still emits a blank
        # line -- callers read multiple -f results positionally via mapfile
        echo "${discovery_json}" | jq -r --arg f "${field}" '.[$f] // ""'
    done
fi

#!/usr/bin/env bash

set -ueo pipefail

DIR="${BASH_SOURCE[0]%/*}"
[ "$DIR" = "${BASH_SOURCE[0]}" ] && DIR="."
readonly DIR

[[ -f "${DIR}/.env" ]] && . "${DIR}"/.env

function usage() {
    cat <<END >&2
USAGE: $0 [-e env] [-t tenant] [-d domain] [-c client_id] [-x client_secret] [-r refresh_token]  [-v|-h]
        -e file        # .env file location (default cwd)
        -t tenant      # tenant@region shorthand (Auth0-style, appends .auth0.com)
        -d domain      # OIDC provider domain
        -c client_id   # OAuth2/OIDC client ID
        -x secret      # OAuth2/OIDC client secret (optional for public clients)
        -r token       # refresh_token
        -D             # disable OIDC discovery; use default endpoint oauth/revoke
        -W             # force-renew discovery cache (bypass any cached openid-configuration)
        -h|?           # usage
        -v             # verbose

eg,
     $0 -t amin01@au -c aIioQEeY7nJdX78vcQWDBcAqTABgKnZl -x XXXXXX -r RRRRRRR
END
    exit "$1"
}

declare DOMAIN=''
declare CLIENT_ID=''
declare CLIENT_SECRET=''
declare opt_verbose=0
declare refresh_token=''
declare opt_disable_discovery=0
declare opt_force_refresh=0

while getopts "e:t:d:c:r:x:DWhv?" opt
do
    case ${opt} in
        e) source "${OPTARG}";;
        t) DOMAIN=$(echo "${OPTARG}".auth0.com | tr '@' '.');;
        d) DOMAIN=${OPTARG};;
        c) CLIENT_ID=${OPTARG};;
        x) CLIENT_SECRET=${OPTARG};;
        r) refresh_token=${OPTARG};;
        D) opt_disable_discovery=1;;
        W) opt_force_refresh=1;;
        v) opt_verbose=1;; #set -x;;
        h|?) usage 0;;
        *) usage 1;;
    esac
done

[[ -z "${DOMAIN}" ]] && { echo >&2 "ERROR: DOMAIN undefined"; usage 1; }
[[ -z "${CLIENT_ID}" ]] && { echo >&2 "ERROR: CLIENT_ID undefined"; usage 1; }
[[ -z "${refresh_token}" ]] && { echo >&2 "ERROR: refresh_token undefined"; usage 1; }

declare secret=''
[[ -n "${CLIENT_SECRET}" ]] && secret="\"client_secret\":\"${CLIENT_SECRET}\","

declare BODY
BODY=$(cat <<EOL
{
    "client_id":"${CLIENT_ID}",
    ${secret}
    "token": "${refresh_token}"
}
EOL
)

declare revocation_endpoint="https://${DOMAIN}/oauth/revoke"

# OIDC Discovery to resolve revocation endpoint (unless disabled via -D); -W forces a cache-bypassing re-fetch
if [[ ${opt_disable_discovery} -eq 0 ]]; then
    declare -a discovery_args=(-d "${DOMAIN}" -f revocation_endpoint)
    [[ ${opt_force_refresh} -eq 1 ]] && discovery_args+=(-W)

    declare -a discovery_vals
    mapfile -t discovery_vals < <("${DIR}/discover.sh" "${discovery_args[@]}")

    d_revoke="${discovery_vals[0]}"
    [[ -n "${d_revoke}" ]] && revocation_endpoint="${d_revoke}"
fi

if [[ -n "${opt_verbose}" ]]; then
    echo >&2 "> POST ${revocation_endpoint}"
    echo >&2 "${BODY}"
fi

curl --request POST \
  --url "${revocation_endpoint}" \
  --header 'content-type: application/json' \
  --data "${BODY}"


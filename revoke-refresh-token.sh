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
        -h|?           # usage
        -v             # verbose

eg,
     $0 -t amin01@au -c aIioQEeY7nJdX78vcQWDBcAqTABgKnZl -x XXXXXX -r RRRRRRR
END
    exit $1
}

declare DOMAIN=''
declare CLIENT_ID=''
declare CLIENT_SECRET=''
declare opt_verbose=0
declare refresh_token=''

while getopts "e:t:d:c:r:x:hv?" opt
do
    case ${opt} in
        e) source "${OPTARG}";;
        t) DOMAIN=$(echo "${OPTARG}".auth0.com | tr '@' '.');;
        d) DOMAIN=${OPTARG};;
        c) CLIENT_ID=${OPTARG};;
        x) CLIENT_SECRET=${OPTARG};;
        r) refresh_token=${OPTARG};;
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

if [[ -n "${opt_verbose}" ]]; then
    echo >&2 "> POST https://${DOMAIN}/oauth/revoke"
    echo >&2 "${BODY}"
fi

curl --request POST \
  --url "https://${DOMAIN}/oauth/revoke" \
  --header 'content-type: application/json' \
  --data "${BODY}"


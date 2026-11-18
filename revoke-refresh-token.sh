#!/usr/bin/env bash

set -ueo pipefail

DIR="${BASH_SOURCE[0]%/*}"
[ "$DIR" = "${BASH_SOURCE[0]}" ] && DIR="."
readonly DIR
declare alg='RS256'

# OIDC_BASH_NO_DOTENV=1 skips the automatic .env, eg. when another tool calls this script
[[ -z "${OIDC_BASH_NO_DOTENV:-}" && -f "${DIR}/.env" ]] && . "${DIR}/.env"

function usage() {
    cat <<END >&2
USAGE: $0 [-e env] [-t tenant] [-d domain] [-c client_id] [-x client_secret] [-k kid] [-K private.pem] [-A alg] [-r refresh_token] [-v|-h]
        -e file        # .env file location (default cwd)
        -t tenant      # tenant@region shorthand (Auth0-style, appends .auth0.com)
        -d domain      # OIDC provider domain
        -c client_id   # OAuth2/OIDC client ID
        -x secret      # OAuth2/OIDC client secret (optional for public clients)
        -k kid         # JWT-CA (private_key_jwt) key id
        -K private.pem # JWT-CA client private key file for client assertion
        -A alg         # JWT-CA algorithm. default ${alg}. supports: RS256, ES256, PS256
        -r token       # refresh_token
        -D             # disable OIDC discovery; use default endpoint oauth/revoke
        -W             # force-renew discovery cache (bypass any cached openid-configuration)
        -h|?           # usage
        -v             # verbose

eg,
     $0 -t amin01@au -c aIioQEeY7nJdX78vcQWDBcAqTABgKnZl -x XXXXXX -r RRRRRRR
     $0 -d tenant.auth0.com -c https://agent.example/cimd.json -k KID -K ec-private.pem -A ES256 -r RRRRRRR
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
declare kid=''
declare private_pem=''

while getopts "e:t:d:c:r:x:k:K:A:DWhv?" opt
do
    case ${opt} in
        e) source "${OPTARG}";;
        t) DOMAIN=$(echo "${OPTARG}".auth0.com | tr '@' '.');;
        d) DOMAIN=${OPTARG};;
        c) CLIENT_ID=${OPTARG};;
        x) CLIENT_SECRET=${OPTARG};;
        r) refresh_token=${OPTARG};;
        k) kid=${OPTARG};;
        K) private_pem=${OPTARG};;
        A) alg=${OPTARG};;
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

[[ ${DOMAIN} =~ ^http ]] || DOMAIN=https://${DOMAIN}
declare revocation_endpoint="${DOMAIN}/oauth/revoke"
declare issuer="${DOMAIN}"
[[ ${issuer} =~ /$ ]] || issuer="${issuer}/"

# OIDC Discovery to resolve revocation endpoint (unless disabled via -D); -W forces a cache-bypassing re-fetch
if [[ ${opt_disable_discovery} -eq 0 ]]; then
    declare -a discovery_args=(-d "${DOMAIN}" -f issuer -f revocation_endpoint)
    [[ ${opt_force_refresh} -eq 1 ]] && discovery_args+=(-W)

    declare -a discovery_vals
    mapfile -t discovery_vals < <("${DIR}/discover.sh" "${discovery_args[@]}")

    d_issuer="${discovery_vals[0]}"
    d_revoke="${discovery_vals[1]}"
    [[ -n "${d_issuer}" ]] && issuer="${d_issuer}"
    [[ -n "${d_revoke}" ]] && revocation_endpoint="${d_revoke}"
fi

# one client authentication method per request (RFC 6749 §2.3): JWT-CA (-K) wins over a secret
declare secret=''
[[ -n "${CLIENT_SECRET}" && -z "${private_pem}" ]] && secret="\"client_secret\":\"${CLIENT_SECRET}\","

# JWT-CA (private_key_jwt, RFC 7523): the assertion's aud is the issuer
declare client_assertion=''
if [[ -n "${private_pem}" ]]; then
    [[ -f "${private_pem}" ]] || { echo >&2 "ERROR: private key missing: ${private_pem}"; usage 1; }
    assertion=$("${DIR}"/jwt/client-assertion.sh -a "${issuer}" -i "${CLIENT_ID}" -k "${kid}" -f "${private_pem}" -A "${alg}")
    readonly assertion
    client_assertion="\"client_assertion_type\":\"urn:ietf:params:oauth:client-assertion-type:jwt-bearer\",\"client_assertion\":\"${assertion}\","
fi
readonly client_assertion

declare BODY
BODY=$(cat <<EOL
{
    "client_id":"${CLIENT_ID}",
    ${secret}
    ${client_assertion}
    "token": "${refresh_token}",
    "token_type_hint": "refresh_token"
}
EOL
)

if [[ ${opt_verbose} -eq 1 ]]; then
    echo >&2 "> POST ${revocation_endpoint}"
    echo >&2 "${BODY}"
fi

# RFC 7009 §2.2: HTTP 200 with an empty body on success. The status goes to stderr, and a
# non-2xx response makes this script exit non-zero.
curl -sS --fail-with-body -w '%{stderr}HTTP %{http_code}\n' --request POST \
  --url "${revocation_endpoint}" \
  --header 'content-type: application/json' \
  --data "${BODY}"


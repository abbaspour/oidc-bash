#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2022-06-12
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/main/LICENSE)
##########################################################################################

set -eo pipefail

DIR="${BASH_SOURCE[0]%/*}"
[ "$DIR" = "${BASH_SOURCE[0]}" ] && DIR="."
readonly DIR

##
# prerequisite:
# 1. create a clients with type SPA
# 2. add allowed callback to clients: https://jwt.io
# 3. ./authorize.sh -t tenant -c client_id
##

declare REDIRECT_URI='http://local.abbaspour.net:1980/cgi-bin/cb.sh'
declare SCOPE='openid profile email'
declare RESPONSE_TYPE='id_token'
declare RESPONSE_MODE=''
declare authorization_path='authorize'
declare bc_authorization_path='bc-authorize'
declare par_path='oauth/par'

function usage() {
    cat <<END >&2
USAGE: $0 [-e env] [-t tenant] [-d domain] [-c client_id] [-a audience] [-r connection] [-T response_type] [-f flow] [-u callback] [-s scope] [-p prompt] [-R mode] [-A max_age] [-D] [-P|-m|-M|-C|-N|-o|-h]
        -e file        # .env file location (default cwd)
        -t tenant      # tenant@region shorthand (Auth0-style, appends .auth0.com)
        -d domain      # OIDC provider domain
        -c client_id   # OAuth2/OIDC client ID
        -x secret      # OAuth2/OIDC client secret (for PAR and CIBA)
        -a audience    # Audience
        -r realm       # Connection
        -T types       # comma separated response types (default is "${RESPONSE_TYPE}")
        -f flow        # OAuth2 flow type (implicit,code,pkce,hybrid)
        -u callback    # callback URL (default ${REDIRECT_URI})
        -s scopes      # comma separated list of scopes (default is "${SCOPE}")
        -p prompt      # prompt type: none, silent, login, consent
        -R mode        # response_mode of: query, web_message, form_post, fragment
        -A max_age     # max_age in seconds (default is unset; can be set via MAX_AGE in .env)
        -S state       # state
        -n nonce       # nonce
        -H hint        # login hint (for CIBA should be JSON with sub and aud)
        -I id_token    # id_token hint
        -o org_id      # organisation id
        -i invitation  # invitation
        -l locale      # ui_locales
        -E key=value   # additional comma separated list of key=value parameters to be sent as ext-key
        -k key_id      # client credentials key_id
        -K file.pem    # client credentials private key
        -j file        # path to file containing authorization_details JSON format array, for RAR
        -L protocol    # protocol to use. can be samlp, wsfed or oauth (default)
        -g token       # send session_transfer_token as get query param
        -G token       # send session_transfer_token as get cookie param
        -U endpoint    # authorization endpoint path (default is 'authorize')
        -D             # disable OIDC discovery; use default endpoints derived from -d/-t and -U
        -P             # use PAR (pushed authorization request)
        -J             # use JAR (JWT authorization request)
        -B message     # use back channel authorize (CIBA request) with given binding message
        -C             # copy to clipboard
        -N             # no pretty print
        -m             # MyAccount API audience
        -M             # Management API audience
        -O             # MyOrg API audience
        -F             # MFA API audience
        -h|?           # usage
        -v             # verbose

eg,
     $0 -t amin01@au -s offline_access -o
END
    exit "$1"
}

urlencode() {
    jq -rn --arg x "${1}" '$x|@uri'
}

random32() {
    for _ in {0..45}; do echo -n $((RANDOM % 10)); done
}

base64URLEncode() {
  echo -n "$1" | base64 -w0 | tr '+' '-' | tr '/' '_' | tr -d '='
}

gen_code_verifier() {
    base64URLEncode "$(random32)"
}

gen_code_challenge() {
    base64URLEncode "$(echo -n "$1" | openssl dgst -binary -sha256)"
}

#declare -r CURL='/opt/homebrew/opt/curl/bin/curl'
declare -r CURL='curl'

declare DOMAIN=''
declare CLIENT_ID=''
declare CLIENT_SECRET=''
declare CONNECTION=''
declare AUDIENCE=''
declare PROMPT=''
declare MAX_AGE=''

declare opt_clipboard=''
declare opt_flow='implicit'
declare opt_mgmnt=''
declare opt_mfa_api=''
declare opt_myaccount_api=''
declare opt_myorg_api=''
declare opt_state='mystate'
declare opt_nonce='mynonce'
declare opt_login_hint=''
declare opt_id_token_hint=''
declare org_id=''
declare ui_locales=''
declare invitation=''
declare key_id=''
declare key_file=''
declare authorization_details=''
declare protocol='oauth'
declare opt_pp=1
declare opt_par=0
declare opt_jar=0
declare opt_ciba=0
declare opt_binding_message=''
declare opt_ext_params=''
declare opt_session_transfer_token_query=''
declare opt_session_transfer_token_cookie=''
declare opt_verbose=0
declare opt_disable_discovery=0

[[ -f "${DIR}/.env" ]] && . "${DIR}/.env"

while getopts "e:t:d:c:x:a:r:R:A:f:u:p:s:S:n:H:I:o:i:l:E:k:K:j:T:g:G:B:L:U:DmMFCOPJNhv?" opt; do
    case ${opt} in
    e) source "${OPTARG}" ;;
    t) DOMAIN=$(echo "${OPTARG}.auth0.com" | tr '@' '.') ;;
    d) DOMAIN=${OPTARG} ;;
    c) CLIENT_ID=${OPTARG} ;;
    x) CLIENT_SECRET=${OPTARG} ;;
    a) AUDIENCE=${OPTARG} ;;
    r) CONNECTION=${OPTARG} ;;
    T) RESPONSE_TYPE=$(echo "${OPTARG}" | tr ',' ' ') ;;
    f) opt_flow=${OPTARG} ;;
    u) REDIRECT_URI=${OPTARG} ;;
    p) PROMPT=${OPTARG} ;;
    R) RESPONSE_MODE=${OPTARG} ;;
    A) MAX_AGE=${OPTARG} ;;
    s) SCOPE=$(echo "${OPTARG}" | tr ',' ' ') ;;
    S) opt_state=${OPTARG} ;;
    n) opt_nonce=${OPTARG} ;;
    H) opt_login_hint=${OPTARG} ;;
    I) opt_id_token_hint=${OPTARG} ;;
    o) org_id=${OPTARG} ;;
    i) invitation=${OPTARG} ;;
    l) ui_locales=${OPTARG} ;;
    E) opt_ext_params=$(echo "${OPTARG}" | tr ',' ' ') ;;
    k) key_id="${OPTARG}";;
    K) key_file="${OPTARG}";;
    j) authorization_details="${OPTARG}";;
    L) protocol="${OPTARG}";;
    g) opt_session_transfer_token_query="${OPTARG}";;
    G) opt_session_transfer_token_cookie="${OPTARG}";;
    U) authorization_path="${OPTARG}";;
    D) opt_disable_discovery=1 ;;
    C) opt_clipboard=1 ;;
    P) opt_par=1 ;;
    J) opt_jar=1 ;;
    B) opt_ciba=1; opt_binding_message="${OPTARG}" ;;
    N) opt_pp=0 ;;
    M) opt_mgmnt=1 ;;
    m) opt_myaccount_api=1 ;;
    O) opt_myorg_api=1 ;;
    F) opt_mfa_api=1 ;;
    v) opt_verbose=1;; #set -x ;;
    h | ?) usage 0 ;;
    *) usage 1 ;;
    esac
done

[[ -z "${DOMAIN}" ]] && {  echo >&2 "ERROR: DOMAIN undefined";  usage 1;  }
[[ -z "${CLIENT_ID}" ]] && { echo >&2 "ERROR: CLIENT_ID undefined";  usage 1; }

# Read authorization_details from file if provided
if [[ -n "${authorization_details}" ]]; then
    [[ ! -f "${authorization_details}" ]] && {
        echo >&2 "ERROR: authorization_details file not found: ${authorization_details}";
        exit 1;
    }
    authorization_details=$(jq -c . "${authorization_details}")
fi

[[ ${DOMAIN} =~ ^http ]] || DOMAIN=https://${DOMAIN}

declare issuer="${DOMAIN}"
[[ ${issuer} =~ /$ ]] || issuer="${issuer}/"

# Default endpoints derived from domain and paths
declare par_endpoint="${DOMAIN}/${par_path}"
declare authorization_endpoint="${DOMAIN}/${authorization_path}"
declare bc_authorization_endpoint="${DOMAIN}/${bc_authorization_path}"

# OIDC Discovery (unless disabled with -D)
if [[ ${opt_disable_discovery} -eq 0 ]]; then
    # Use -k to allow dev environments with self-signed; consistent with later curl usage
    declare discovery_json
    discovery_json=$(${CURL} -s -k --header "accept: application/json" --url "${DOMAIN}/.well-known/openid-configuration" || true)

    # Extract fields if present
    d_authz=$(echo "${discovery_json}" | jq -r '.authorization_endpoint // empty')
    d_par=$(echo "${discovery_json}" | jq -r '.pushed_authorization_request_endpoint // empty')
    d_ciba=$(echo "${discovery_json}" | jq -r '.backchannel_authentication_endpoint // empty')
    d_issuer=$(echo "${discovery_json}" | jq -r '.issuer // empty')

    # Override defaults when discovery provides values
    [[ -n "${d_authz}" ]] && authorization_endpoint="${d_authz}"
    [[ -n "${d_par}" ]] && par_endpoint="${d_par}"
    [[ -n "${d_ciba}" ]] && bc_authorization_endpoint="${d_ciba}"
    [[ -n "${d_issuer}" ]] && issuer="${d_issuer}"
fi

if [[ "${protocol}" != "oauth" && "${protocol}" != "oidc" ]]; then
  declare signon_url="${DOMAIN}/${protocol}/${CLIENT_ID}"
  [[ -n "${CONNECTION}" ]] && signon_url+="?connection=${CONNECTION}"

  echo "${signon_url}"
  [[ -n "${opt_clipboard}" ]] && echo "${signon_url}" | pbcopy

  exit 0
fi

[[ -n "${opt_mgmnt}" ]] && AUDIENCE="${DOMAIN}/api/v2/"
[[ -n "${opt_mfa_api}" ]] && AUDIENCE="${DOMAIN}/mfa/"
[[ -n "${opt_myaccount_api}" ]] && AUDIENCE="${DOMAIN}/me/"
[[ -n "${opt_myorg_api}" ]] && AUDIENCE="${DOMAIN}/my-org/"

declare response_param=''

case ${opt_flow} in
implicit) response_param="response_type=$(urlencode "${RESPONSE_TYPE}")" ;;
*code) response_param='response_type=code' ;;
pkce | hybrid)
    code_verifier=$(gen_code_verifier)
    code_challenge=$(gen_code_challenge "${code_verifier}")
    echo "code_verifier=${code_verifier}"
    response_param="code_challenge_method=S256&code_challenge=${code_challenge}"
    if [[ ${opt_flow} == 'pkce' ]]; then response_param+='&response_type=code'; else response_param+='&response_type=code%20token%20id_token'; fi
    ;;
*) echo >&2 "ERROR: unknown flow: ${opt_flow}"
    usage 1
    ;;
esac

# CIBA login_hint in iss_sub format
if [[ ${opt_ciba} -ne 0 ]]; then                    # CIBA
  [[ -z "${opt_login_hint}" ]] && { echo >&2 "login_hint required for CIBA"; exit 1; }
  opt_login_hint=$(printf '{"format": "iss_sub", "iss": "%s", "sub": "%s"}'  "${issuer}" "${opt_login_hint}")
fi


# shellcheck disable=SC2155
declare authorize_params="client_id=${CLIENT_ID}&${response_param}&nonce=$(urlencode "${opt_nonce}")&redirect_uri=$(urlencode "${REDIRECT_URI}")&scope=$(urlencode "${SCOPE}")"

[[ -n "${AUDIENCE}" ]] && authorize_params+="&audience=$(urlencode "${AUDIENCE}")"
[[ -n "${CONNECTION}" ]] && authorize_params+="&connection=${CONNECTION}"
[[ -n "${PROMPT}" ]] && authorize_params+="&prompt=${PROMPT}"
[[ -n "${RESPONSE_MODE}" ]] && authorize_params+="&response_mode=${RESPONSE_MODE}"
[[ -n "${MAX_AGE}" ]] && authorize_params+="&max_age=${MAX_AGE}"
[[ -n "${opt_state}" ]] && authorize_params+="&state=$(urlencode "${opt_state}")"
[[ -n "${opt_login_hint}" ]] && authorize_params+="&login_hint=$(urlencode "${opt_login_hint}")"
[[ -n "${opt_id_token_hint}" ]] && authorize_params+="&id_token_hint=$(urlencode "${opt_id_token_hint}")"
[[ -n "${invitation}" ]] && authorize_params+="&invitation=$(urlencode "${invitation}")"
[[ -n "${org_id}" ]] && authorize_params+="&organization=$(urlencode "${org_id}")"
[[ -n "${ui_locales}" ]] && authorize_params+="&ui_locales=${ui_locales}"
[[ -n "${authorization_details}" ]] && authorize_params+="&authorization_details=$(urlencode "${authorization_details}")"
[[ -n "${opt_session_transfer_token_query}" ]] && authorize_params+="&session_transfer_token=$(urlencode "${opt_session_transfer_token_query}")"
for p in ${opt_ext_params}; do authorize_params+="&$p"; done
#authorize_params+="&purpose=testing"

if [[ ${opt_jar} -ne 0 ]]; then                       # JAR
  [[ -z "${key_id}" ]] && { echo >&2 "ERROR: key_id undefined"; exit 2; }
  [[ -z "${key_file}" ]] && { echo >&2 "ERROR: key_file undefined"; exit 2; }
  [[ ! -f "${key_file}" ]] && { echo >&2 "ERROR: key_file missing: ${key_file}"; exit 2; }
  tmp_jwt=$(mktemp --suffix=.json)
  readonly tmp_jwt
  # shellcheck disable=SC2129
  printf "{\n \"iss\":\"%s\", \n " "${CLIENT_ID}" >> "${tmp_jwt}"
  echo "${authorize_params}" | awk -F'[=&]' '{
                                 for (i=1;i<=NF;i+=2) {
                                   gsub(/\+/," ",$(i+1))
                                   gsub(/%20/," ",$(i+1))
                                   gsub(/%3A/,":",$(i+1))
                                   gsub(/%2F/,"/",$(i+1))
                                   printf("\"%s\":\"%s\",\n ", $i, $(i+1))
                                 }
                               }' >> "${tmp_jwt}"
  jar_exp=$(date +%s --date='5 minutes')
  readonly jar_exp
  jar_now=$(date +%s)
  readonly jar_now
  echo "\"aud\": \"${issuer}\", \"iat\": ${jar_now}, \"exp\": ${jar_exp}, \"nbf\": ${jar_now} }"  >> "${tmp_jwt}"
  signed_request=$("${DIR}/jwt/sign-rs256.sh" -p "${key_file}" -f "${tmp_jwt}" -k "${key_id}" -t oauth-authz-req+jwt -A PS256)
  readonly signed_request
  echo "$signed_request"
  authorize_params="client_id=${CLIENT_ID}&request=${signed_request}"
fi

if [[ -n "${CLIENT_SECRET}" ]]; then                      # confidential client for PAR and CIBA
  authorize_params+="&client_secret=${CLIENT_SECRET}"
elif [[ -n "${key_id}" ]]; then                                                # JWT-CA
  declare signed_client_assertion
  signed_client_assertion=$("${DIR}"/jwt/client-assertion.sh -a "${issuer}" -f "${key_file}" -k "${key_id}" -t JWT)
  readonly signed_client_assertion
  authorize_params+="&client_assertion=${signed_client_assertion}&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
fi

if [[ ${opt_par} -ne 0 ]]; then                       # PAR
  command -v jq >/dev/null || {  echo >&2 "error: jq not found";  exit 3; }

  [[ -n "${opt_verbose}" ]] && echo >&2 "> POST ${par_endpoint} ${authorize_params}"

  #  --tlsv1.2 --cert transport.pem --key transport.key --cacert connectid-sandbox-ca.pem
  #  --header "x-fapi-interaction-id: $(random32)" \
  declare request_uri
  request_uri=$("${CURL}" -s -k --header "accept: application/json" --url "${par_endpoint}" \
    -d "${authorize_params}" | jq -r '.request_uri')
  readonly request_uri
  authorize_params="client_id=${CLIENT_ID}&request_uri=${request_uri}"

elif [[ ${opt_ciba} -ne 0 ]]; then                    # CIBA
  [[ -z "${opt_login_hint}" ]] && { echo >&2 "login_hint required for CIBA"; exit 1; }
  [[ -z "${opt_binding_message}" ]] && { echo >&2 "opt_binding_message required for CIBA"; exit 1; }
  authorize_params+="&binding_message=$(urlencode "${opt_binding_message}")"

  command -v jq >/dev/null || {  echo >&2 "error: jq not found";  exit 3; }

  [[ -n "${opt_verbose}" ]] && echo >&2 "> POST ${bc_authorization_endpoint} ${authorize_params}"

  declare auth_req_id
  auth_req_id=$("${CURL}" -s -k --header "accept: application/x-www-form-urlencoded" --url "${bc_authorization_endpoint}" \
    -d "${authorize_params}" | jq -r '.auth_req_id')
  readonly auth_req_id

  echo "auth_req_id: ${auth_req_id}"
  exit 0
fi

declare authorize_url="${authorization_endpoint}?${authorize_params}"

if [[ -n "${opt_session_transfer_token_cookie}" ]]; then
  ${CURL} --cookie "auth0_session_transfer_token=${opt_session_transfer_token_cookie}" "${authorize_url}"
fi

if [[ ${opt_pp} -eq 0 ]]; then
  echo "${authorize_url}"
else
    echo "${authorize_url}" | sed -E 's/&/ &\
    /g; s/%20/ /g; s/%3A/:/g;s/%2F/\//g'
fi

[[ -n "${opt_clipboard}" ]] && echo "${authorize_url}" | pbcopy

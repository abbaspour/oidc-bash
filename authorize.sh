#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2022-06-12
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/master/LICENSE)
##########################################################################################

set -eo pipefail

readonly DIR=$(dirname "${BASH_SOURCE[0]}")

##
# prerequisite:
# 1. create a clients with type SPA
# 2. add allowed callback to clients: https://jwt.io
# 3. ./authorize.sh -t tenant -c client_id
##

declare AUTH0_REDIRECT_URI='https://jwt.io'
declare AUTH0_SCOPE='openid profile email'
declare AUTH0_RESPONSE_TYPE='id_token'
declare AUTH0_RESPONSE_MODE=''
declare authorization_path='authorize'
declare bc_authorization_path='bc-authorize'
declare par_path='oauth/par'

function usage() {
    cat <<END >&2
USAGE: $0 [-e env] [-t tenant] [-d domain] [-c client_id] [-a audience] [-r connection] [-R response_type] [-f flow] [-u callback] [-s scope] [-p prompt] [-M mode] [-D details] [-P|-m|-C|-N|-o|-h]
        -e file        # .env file location (default cwd)
        -t tenant      # Auth0 tenant@region
        -d domain      # Auth0 domain
        -c client_id   # Auth0 client ID
        -x secret      # Auth0 client secret (for PAR and CIBA)
        -a audience    # Audience
        -r realm       # Connection
        -R types       # comma separated response types (default is "${AUTH0_RESPONSE_TYPE}")
        -f flow        # OAuth2 flow type (implicit,code,pkce,hybrid)
        -u callback    # callback URL (default ${AUTH0_REDIRECT_URI})
        -s scopes      # comma separated list of scopes (default is "${AUTH0_SCOPE}")
        -p prompt      # prompt type: none, silent, login, consent
        -M model       # response_mode of: web_message, form_post, fragment
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
        -D details     # authorization_details JSON format array, for RAR
        -T protocol    # protocol to use. can be samlp, wsfed or oauth (default)
        -g token       # send session_transfer_token as get query param
        -G token       # send session_transfer_token as get cookie param
        -P             # use PAR (pushed authorization request)
        -J             # use JAR (JWT authorization request)
        -B message     # use back channel authorize (CIBA request) with given binding message
        -C             # copy to clipboard
        -N             # no pretty print
        -m             # Management API audience
        -F             # MFA API audience
        -O             # Open URL
        -b browser     # Choose browser to open (firefox, chrome, safari)
        -h|?           # usage
        -v             # verbose

eg,
     $0 -t amin01@au -s offline_access -o
END
    exit $1
}

urlencode() {
    jq -rn --arg x "${1}" '$x|@uri'
}

random32() {
    for _ in {0..32}; do echo -n $((RANDOM % 10)); done
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

declare AUTH0_DOMAIN=''
declare AUTH0_CLIENT_ID=''
declare AUTH0_CLIENT_SECRET=''
declare AUTH0_CONNECTION=''
declare AUTH0_AUDIENCE=''
declare AUTH0_PROMPT=''

declare opt_open=''
declare opt_clipboard=''
declare opt_flow='implicit'
declare opt_mgmnt=''
declare opt_mfa_api=''
declare opt_state=''
declare opt_nonce='mynonce'
declare opt_login_hint=''
declare opt_id_token_hint=''
declare org_id=''
declare ui_locales=''
declare invitation=''
declare key_id=''
declare key_file=''
declare opt_browser=''
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

[[ -f "${DIR}/.env" ]] && . "${DIR}/.env"

while getopts "e:t:d:c:x:a:r:R:f:u:p:s:b:M:S:n:H:I:o:i:l:E:k:K:D:T:g:G:B:mFCOPJNhv?" opt; do
    case ${opt} in
    e) source "${OPTARG}" ;;
    t) AUTH0_DOMAIN=$(echo "${OPTARG}.auth0.com" | tr '@' '.') ;;
    d) AUTH0_DOMAIN=${OPTARG} ;;
    c) AUTH0_CLIENT_ID=${OPTARG} ;;
    x) AUTH0_CLIENT_SECRET=${OPTARG} ;;
    a) AUTH0_AUDIENCE=${OPTARG} ;;
    r) AUTH0_CONNECTION=${OPTARG} ;;
    R) AUTH0_RESPONSE_TYPE=$(echo "${OPTARG}" | tr ',' ' ') ;;
    f) opt_flow=${OPTARG} ;;
    u) AUTH0_REDIRECT_URI=${OPTARG} ;;
    p) AUTH0_PROMPT=${OPTARG} ;;
    M) AUTH0_RESPONSE_MODE=${OPTARG} ;;
    s) AUTH0_SCOPE=$(echo "${OPTARG}" | tr ',' ' ') ;;
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
    D) authorization_details="${OPTARG}";;
    T) protocol="${OPTARG}";;
    g) opt_session_transfer_token_query="${OPTARG}";;
    G) opt_session_transfer_token_cookie="${OPTARG}";;
    C) opt_clipboard=1 ;;
    P) opt_par=1 ;;
    J) opt_jar=1 ;;
    B) opt_ciba=1; opt_binding_message="${OPTARG}" ;;
    N) opt_pp=0 ;;
    O) opt_open=1 ;;
    m) opt_mgmnt=1 ;;
    F) opt_mfa_api=1 ;;
    b) opt_browser="-a ${OPTARG} " ;;
    v) opt_verbose=1;; #set -x ;;
    h | ?) usage 0 ;;
    *) usage 1 ;;
    esac
done

[[ -z "${AUTH0_DOMAIN}" ]] && {  echo >&2 "ERROR: AUTH0_DOMAIN undefined";  usage 1;  }
[[ -z "${AUTH0_CLIENT_ID}" ]] && { echo >&2 "ERROR: AUTH0_CLIENT_ID undefined";  usage 1; }

[[ ${AUTH0_DOMAIN} =~ ^http ]] || AUTH0_DOMAIN=https://${AUTH0_DOMAIN}

declare par_endpoint="${AUTH0_DOMAIN}/${par_path}"
declare authorization_endpoint="${AUTH0_DOMAIN}/${authorization_path}"
declare bc_authorization_endpoint="${AUTH0_DOMAIN}/${bc_authorization_path}"

if [[ "${protocol}" != "oauth" && "${protocol}" != "oidc" ]]; then
  declare signon_url="${AUTH0_DOMAIN}/${protocol}/${AUTH0_CLIENT_ID}"
  [[ -n "${AUTH0_CONNECTION}" ]] && signon_url+="?connection=${AUTH0_CONNECTION}"

  echo "${signon_url}"
  [[ -n "${opt_clipboard}" ]] && echo "${signon_url}" | pbcopy
  [[ -n "${opt_open}" ]] && open ${opt_browser} "${signon_url}"

  exit 0
fi

[[ -n "${opt_mgmnt}" ]] && AUTH0_AUDIENCE="${AUTH0_DOMAIN}/api/v2/"
[[ -n "${opt_mfa_api}" ]] && AUTH0_AUDIENCE="${AUTH0_DOMAIN}/mfa/"

declare response_param=''

case ${opt_flow} in
implicit) response_param="response_type=$(urlencode "${AUTH0_RESPONSE_TYPE}")" ;;
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


# shellcheck disable=SC2155
declare authorize_params="client_id=${AUTH0_CLIENT_ID}&${response_param}&nonce=$(urlencode ${opt_nonce})&redirect_uri=$(urlencode ${AUTH0_REDIRECT_URI})&scope=$(urlencode "${AUTH0_SCOPE}")"

[[ -n "${AUTH0_AUDIENCE}" ]] && authorize_params+="&audience=$(urlencode "${AUTH0_AUDIENCE}")"
[[ -n "${AUTH0_CONNECTION}" ]] && authorize_params+="&connection=${AUTH0_CONNECTION}"
[[ -n "${AUTH0_PROMPT}" ]] && authorize_params+="&prompt=${AUTH0_PROMPT}"
[[ -n "${AUTH0_RESPONSE_MODE}" ]] && authorize_params+="&response_mode=${AUTH0_RESPONSE_MODE}"
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
  readonly tmp_jwt=$(mktemp --suffix=.json)
  # shellcheck disable=SC2129
  printf "{\n \"iss\":\"%s\", \n " "${AUTH0_CLIENT_ID}" >> "${tmp_jwt}"
  echo "${authorize_params}" | awk -F'[=&]' '{
                                 for (i=1;i<=NF;i+=2) {
                                   gsub(/\+/," ",$(i+1))
                                   gsub(/%20/," ",$(i+1))
                                   gsub(/%3A/,":",$(i+1))
                                   gsub(/%2F/,"/",$(i+1))
                                   printf("\"%s\":\"%s\",\n ", $i, $(i+1))
                                 }
                               }' >> "${tmp_jwt}"
  readonly jar_exp=$(date +%s --date='5 minutes')
  readonly jar_now=$(date +%s)
  echo "\"aud\": \"${AUTH0_DOMAIN}\", \"iat\": ${jar_now}, \"exp\": ${jar_exp}, \"nbf\": ${jar_now} }"  >> "${tmp_jwt}"
  #cat "${tmp_jwt}"
  signed_request=$("${DIR}/jwt/sign-rs256.sh" -p "${key_file}" -f "${tmp_jwt}" -k "${key_id}" -t oauth-authz-req+jwt -A PS256)
  readonly signed_request
  echo "$signed_request"
  authorize_params="client_id=${AUTH0_CLIENT_ID}&request=${signed_request}"
fi

if [[ -n "${AUTH0_CLIENT_SECRET}" ]]; then                      # confidential client for PAR and CIBA
  authorize_params+="&client_secret=${AUTH0_CLIENT_SECRET}"
elif [[ -n "${key_id}" ]]; then                                                # JWT-CA
  [[ -z "${key_id}" ]] && { echo >&2 "ERROR: key_id undefined"; exit 2; }
  [[ -z "${key_file}" ]] && { echo >&2 "ERROR: key_file undefined"; exit 2; }
  [[ ! -f "${key_file}" ]] && { echo >&2 "ERROR: key_file missing: ${key_file}"; exit 2; }
  readonly exp=$(date +%s --date='5 minutes')
  readonly now=$(date +%s)
  readonly client_assertion=$(mktemp --suffix=.json)
  printf '{"iat": %s, "iss":"%s","sub":"%s","aud":"%s","exp":%s, "jti": "%s"}' "${now}" "${AUTH0_CLIENT_ID}" "${AUTH0_CLIENT_ID}" "${AUTH0_DOMAIN}" "${exp}" "${now}" >> "${client_assertion}"
  readonly signed_client_assertion=$("${DIR}/jwt/sign-rs256.sh" -p "${key_file}" -f "${client_assertion}" -k "${key_id}" -t JWT -A PS256)
  echo signed_client_assertion=$signed_client_assertion
  authorize_params+="&client_assertion=${signed_client_assertion}&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
fi

if [[ ${opt_par} -ne 0 ]]; then                       # PAR
  #command -v curl >/dev/null || { echo >&2 "error: curl not found";  exit 3; }
  readonly curl='/opt/homebrew/opt/curl/bin/curl'
  command -v jq >/dev/null || {  echo >&2 "error: jq not found";  exit 3; }

  #  --tlsv1.2 --cert transport.pem --key transport.key --cacert connectid-sandbox-ca.pem
  #  --header "x-fapi-interaction-id: $(random32)" \
  declare -r request_uri=$("${curl}" -s -k --header "accept: application/json" --url "${par_endpoint}" \
    -d "${authorize_params}" | jq -r '.request_uri')
  authorize_params="client_id=${AUTH0_CLIENT_ID}&request_uri=${request_uri}"

elif [[ ${opt_ciba} -ne 0 ]]; then                    # CIBA
  [[ -z "${opt_login_hint}" ]] && { echo >&2 "login_hint required for CIBA"; exit 1; }
  [[ -z "${opt_binding_message}" ]] && { echo >&2 "opt_binding_message required for CIBA"; exit 1; }
  authorize_params+="&binding_message=$(urlencode "${opt_binding_message}")"

  readonly curl='/opt/homebrew/opt/curl/bin/curl'
  command -v jq >/dev/null || {  echo >&2 "error: jq not found";  exit 3; }

  declare -r auth_req_id=$("${curl}" -s -k --header "accept: application/json" --url "${bc_authorization_endpoint}" \
    -d "${authorize_params}" | jq -r '.auth_req_id')

  echo "auth_req_id: ${auth_req_id}"
  exit 0
fi

declare authorize_url="${authorization_endpoint}?${authorize_params}"

if [[ -n "${opt_session_transfer_token_cookie}" ]]; then
  curl --cookie "auth0_session_transfer_token=${opt_session_transfer_token_cookie}" "${authorize_url}"
fi

if [[ ${opt_pp} -eq 0 ]]; then
  echo "${authorize_url}"
else
    echo "${authorize_url}" | sed -E 's/&/ &\
    /g; s/%20/ /g; s/%3A/:/g;s/%2F/\//g'
fi

[[ -n "${opt_clipboard}" ]] && echo "${authorize_url}" | pbcopy
[[ -n "${opt_open}" ]] && open ${opt_browser} "${authorize_url}"

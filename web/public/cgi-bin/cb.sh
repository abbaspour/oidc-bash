#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2026-06-26
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/main/LICENSE)
#
# cb.sh: CGI callback handler for OAuth2/OIDC redirect_uri.
# Parses QUERY_STRING (GET) or stdin (POST form), renders an HTML key-value table,
# and embeds hash.js so fragment (#) parameters are also displayed client-side.
# Run via: web/server.sh  (python3 -m http.server --cgi)
##########################################################################################

set -uo pipefail

readonly MAX_PARAMS_LEN=65536   # cap processed query/body size to bound CPU/memory on oversized requests

DIR="${BASH_SOURCE[0]%/*}"
[ "$DIR" = "${BASH_SOURCE[0]}" ] && DIR="."
DIR=$(cd "$DIR" && pwd)
readonly DIR

# Decodes only genuine %XX triples. Pre-doubling any literal backslash already present in
# the input stops printf %b from reinterpreting attacker-supplied \n, \e, \cX, etc. as escapes.
url_decode() {
    local data="${1//+/ }"
    data="${data//\\/\\\\}"
    printf '%b' "${data//%/\\x}"
}

html_escape() {
    local s=$1
    s=${s//&/&amp;}
    s=${s//</&lt;}
    s=${s//>/&gt;}
    s=${s//\"/&quot;}
    printf '%s' "$s"
}

# Strips control characters so attacker-influenced values can't forge extra log lines
# or inject terminal escape sequences when this log is viewed/tailed.
sanitize_log() {
    printf '%s' "$1" | tr -d '[:cntrl:]'
}

method="${REQUEST_METHOD:-GET}"
query="${QUERY_STRING:-}"

req_body=''
if [[ "$method" == "POST" && "${CONTENT_TYPE:-}" == application/x-www-form-urlencoded* ]]; then
    content_length="${CONTENT_LENGTH:-0}"
    if [[ "$content_length" =~ ^[0-9]+$ && "$content_length" -gt 0 ]]; then
        read_len=$content_length
        (( read_len > MAX_PARAMS_LEN )) && read_len=$MAX_PARAMS_LEN
        IFS= read -r -N "$read_len" req_body || true
    fi
fi

params="$query"
source_label='query'
if [[ "$method" == "POST" && -n "$req_body" ]]; then
    params="$req_body"
    source_label='form'
fi
[[ ${#params} -gt $MAX_PARAMS_LEN ]] && params="${params:0:$MAX_PARAMS_LEN}"

echo >&2 "[$(date '+%Y-%m-%d %H:%M:%S')] ${method} /cgi-bin/cb.sh${query:+?${query}}"

html_rows=''
if [[ -n "$params" ]]; then
    declare -a pairs
    IFS='&' read -ra pairs <<< "$params"
    for pair in "${pairs[@]}"; do
        key="${pair%%=*}"
        value=''
        [[ "$pair" == *=* ]] && value="${pair#*=}"
        key=$(url_decode "$key")
        value=$(url_decode "$value")
        printf >&2 '  %s = %s\n' "$(sanitize_log "$key")" "$(sanitize_log "$value")"
        html_rows+="<tr><td><b>$(html_escape "$key")</b></td><td><code>$(html_escape "$value")</code> <button type=\"button\" class=\"copy-btn\" title=\"Copy to clipboard\" aria-label=\"Copy to clipboard\">📋</button></td></tr>"
    done
else
    echo >&2 "  (no ${source_label} parameters)"
    html_rows="<tr><td colspan=\"2\"><i>(no ${source_label} parameters)</i></td></tr>"
fi

copy_script=''
[[ -f "${DIR}/../js/copy.js" ]] && copy_script=$(<"${DIR}/../js/copy.js")
jwt_script=''
[[ -f "${DIR}/../js/jwt.js" ]] && jwt_script=$(<"${DIR}/../js/jwt.js")
script_content=''
[[ -f "${DIR}/../js/hash.js" ]] && script_content=$(<"${DIR}/../js/hash.js")
saml_script=''
[[ -f "${DIR}/../js/saml.js" ]] && saml_script=$(<"${DIR}/../js/saml.js")

printf 'Content-Type: text/html; charset=utf-8\nCache-Control: no-store\nX-Frame-Options: DENY\n\n'
cat <<HTML
<!doctype html>
<html><head><meta charset="utf-8"><title>OIDC Callback</title>
<style>body{font-family:sans-serif;max-width:900px;margin:2em auto;padding:0 1em}
table{border-collapse:collapse;width:100%}
td{border:1px solid #ccc;padding:6px 10px;vertical-align:top}
code{word-break:break-all}
.copy-btn{border:none;background:none;cursor:pointer;font-size:0.9em;padding:0 4px;vertical-align:middle}
.copy-btn:hover{opacity:0.7}</style></head>
<body><h1>OIDC Callback</h1>
<table>${html_rows}</table>
<script>${copy_script}</script>
<script>${jwt_script}</script>
<script>${script_content}</script>
<script>${saml_script}</script>
</body></html>
HTML

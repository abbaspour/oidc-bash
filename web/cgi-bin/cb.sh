#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2026-06-26
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/master/LICENSE)
#
# cb.sh: CGI callback handler for OAuth2/OIDC redirect_uri.
# Parses QUERY_STRING (GET) or stdin (POST form), renders an HTML key-value table,
# and embeds hash.js so fragment (#) parameters are also displayed client-side.
# Run via: web/server.sh  (python3 -m http.server --cgi)
##########################################################################################

set -uo pipefail

readonly DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

url_decode() {
    local data="${1//+/ }"
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

method="${REQUEST_METHOD:-GET}"
query="${QUERY_STRING:-}"

req_body=''
if [[ "$method" == "POST" && "${CONTENT_TYPE:-}" == application/x-www-form-urlencoded* ]]; then
    content_length="${CONTENT_LENGTH:-0}"
    [[ "$content_length" =~ ^[0-9]+$ && "$content_length" -gt 0 ]] && \
        IFS= read -r -N "$content_length" req_body || true
fi

params="$query"
source_label='query'
if [[ "$method" == "POST" && -n "$req_body" ]]; then
    params="$req_body"
    source_label='form'
fi

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
        printf >&2 '  %s = %s\n' "$key" "$value"
        html_rows+="<tr><td><b>$(html_escape "$key")</b></td><td><code>$(html_escape "$value")</code></td></tr>"
    done
else
    echo >&2 "  (no ${source_label} parameters)"
    html_rows="<tr><td colspan=\"2\"><i>(no ${source_label} parameters)</i></td></tr>"
fi

script_content=''
[[ -f "${DIR}/../js/hash.js" ]] && script_content=$(<"${DIR}/../js/hash.js")

printf 'Content-Type: text/html; charset=utf-8\n\n'
cat <<HTML
<!doctype html>
<html><head><meta charset="utf-8"><title>OIDC Callback</title>
<style>body{font-family:sans-serif;max-width:900px;margin:2em auto;padding:0 1em}
table{border-collapse:collapse;width:100%}
td{border:1px solid #ccc;padding:6px 10px;vertical-align:top}
code{word-break:break-all}</style></head>
<body><h1>OIDC Callback</h1>
<table>${html_rows}</table>
<script>${script_content}</script>
</body></html>
HTML

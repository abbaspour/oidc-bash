#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2026-06-01
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/master/LICENSE)
#
# callback.sh: A minimal OAuth2/OIDC redirect_uri server.
# Listens on a TCP port using netcat, parses the query string from the incoming
# GET request, and (1) renders an HTML key-value table to the browser and
# (2) prints the same key-value pairs to the console.
##########################################################################################

set -ueo pipefail

readonly DIR=$(dirname "${BASH_SOURCE[0]}")

function usage() {
    cat <<END >&2
USAGE: $0 [-p port] [-v|-h]
        -p port        # TCP port to listen on (default 3000)
        -h|?           # usage
        -v             # verbose (also prints raw request line)

eg,
     $0 -p 3000
END
    exit $1
}

command -v nc >/dev/null 2>&1 || {
    echo >&2 "ERROR: nc (netcat) is not installed. Install with 'brew install netcat' (macOS) or your package manager."
    exit 1
}

declare port=3000
declare opt_verbose=''

[[ -f "${DIR}/.env" ]] && . "${DIR}/.env"

while getopts "p:hv?" opt; do
    case ${opt} in
    p) port=${OPTARG} ;;
    v) opt_verbose=1 ;;
    h | ?) usage 0 ;;
    *) usage 1 ;;
    esac
done

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

handle_request() {
    local request_line line method path query
    if ! IFS= read -r request_line; then return; fi
    request_line=${request_line%$'\r'}

    while IFS= read -r line; do
        line=${line%$'\r'}
        [[ -z "$line" ]] && break
    done

    method=${request_line%% *}
    path=${request_line#* }
    path=${path%% *}

    query=''
    [[ "$path" == *\?* ]] && query="${path#*\?}"

    echo >&2 ''
    echo >&2 "[$(date '+%Y-%m-%d %H:%M:%S')] ${method} ${path}"
    [[ -n "${opt_verbose}" ]] && echo >&2 "  raw: ${request_line}"

    local html_rows=''
    if [[ -n "$query" ]]; then
        local -a pairs
        IFS='&' read -ra pairs <<< "$query"
        for pair in "${pairs[@]}"; do
            local key="${pair%%=*}"
            local value=''
            [[ "$pair" == *=* ]] && value="${pair#*=}"
            key=$(url_decode "$key")
            value=$(url_decode "$value")
            printf >&2 '  %s = %s\n' "$key" "$value"
            html_rows+="<tr><td><b>$(html_escape "$key")</b></td><td><code>$(html_escape "$value")</code></td></tr>"
        done
    else
        echo >&2 '  (no query parameters)'
        html_rows='<tr><td colspan="2"><i>(no query parameters)</i></td></tr>'
    fi

    local body
    body="<!doctype html>
<html><head><meta charset=\"utf-8\"><title>OIDC Callback</title>
<style>body{font-family:sans-serif;max-width:900px;margin:2em auto;padding:0 1em}
table{border-collapse:collapse;width:100%}
td{border:1px solid #ccc;padding:6px 10px;vertical-align:top}
code{word-break:break-all}</style></head>
<body><h1>OIDC Callback</h1>
<table>${html_rows}</table>
</body></html>"

    printf 'HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' "${#body}" "$body"
}

declare RESPONSE_FIFO
RESPONSE_FIFO=$(mktemp -u)
mkfifo "$RESPONSE_FIFO"
trap 'rm -f "$RESPONSE_FIFO"' EXIT INT TERM

echo >&2 "Listening on http://localhost:${port}/  (Ctrl-C to stop)"

# nc reads response bytes from FIFO and forwards to client; bytes received from
# client flow into handle_request, whose stdout writes back into the FIFO.
while true; do
    nc -l "$port" < "$RESPONSE_FIFO" | handle_request > "$RESPONSE_FIFO"
done

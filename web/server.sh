#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2026-06-26
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/main/LICENSE)
#
# server.sh: Starts Python's built-in CGI HTTP server from the web/ directory.
##########################################################################################

set -euo pipefail

declare port=1980

function usage() {
    cat <<END >&2
USAGE: $0 [-p port] [-h]
        -p port        # TCP port to listen on (default ${port})
        -h|?           # usage

eg,
     $0 -p 8080
END
    exit "$1"
}

while getopts "p:h?" opt; do
    case $opt in
    p) port=$OPTARG ;;
    h|?) usage 0 ;;
    *) usage 1 ;;
    esac
done

DIR="${BASH_SOURCE[0]%/*}"
[ "$DIR" = "${BASH_SOURCE[0]}" ] && DIR="."
cd "$DIR"

echo >&2 "Serving at       http://localhost:${port}/"
echo >&2 "Callback URL:    http://localhost:${port}/cgi-bin/cb.sh"
echo >&2 "Callback URL:    http://localhost:${port}/callback"
echo >&2 "(Ctrl-C to stop)"

exec python3 -W ignore::DeprecationWarning -c '
import http.server, sys

def is_callback(path):
    return path.split("?", 1)[0].rstrip("/").endswith("/callback")

class Handler(http.server.CGIHTTPRequestHandler):
    def guess_type(self, path):
        # extension-less "callback" has no extension to guess from; force it to render as HTML
        # instead of the application/octet-stream default (which browsers download rather than show)
        if is_callback(path):
            return "text/html"
        return super().guess_type(path)

    def end_headers(self):
        # each redirect_uri hit carries a distinct code/state query string, so letting the
        # browser cache a 200 and later reuse it via a headerless 304 risks replaying a stale
        # Content-Type; disabling caching keeps every hit a fresh, correctly-typed response
        if is_callback(self.path):
            self.send_header("Cache-Control", "no-store")
        super().end_headers()

http.server.test(HandlerClass=Handler, port=int(sys.argv[1]))
' "$port"

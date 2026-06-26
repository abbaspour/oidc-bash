#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2026-06-26
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/master/LICENSE)
#
# server.sh: Starts Python's built-in CGI HTTP server from the web/ directory.
##########################################################################################

set -euo pipefail

declare port=3000

function usage() {
    cat <<END >&2
USAGE: $0 [-p port] [-h]
        -p port        # TCP port to listen on (default ${port})
        -h|?           # usage

eg,
     $0 -p 8080
END
    exit $1
}

while getopts "p:h?" opt; do
    case $opt in
    p) port=$OPTARG ;;
    h|?) usage 0 ;;
    *) usage 1 ;;
    esac
done

cd "$(dirname "${BASH_SOURCE[0]}")"

echo >&2 "Serving at       http://localhost:${port}/"
echo >&2 "Callback URL:    http://localhost:${port}/cgi-bin/cb.sh"
echo >&2 "(Ctrl-C to stop)"

exec python3 -W ignore::DeprecationWarning -m http.server --cgi "$port"

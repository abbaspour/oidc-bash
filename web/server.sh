#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2026-06-26
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/main/LICENSE)
#
# server.sh: Starts Python's built-in HTTP server from web/public, executing cgi-bin/ scripts as CGI.
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
cd "$DIR/public"

echo >&2 "Serving at       http://localhost:${port}/"
echo >&2 "Callback URL:    http://localhost:${port}/cgi-bin/cb.sh"
echo >&2 "Callback URL:    http://localhost:${port}/callback"
echo >&2 "(Ctrl-C to stop)"

exec python3 -c '
import http.server, os, subprocess, sys

def is_callback(path):
    return path.split("?", 1)[0].rstrip("/").endswith("/callback")

# CGIHTTPRequestHandler was removed in Python 3.15, so cgi-bin/ scripts are run here directly
class Handler(http.server.SimpleHTTPRequestHandler):
    def cgi_script(self):
        path = self.path.split("?", 1)[0]
        if not path.startswith("/cgi-bin/"):
            return None
        name = path[len("/cgi-bin/"):]
        script = os.path.join(os.getcwd(), "cgi-bin", name)
        if not name or "/" in name or name.startswith(".") or not os.path.isfile(script):
            self.send_error(404, "No such CGI script")
            return ""
        if not os.access(script, os.X_OK):
            self.send_error(403, "CGI script is not executable")
            return ""
        return script

    def run_cgi(self, script):
        query = self.path.split("?", 1)[1] if "?" in self.path else ""
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length > 0 else b""
        env = dict(os.environ,
                   GATEWAY_INTERFACE="CGI/1.1",
                   SERVER_SOFTWARE=self.version_string(),
                   SERVER_NAME=self.server.server_name,
                   SERVER_PORT=str(self.server.server_port),
                   SERVER_PROTOCOL=self.protocol_version,
                   REQUEST_METHOD=self.command,
                   SCRIPT_NAME=self.path.split("?", 1)[0],
                   QUERY_STRING=query,
                   REMOTE_ADDR=self.client_address[0],
                   CONTENT_TYPE=self.headers.get("Content-Type", ""),
                   CONTENT_LENGTH=str(len(body)))
        for k, v in self.headers.items():
            env["HTTP_" + k.upper().replace("-", "_")] = v
        # stderr is inherited so the script logs straight to this terminal
        result = subprocess.run([script], input=body, stdout=subprocess.PIPE, env=env)
        if result.returncode != 0:
            self.log_error("CGI script exit status %#x", result.returncode)
        # the script emits its own headers and blank line, as the removed handler expected
        self.send_response(200, "Script output follows")
        self.flush_headers()
        self.wfile.write(result.stdout)

    def do_GET(self):
        script = self.cgi_script()
        if script is None:
            return super().do_GET()
        if script:
            self.run_cgi(script)

    def do_POST(self):
        script = self.cgi_script()
        if script is None:
            return self.send_error(501, "Can only POST to CGI scripts")
        if script:
            self.run_cgi(script)

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

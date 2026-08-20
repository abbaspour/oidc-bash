#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2026-08-20
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/main/LICENSE)
#
# decrypt-jwe.sh: decrypts a compact JWE token with a private key and prints its
# decoded header and payload.
##########################################################################################

set -euo pipefail

command -v node >/dev/null || { echo >&2 "error: node not found"; exit 3; }
command -v jq >/dev/null || { echo >&2 "error: jq not found"; exit 3; }

declare pem_file=''
declare opt_verbose=0

function usage() {
    cat <<END >&2
USAGE: $0 -p pem [token] [-v|-h]
        -p pem         # private key PEM file (decryption key)
        -h|?           # usage
        -v             # verbose

token is read from the first positional argument, else stdin, else \$id_token.

eg,
     $0 -p ../ca/myapi-private.pem "eyJhbGc...jwe.compact.token"
     echo "\${JWE}" | $0 -p ../ca/myapi-private.pem
END
    exit "$1"
}

while getopts "p:hv?" opt; do
    case ${opt} in
    p) pem_file=${OPTARG} ;;
    v) opt_verbose=1 ;; #set -x;;
    h | ?) usage 0 ;;
    *) usage 1 ;;
    esac
done
shift $((OPTIND - 1))

[[ -z "${pem_file}" ]] && { echo >&2 "ERROR: pem_file undefined"; usage 1; }
[[ -f "${pem_file}" ]] || { echo >&2 "ERROR: pem_file missing: ${pem_file}"; usage 1; }

declare jwe
if [[ $# -ge 1 ]]; then
    jwe=$1
elif [[ ! -t 0 ]]; then
    read -r jwe || true
else
    jwe=${id_token:-}
fi

[[ -z "${jwe}" ]] && { echo >&2 "ERROR: no JWE token provided"; usage 1; }

[[ ${opt_verbose} -eq 1 ]] && echo >&2 "decrypting with key: ${pem_file}"

declare node_output
node_output=$(PEM_FILE="${pem_file}" JWE_TOKEN="${jwe}" node <<'NODE'
import * as jose from 'jose';
import crypto from 'node:crypto';
import fs from 'node:fs';

const pem = fs.readFileSync(process.env.PEM_FILE, 'utf8');
const privateKey = crypto.createPrivateKey(pem);

const { plaintext, protectedHeader } = await jose.compactDecrypt(process.env.JWE_TOKEN, privateKey);

const text = Buffer.from(plaintext).toString('utf8');

process.stdout.write(JSON.stringify(protectedHeader) + '\n');
process.stdout.write(JSON.stringify(text) + '\n');
NODE
)
readonly node_output

echo "header:"
sed -n '1p' <<<"${node_output}" | jq .

declare payload_text
payload_text=$(sed -n '2p' <<<"${node_output}" | jq -r .)

echo "payload:"
if [[ "${payload_text}" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$ ]]; then
    # plaintext is itself a JWS (eg. a nested signed id_token) -- decode its payload; signature not verified
    jq -Rr 'split(".")[1] | gsub("-";"+") | gsub("_";"/") | gsub("%3D";"=") | @base64d | fromjson' <<<"${payload_text}"
elif jq -e . >/dev/null 2>&1 <<<"${payload_text}"; then
    jq . <<<"${payload_text}"
else
    printf '%s\n' "${payload_text}"
fi

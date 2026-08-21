#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2026-08-20
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/main/LICENSE)
#
# build-jwks.sh: Scans a folder for RSA/EC private key PEM files and builds a public
# jwks.json from them (two entries per key: use=sig and use=enc), suitable for serving
# as a jwks_uri -- eg. for JWT client-assertion (sig) or id_token JWE decryption (enc).
##########################################################################################

set -euo pipefail

command -v openssl >/dev/null || { echo >&2 "error: openssl not found"; exit 3; }
command -v node >/dev/null || { echo >&2 "error: node not found"; exit 3; }

function usage() {
    cat <<END >&2
USAGE: $0 [-p path] [-k file] [-o output] [-h]
        -p path        # folder to scan for private key .pem files (default: current folder)
        -k file        # single private key file (skips scanning -p)
        -o output      # output JWKS file (default: jwks.json)
        -h|?           # usage

eg,
     $0 -p .
     $0 -k ec-LTYPNWQG14-private.pem -o ec-jwks.json
END
    exit "$1"
}

declare search_path='.'
declare single_key=''
declare output_file='jwks.json'

while getopts "p:k:o:h?" opt; do
    case $opt in
    p) search_path=$OPTARG ;;
    k) single_key=$OPTARG ;;
    o) output_file=$OPTARG ;;
    h | ?) usage 0 ;;
    *) usage 1 ;;
    esac
done

# resolve to absolute paths against the caller's cwd before we cd anywhere below
function abspath() {
    local p=$1
    [[ "$p" = /* ]] && printf '%s\n' "$p" || printf '%s\n' "$PWD/$p"
}

search_path=$(abspath "$search_path")
output_file=$(abspath "$output_file")
[[ -n "$single_key" ]] && single_key=$(abspath "$single_key")

# cd into the script's own directory so node resolves the `jose` dependency
# from ca/node_modules regardless of the caller's cwd (all paths above are now absolute)
DIR="${BASH_SOURCE[0]%/*}"
[ "$DIR" = "${BASH_SOURCE[0]}" ] && DIR="."
cd "$(cd "$DIR" && pwd)"

declare -a key_files=()
if [[ -n "$single_key" ]]; then
    [[ -f "$single_key" ]] || { echo >&2 "ERROR: key file not found: ${single_key}"; exit 1; }
    openssl pkey -in "$single_key" -noout >/dev/null 2>&1 || { echo >&2 "ERROR: not a private key: ${single_key}"; exit 1; }
    key_files=("$single_key")
else
    [[ -d "$search_path" ]] || { echo >&2 "ERROR: path not found: ${search_path}"; exit 1; }
    while IFS= read -r -d '' f; do
        openssl pkey -in "$f" -noout >/dev/null 2>&1 && key_files+=("$f")
    done < <(find "$search_path" -maxdepth 1 -type f -name '*.pem' -print0 | sort -z)
fi

[[ ${#key_files[@]} -eq 0 ]] && { echo >&2 "ERROR: no private keys found in ${single_key:-$search_path}"; exit 1; }

declare -a tmpfiles=()
function cleanup() { [[ ${#tmpfiles[@]} -gt 0 ]] && rm -f "${tmpfiles[@]}"; }
trap cleanup EXIT

descriptor_file=$(mktemp)
tmpfiles+=("$descriptor_file")

for f in "${key_files[@]}"; do
    name="${f##*/}"
    name="${name%.pem}"
    name="${name%-private}"

    text=$(openssl pkey -in "$f" -noout -text 2>/dev/null)
    if [[ "$text" == *"ASN1 OID:"* ]]; then
        curve=$(awk '/ASN1 OID:/{print $3; exit}' <<<"$text")
        case "$curve" in
        prime256v1) sig_alg=ES256 ;;
        secp384r1) sig_alg=ES384 ;;
        secp521r1) sig_alg=ES512 ;;
        *) sig_alg=ES256 ;;
        esac
        enc_alg='ECDH-ES'
    else
        sig_alg=RS256
        enc_alg='RSA-OAEP-256'
    fi

    pubfile=$(mktemp)
    tmpfiles+=("$pubfile")
    openssl pkey -in "$f" -pubout -out "$pubfile" 2>/dev/null

    echo >&2 "processing ${f##*/}: name=${name} sig=${sig_alg} enc=${enc_alg}"
    printf '%s\t%s\t%s\t%s\n' "$pubfile" "$name" "$sig_alg" "$enc_alg" >>"$descriptor_file"
done

DESCRIPTOR_FILE="$descriptor_file" OUTPUT_FILE="$output_file" node <<'NODE'
import * as jose from 'jose';
import fs from 'node:fs';
import readline from 'node:readline';

const rl = readline.createInterface({ input: fs.createReadStream(process.env.DESCRIPTOR_FILE) });
const keys = [];

for await (const line of rl) {
    if (!line.trim()) continue;
    const [pubfile, name, sigAlg, encAlg] = line.split('\t');
    const pem = fs.readFileSync(pubfile, 'utf8');

    const sigKey = await jose.importSPKI(pem, sigAlg, { extractable: true });
    const sigJwk = await jose.exportJWK(sigKey);
    sigJwk.use = 'sig';
    sigJwk.alg = sigAlg;
    sigJwk.kid = name + '-sig';
    keys.push(sigJwk);

    const encKey = await jose.importSPKI(pem, encAlg, { extractable: true });
    const encJwk = await jose.exportJWK(encKey);
    encJwk.use = 'enc';
    encJwk.alg = encAlg;
    encJwk.kid = name + '-enc';
    keys.push(encJwk);
}

fs.writeFileSync(process.env.OUTPUT_FILE, JSON.stringify({ keys }, null, 2) + '\n');
console.error(`wrote ${keys.length} keys to ${process.env.OUTPUT_FILE}`);
NODE

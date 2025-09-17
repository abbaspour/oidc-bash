#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2025-08-18
# License: MIT (https://github.com/abbaspour/auth0-bash/blob/master/LICENSE)
##########################################################################################

set -euo pipefail

command -v node >/dev/null || {  echo >&2 "error: node not found";  exit 3; }

function usage() {
    cat <<END >&2
USAGE: $0 [-i key.jks] [-o key.pem] [-v|-h]
        -i file        # input JKS file
        -o file        # output PEM file
        -h|?           # usage
        -v             # verbose

eg,
     $0 -f mykey.jks -o mykey-pkcs8.pem
END
    exit $1
}

declare input_file
declare output_file='output-pkcs8.pem'

while getopts "i:o:hv?" opt; do
    case ${opt} in
    i) input_file=${OPTARG} ;;
    o) output_file=${OPTARG} ;;
    v) opt_verbose=1 ;; #set -x;;
    h | ?) usage 0 ;;
    *) usage 1 ;;
    esac
done

[[ -z "${input_file}" ]] && { echo >&2 "ERROR: input file undefined";  usage 1; }
[[ ! -f "${input_file}" ]] && { echo >&2 "ERROR: unable to read file: ${input_file}";  usage 1; }

cat <<EOL | node
import * as jose from 'jose';
import fs from 'node:fs';

//const jwk = {"kty": "EC", "d": "xxxx", "use": "sig", "crv": "P-256", "kid": "xxx", "x": "x", "y": "x", "alg": "ES256"};
const jwk = JSON.parse(fs.readFileSync("${input_file}", 'utf8'))

const key = await jose.importJWK(jwk, 'ES256', {extractable: true});
const pkcs8Pem = await jose.exportPKCS8(key);

//console.log(pkcs8Pem);
fs.writeFileSync("${output_file}", pkcs8Pem);
EOL
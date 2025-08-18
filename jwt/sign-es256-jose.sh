#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2025-08-18
# License: MIT (https://github.com/abbaspour/auth0-bash/blob/master/LICENSE)
##########################################################################################

set -euo pipefail

command -v openssl >/dev/null || {  echo >&2 "error: openssl not found";  exit 3; }

function usage() {
    cat <<END >&2
USAGE: $0 [-f json] [-i iss] [-a aud] [-k kid] [-p private-key] [-v|-h]
        -f file        # JSON file to sign
        -p pem         # private key PEM file
        -i iss         # issuer
        -a aud         # audience
        -k kid         # Key ID
        -t ttl         # TTL in seconds, default is 5min
        -T type        # type, defaults to "jwt"
        -h|?           # usage
        -v             # verbose

eg,
     $0 -f file.json -a http://my.api -i http://some.issuer -k 1 -p ../ca/myapi-private.pem
END
    exit $1
}

# Token validity (seconds)
declare -i TTL=100

while getopts "f:i:a:k:p:t:hv?" opt; do
    case ${opt} in
    f) json_file=${OPTARG} ;;
    i) CLIENT_ID=${OPTARG} ;;
    a) AUDIENCE=${OPTARG} ;;
    k) KID=${OPTARG} ;;
    p) ORIG_KEY=${OPTARG} ;;
    t) TTL=${OPTARG} ;;
    T) typ=${OPTARG} ;;
    v) opt_verbose=1 ;; #set -x;;
    h | ?) usage 0 ;;
    *) usage 1 ;;
    esac
done

[[ -z "${KID}" ]] && { echo >&2 "ERROR: KID undefined.";  usage 1; }

[[ -f "${ORIG_KEY}" ]] || { echo >&2 "ERROR: ORIG_KEY missing: ${pem_file}"; usage 1; }
[[ -z "${json_file}" ]] && { echo >&2 "ERROR: json_file undefined";  usage 1; }

[[ ! -f "${json_file}" ]] && { echo >&2 "json_file: unable to read file: ${json_file}";  usage 1; }


cat <<EOL | node
import {SignJWT} from 'jose/jwt/sign';
import {parseJwk} from 'jose/jwk/parse';
import fs from 'node:fs';

const jwk = JSON.parse(fs.readFileSync("${ORIG_KEY}", 'utf8'))

const key = await parseJwk(jwk, 'ES256');

const signature = await new SignJWT({})
    .setProtectedHeader({alg: 'ES256', kid: "${KID}", typ: 'JWT'})
    .setIssuedAt()
    .setIssuer("${CLIENT_ID}")
    .setSubject("${CLIENT_ID}")
    .setAudience("${AUDIENCE}")
    .setExpirationTime('2m') // NDI will not accept tokens with an exp longer than 2 minutes since iat.
    .sign(key);

console.log(signature);
EOL

#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2024-07-26
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/master/LICENSE)
##########################################################################################

set -euo pipefail

command -v openssl >/dev/null || { echo >&2 "error: openssl not found"; exit 3; }
command -v jq >/dev/null || { echo >&2 "error: jq not found"; exit 3; }
command -v xxd >/dev/null || { echo >&2 "error: xxd not found"; exit 3; }

function usage() {
    cat <<END >&2
USAGE: $0 -p pem_file -m http_method -u http_uri [-a alg] [-h]
        -p pem_file     # private key PEM file
        -m http_method  # HTTP method (e.g., POST)
        -u http_uri     # HTTP URI (e.g., https://server.com/token)
        -a alg          # algorithm (optional, auto-detected from key type: RS256 for RSA, ES256 for EC)
        -h|?            # usage
END
    exit $1
}

declare pem_file=''
declare http_method=''
declare http_uri=''
declare alg=''

while getopts "p:m:u:a:h?" opt; do
    case ${opt} in
        p) pem_file=${OPTARG};;
        m) http_method=${OPTARG};;
        u) http_uri=${OPTARG};;
        a) alg=${OPTARG};;
        h|?) usage 0;;
        *) usage 1;;
    esac
done

[[ -z "${pem_file}" ]] && { echo >&2 "ERROR: pem_file undefined."; usage 1; }
[[ ! -f "${pem_file}" ]] && { echo >&2 "ERROR: pem_file missing: ${pem_file}"; usage 1; }
[[ -z "${http_method}" ]] && { echo >&2 "ERROR: http_method undefined."; usage 1; }
[[ -z "${http_uri}" ]] && { echo >&2 "ERROR: http_uri undefined."; usage 1; }

# Function to base64url encode
base64url() {
    openssl base64 -e -A | tr '+' '-' | tr '/' '_' | sed -E 's/=+$//'
}

# Extract public key components and create JWK
if openssl rsa -in "${pem_file}" -check >/dev/null 2>&1; then
    [[ -z "${alg}" ]] && alg='RS256'
    pub_key_details=$(openssl rsa -in "${pem_file}" -text -noout)
    n=$(echo "${pub_key_details}" | awk '/modulus:/{flag=1;next}/publicExponent:/{flag=0}flag' | tr -d '[:space:]:' | xxd -r -p | base64url)
    e_hex=$(echo "${pub_key_details}" | awk '/publicExponent:/ {print $2}' | sed 's/.*(0x\(.*\))/\1/')
    e=$(echo -n "${e_hex}" | xxd -r -p | base64url)
    jwk=$(printf '{"kty":"RSA","n":"%s","e":"%s"}' "${n}" "${e}")
elif openssl ec -in "${pem_file}" -check >/dev/null 2>&1; then
    [[ -z "${alg}" ]] && alg='ES256'
    pub_key_details=$(openssl ec -in "${pem_file}" -text -noout)
    crv_name=$(echo "${pub_key_details}" | awk -F':' '/ASN1 OID: / {print $2}' | tr -d '[:space:]')
    pub_hex=$(echo "${pub_key_details}" | awk '/pub:/{flag=1;next}/ASN1 OID:/{flag=0}flag' | tr -d '[:space:]:' | sed 's/^04//')
    x_hex=$(echo "${pub_hex}" | cut -c 1-64)
    y_hex=$(echo "${pub_hex}" | cut -c 65-128)
    x=$(echo -n "${x_hex}" | xxd -r -p | base64url)
    y=$(echo -n "${y_hex}" | xxd -r -p | base64url)
    jwk=$(printf '{"kty":"EC","crv":"%s","x":"%s","y":"%s"}' "${crv_name}" "${x}" "${y}")
else
    echo >&2 "ERROR: Unsupported key type. Only RSA and EC keys are supported for DPoP generation."
    exit 1
fi

# Create Header
header=$(printf '{"typ":"dpop+jwt","alg":"%s","jwk":%s}' "${alg}" "${jwk}" | base64url)

# Create Payload
iat=$(date +%s)
jti=$(openssl rand -hex 16)
payload=$(printf '{"iat":%s,"jti":"%s","htm":"%s","htu":"%s"}' "${iat}" "${jti}" "${http_method}" "${http_uri}" | base64url)

# Sign
signature=$(echo -n "${header}.${payload}" | openssl dgst -sha256 -sign "${pem_file}" -binary | base64url)

# Assemble JWT
echo "${header}.${payload}.${signature}"

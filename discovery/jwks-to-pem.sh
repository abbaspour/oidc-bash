#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2022-06-12
# License: MIT (https://github.com/abbaspour/auth0-bash/blob/master/LICENSE)
#
# Note: this script only works for key types kty RSA and does not support EC
##########################################################################################

# downloads x5c of jwks.json into a PEM file

set -eo pipefail

command -v curl >/dev/null || { echo >&2 "error: curl not found";  exit 3; }
command -v jq >/dev/null || {  echo >&2 "error: jq not found";  exit 3; }
command -v fold &>/dev/null || { echo >&2 "ERROR: fold not found"; exit 3; }
command -v openssl &>/dev/null || { echo >&2 "ERROR: openssl not found"; exit 3; }

function usage() {
    cat <<END >&2
USAGE: $0 [-e file] [-t tenant] [-d domain] [-k kid] [-a alg]
        -e file        # .env file location (default cwd)
        -t tenant      # Auth0 tenant@region
        -d domain      # Auth0 domain
        -u url         # JWKS url
        -k kid         # (optional) kid (exporting all KIDs if absent)
        -a alg         # (optional) algorithm to filter by (exporting all algorithms if absent)
        -y typ         # (optional) key type to filter by (exporting all keys if absent)
        -D             # Dump certificate
        -h|?           # usage
        -v             # verbose

eg,
     $0 -t amin01@au
     $0 -t amin01@au -a RS256
END
    exit $1
}

declare AUTH0_DOMAIN=''
declare opt_dump=''
declare jwks_url=''
declare KID=''
declare ALG=''
declare KTY=''

while getopts "e:t:d:f:u:k:a:y:Dhv?" opt; do
    case ${opt} in
    e) source "${OPTARG}" ;;
    t) AUTH0_DOMAIN=$(echo "${OPTARG}.auth0.com" | tr '@' '.') ;;
    d) AUTH0_DOMAIN=${OPTARG} ;;
    u) jwks_url=${OPTARG} ;;
    f) cert_file=${OPTARG} ;;
    k) KID=${OPTARG} ;;
    a) ALG=${OPTARG} ;;
    y) KTY=${OPTARG} ;;
    D) opt_dump=1 ;;
    v) set -x ;;
    h | ?) usage 0 ;;
    *) usage 1 ;;
    esac
done

if [[ -z "${jwks_url}" ]]; then
    [[ -z "${AUTH0_DOMAIN}" ]] && { echo >&2 "ERROR: AUTH0_DOMAIN undefined"; usage 1; }
    jwks_url=$(curl -s "https://${AUTH0_DOMAIN}/.well-known/openid-configuration" | jq -r '.jwks_uri')
else
    AUTH0_DOMAIN='generic'
fi

declare jwks_json=$(curl -s "${jwks_url}")

for k in $(echo "${jwks_json}" | jq -r '.keys[] .kid'); do
    [[ -n "${KID}" && ! "${k}" =~ ${KID} ]] && continue

    # Get all algorithms for this kid
    declare key_algs=($(echo "${jwks_json}" | jq -r ".keys[] | select(.kid==\"${k}\") | .alg"))

    for key_alg in "${key_algs[@]}"; do
        # Skip if ALG is specified and doesn't match this key's algorithm
        [[ -n "${ALG}" && "${key_alg}" != "${ALG}" ]] && continue

        # Get the key type (kty)
        declare key_type=$(echo "${jwks_json}" | jq -r ".keys[] | select(.kid==\"${k}\" and .alg==\"${key_alg}\") | .kty")
        [[ -n "${KTY}" && "${key_type}" != "${KTY}" ]] && continue

        echo "Exporting KID: ${k}, Algorithm: ${key_alg}, Key Type: ${key_type}"
        declare cert_file="${AUTH0_DOMAIN}-${k}-${key_alg}-certificate.pem"
        declare public_key_file="${AUTH0_DOMAIN}-${k}-${key_alg}-public_key.pem"

        if [[ "${key_type}" == "RSA" ]]; then
            # Process RSA key using x5c certificate
            declare x5c=$(echo "${jwks_json}" | jq -r ".keys[] | select(.kid==\"${k}\" and .alg==\"${key_alg}\") | .x5c[0]")

            if [[ -n "${x5c}" && "${x5c}" != "null" ]]; then
                echo '-----BEGIN CERTIFICATE-----' >"${cert_file}"
                echo "$x5c" | fold -w64 >>"${cert_file}"
                echo '-----END CERTIFICATE-----' >>"${cert_file}"

                openssl x509 -in "${cert_file}" -pubkey -noout >"${public_key_file}"

                [[ ${opt_dump} ]] && openssl x509 -in "${cert_file}" -text -noout
            else
                echo "  Warning: No x5c certificate found for RSA key ${k}"
                continue
            fi
        elif [[ "${key_type}" == "EC" ]]; then
            echo "  Warning: Unsupported key type ${key_type} for key ${k}"
            continue
        else
            echo "  Warning: Unsupported key type ${key_type} for key ${k}"
            continue
        fi

        echo "  cert_file: ${cert_file}"
        echo "  public_key_file: ${public_key_file}"
    done
done

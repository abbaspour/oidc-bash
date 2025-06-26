#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2022-06-12
# License: MIT (https://github.com/abbaspour/auth0-bash/blob/master/LICENSE)
##########################################################################################

set -eo pipefail

command -v openssl >/dev/null || { echo >&2 "error: openssl not found";  exit 3; }

function usage() {
    cat <<END >&2
USAGE: $0 [-n domain] [-e]
        -n name     # name of key pair (default is your hostname)
        -e          # Generate EC key (default is RSA)
        -h|?        # usage
        -v          # verbose

eg,
     $0 -n backend-api
     $0 -n backend-api -e
END
    exit $1
}

declare pair_name=$(hostname)
declare opt_verbose=0
declare ec_mode=0
declare key_type_prefix="rsa" # Default prefix

while getopts "n:ehv?" opt; do
    case ${opt} in
    n) pair_name=${OPTARG} ;;
    e) ec_mode=1; key_type_prefix="ec" ;;
    v) opt_verbose=1 ;; #set -x;;
    h | ?) usage 0 ;;
    *) usage 1 ;;
    esac
done

[[ -z "${pair_name}" ]] && { echo >&2 "ERROR: pair_name undefined.";  usage 1; }

# Add the prefix to the filenames
declare -r private_key="${key_type_prefix}-${pair_name}-private.pem"
declare -r cert_key="${key_type_prefix}-${pair_name}-cert.pem"
declare -r public_key="${key_type_prefix}-${pair_name}-public.pem"

cat >openssl.cnf <<-EOF
  [req]
  distinguished_name = req_distinguished_name
  x509_extensions = v3_req
  prompt = no
EOF

if [[ "${ec_mode}" -eq 1 ]]; then
    # For EC, we define the curve
    cat >>openssl.cnf <<-EOF
  default_md            = sha256
  req_extensions        = v3_req
  [req_distinguished_name]
  CN = ${pair_name}
  [v3_req]
  keyUsage = keyEncipherment, dataEncipherment
  extendedKeyUsage = serverAuth
EOF
    # Generate EC private key and CSR
    openssl ecparam -genkey -name prime256v1 -noout -out "${private_key}"
    openssl req -x509 -nodes -days 3650 -key "${private_key}" -sha256 -new -config openssl.cnf -out "${cert_key}"
else
    # Default to RSA
    cat >>openssl.cnf <<-EOF
  default_bits            = 2048
  [req_distinguished_name]
  CN = ${pair_name}
  [v3_req]
  keyUsage = keyEncipherment, dataEncipherment
  extendedKeyUsage = serverAuth
EOF
    # Generate RSA private key and CSR
    openssl req -x509 -nodes -days 3650 -new -config openssl.cnf -keyout "${private_key}" -out "${cert_key}"
fi

openssl x509 -inform PEM -in "${cert_key}" -pubkey -noout >"${public_key}"

rm openssl.cnf
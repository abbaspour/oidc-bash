#!/usr/bin/env bash

# dpop.sh: A script to generate DPoP JWTs for EC keys using OpenSSL.
# Follows the specification RFC 9449.

set -e
set -o pipefail

# --- Configuration ---
# Modify the command path for openssl if needed.
OPENSSL_CMD="/opt/homebrew/bin/openssl"

# --- Default Values ---
METHOD="POST"

# --- Function Definitions ---

# URL-safe base64 encoding
# RFC 4648 sec 5: '+' -> '-', '/' -> '_', remove '=' padding
base64url_encode() {
    ${OPENSSL_CMD} base64 -e -A | tr -- '+/' '-_' | tr -d '='
}

# Simple error logging and exit
fail() {
    echo "Error: $1" >&2
    exit 1
}

# --- Argument Parsing with getopts ---
while getopts ":r:m:u:" opt; do
  case ${opt} in
    r )
      PRIVATE_KEY_FILE=$OPTARG
      ;;
    m )
      METHOD=$OPTARG
      ;;
    u )
      URL=$OPTARG
      ;;
    \? )
      fail "Invalid option: -$OPTARG"
      ;;
    : )
      fail "Invalid option: -$OPTARG requires an argument"
      ;;
  esac
done

# --- Validate Inputs ---
if [ -z "${PRIVATE_KEY_FILE}" ]; then
    fail "Private key file is required. Use -r <private-key-file>"
fi
if [ ! -f "${PRIVATE_KEY_FILE}" ]; then
    fail "Private key file not found at ${PRIVATE_KEY_FILE}"
fi
if [ -z "${URL}" ]; then
    fail "URL is required. Use -u <url>"
fi
if [ -z "${METHOD}" ]; then
    fail "Method is required. Use -m <method>"
fi

# --- Main Script Logic ---

# 1. Derive Public Key from the Private Key
PUBLIC_KEY=$(${OPENSSL_CMD} ec -in "${PRIVATE_KEY_FILE}" -pubout 2>/dev/null)
if [ $? -ne 0 ]; then
    fail "Failed to derive public key from the private key."
fi

# 2. Extract EC key parameters (crv, x, y) to build the JWK.
# We use openssl to get the key details in a parsable format.
# The curve name from OpenSSL needs to be mapped to the RFC JWK 'crv' name.
# For prime256v1 (secp256r1), the crv is "P-256".
CURVE_NAME=$(cat "${PRIVATE_KEY_FILE}" | ${OPENSSL_CMD} ec -noout -text 2>/dev/null | grep "ASN1 OID" | awk '{print $3}')
case ${CURVE_NAME} in
    "prime256v1")
        CRV="P-256"
        ;;
    # Add other curves here if needed, e.g., secp384r1 -> P-384
    *)
        fail "Unsupported EC curve: ${CURVE_NAME}. This script currently only supports prime256v1 (P-256)."
        ;;
esac

readonly coords="$(echo "${PUBLIC_KEY}" | ${OPENSSL_CMD} ec -pubin -noout -text -conv_form uncompressed 2>/dev/null | grep -E "^ +.*" | tr -d ' \n' | sed 's/^...//' | tr -d ':')"

readonly X_HEX=${coords:0:${#coords}/2} # first half
readonly Y_HEX=${coords:${#coords}/2}   # second half


# Convert hex coordinates to base64url
X_B64=$(echo "${X_HEX}" | xxd -r -p | base64url_encode)
Y_B64=$(echo "${Y_HEX}" | xxd -r -p | base64url_encode)

# 3. Construct JWT Header with the JWK
# The header contains the algorithm (ES256) and the public key as a JWK.
JWK="{\"kty\":\"EC\",\"crv\":\"${CRV}\",\"x\":\"${X_B64}\",\"y\":\"${Y_B64}\"}"
HEADER="{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":${JWK}}"
ENCODED_HEADER=$(echo -n "${HEADER}" | base64url_encode)

# 4. Construct JWT Payload
# It includes a unique token identifier (jti), the HTTP method (htm),
# the HTTP URI (htu), and the issued-at timestamp (iat).
JTI=$(${OPENSSL_CMD} rand -hex 16)
IAT=$(date +%s)
PAYLOAD="{\"jti\":\"${JTI}\",\"htm\":\"${METHOD}\",\"htu\":\"${URL}\",\"iat\":${IAT}}"
ENCODED_PAYLOAD=$(echo -n "${PAYLOAD}" | base64url_encode)

# 5. Create the Signing Input
SIGNING_INPUT="${ENCODED_HEADER}.${ENCODED_PAYLOAD}"

# 6. Sign, Parse, and Convert the Signature
# The signing input is signed, and the resulting binary DER signature is
# piped directly to `openssl asn1parse` to robustly extract the R and S integers.
HEX_VALUES=$(echo -n "${SIGNING_INPUT}" \
    | ${OPENSSL_CMD} dgst -sha256 -sign "${PRIVATE_KEY_FILE}" -binary \
    | ${OPENSSL_CMD} asn1parse -inform DER \
    | grep "INTEGER" | awk '{print $NF}' | tr -d ':')

# Separate r and s
R_HEX=$(echo "${HEX_VALUES}" | head -n 1)
S_HEX=$(echo "${HEX_VALUES}" | tail -n 1)

# The integers r and s may have a leading '00' byte if their first bit is 1.
# This is to ensure they are parsed as positive numbers. We must strip this
# leading '00' byte if it exists and the hex string is longer than 64 characters (32 bytes).
if [ ${#R_HEX} -gt 64 ]; then
    R_HEX=${R_HEX: -64}
fi
if [ ${#S_HEX} -gt 64 ]; then
    S_HEX=${S_HEX: -64}
fi

# The final signature is the concatenation of r and s.
RAW_SIGNATURE_HEX="${R_HEX}${S_HEX}"

# 7. Base64url Encode the Raw Signature
ENCODED_SIGNATURE=$(echo "${RAW_SIGNATURE_HEX}" | xxd -r -p | base64url_encode)

# 8. Assemble the final DPoP JWT
DPOP_JWT="${SIGNING_INPUT}.${ENCODED_SIGNATURE}"

# --- Output the JWT ---
echo "${DPOP_JWT}"

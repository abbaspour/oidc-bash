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

b64url(){ openssl base64 -A | tr '+/' '-_' | tr -d '='; }

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

# ----------------------------------------

hex_left_pad_to_bytes(){
  local hex="${1^^}" want_bytes="$2"
  hex="${hex#0X}"
  hex="$(printf '%s' "$hex" | tr -d '[:space:]')"
  # drop leading 00 if total > want
  while [[ ${#hex} -gt 0 && "${hex:0:2}" == "00" && $(( ${#hex}/2 > want_bytes )) == 1 ]]; do
    hex="${hex:2}"
  done
  (( ${#hex} % 2 )) && hex="0$hex"
  local need=$(( want_bytes*2 ))
  while (( ${#hex} < need )); do hex="0$hex"; done
  while (( ${#hex} > need )); do hex="${hex:2}"; done
  printf '%s' "$hex"
}

der_to_raw_rs(){
  local der="$1"
  mapfile -t ints < <(openssl asn1parse -inform DER -in "$der" -dump | awk '/prim:[[:space:]]*INTEGER/ {print}' | head -n 2)
  if (( ${#ints[@]} < 2 )); then
    echo "ERROR: Could not find r/s in ECDSA DER signature" >&2
    openssl asn1parse -inform DER -in "$der" || true
    return 1
  fi
  local r_hex s_hex
  r_hex="$(printf '%s\n' "${ints[0]}" | sed -E 's/.*:([0-9A-Fa-f]+)$/\1/')"
  s_hex="$(printf '%s\n' "${ints[1]}" | sed -E 's/.*:([0-9A-Fa-f]+)$/\1/')"
  r_hex="$(hex_left_pad_to_bytes "$r_hex" 32)"
  s_hex="$(hex_left_pad_to_bytes "$s_hex" 32)"
  printf '%s%s' "$r_hex" "$s_hex" | xxd -r -p
}

# --- normalize key: convert SEC1 → PKCS#8 if needed ---
TMPKEY=""
if grep -q "BEGIN EC PRIVATE KEY" "$ORIG_KEY"; then
  TMPKEY="$(mktemp)"
  openssl pkey -in "$ORIG_KEY" -out "$TMPKEY" >/dev/null 2>&1 || {
    echo "ERROR: failed to convert EC SEC1 key to PKCS#8" >&2; exit 1; }
else
  TMPKEY="$ORIG_KEY"
fi

# ensure prime256v1 (P-256)
if ! openssl pkey -in "$TMPKEY" -text -noout | grep -q "ASN1 OID: prime256v1"; then
  echo "ERROR: Key is not P-256 (prime256v1). ES256 requires secp256r1." >&2
  [[ "$TMPKEY" != "$ORIG_KEY" ]] && rm -f "$TMPKEY"
  exit 1
fi


if [[ -n "$KID" ]]; then
  HEADER_JSON='{"alg":"ES256","typ":"JWT","kid":"'"$KID"'"}'
else
  HEADER_JSON='{"alg":"ES256","typ":"JWT"}'
fi

declare -r PAYLOAD_JSON=$(cat "${json_file}")

HEADER_B64=$(printf '%s' "$HEADER_JSON" | b64url)
PAYLOAD_B64=$(printf '%s' "$PAYLOAD_JSON" | b64url)
SIGNED_INPUT="${HEADER_B64}.${PAYLOAD_B64}"

# hash → sign (DER ECDSA)
MSG_BIN="$(mktemp)"; SIG_DER="$(mktemp)"; SIG_RAW="$(mktemp)"
printf '%s' "$SIGNED_INPUT" | openssl dgst -sha256 -binary > "$MSG_BIN"

if ! openssl pkeyutl -sign -inkey "$TMPKEY" -rawin -in "$MSG_BIN" -out "$SIG_DER"; then
  echo "ERROR: openssl pkeyutl failed to sign. Check key format/provider." >&2
  [[ "$TMPKEY" != "$ORIG_KEY" ]] && rm -f "$TMPKEY"
  rm -f "$MSG_BIN" "$SIG_DER" "$SIG_RAW"
  exit 1
fi
[[ -s "$SIG_DER" ]] || { echo "ERROR: signature file empty"; exit 1; }

der_to_raw_rs "$SIG_DER" > "$SIG_RAW"
SIG_B64=$(cat "$SIG_RAW" | b64url)
echo "${SIGNED_INPUT}.${SIG_B64}"

# cleanup
[[ "$TMPKEY" != "$ORIG_KEY" ]] && rm -f "$TMPKEY"
rm -f "$MSG_BIN" "$SIG_DER" "$SIG_RAW"

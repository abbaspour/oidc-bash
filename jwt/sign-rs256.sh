#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2022-06-12 (Modified: 2024-10-25)
# License: MIT (https://github.com/abbaspour/auth0-bash/blob/master/LICENSE)
##########################################################################################

set -eo pipefail

command -v openssl >/dev/null || {  echo >&2 "error: openssl not found";  exit 3; }

declare alg='RS256'
declare typ='JWT'

function usage() {
    cat <<END >&2
USAGE: $0 [-f json] [-i iss] [-a aud] [-k kid] [-p private-key] [-v|-h]
        -f file        # JSON file to sign
        -p pem         # private key PEM file
        -i iss         # issuer
        -a aud         # audience
        -k kid         # Key ID
        -A alg         # algorithm. default ${alg}
        -t type        # type, defaults to "jwt"
        -h|?           # usage
        -v             # verbose

eg,
     $0 -f file.json -a http://my.api -i http://some.issuer -k 1 -p ../ca/myapi-private.pem
END
    exit $1
}

b64url(){ openssl base64 -A | tr '+/' '-_' | tr -d '='; }


declare opt_verbose=0
declare aud=''
declare iss=''
declare kid=''
declare json_file=''
declare pem_file=''

while getopts "f:i:a:k:p:A:t:hv?" opt; do
    case ${opt} in
    f) json_file=${OPTARG} ;;
    i) iss=${OPTARG} ;;
    a) aud=${OPTARG} ;;
    k) kid=${OPTARG} ;;
    p) pem_file=${OPTARG} ;;
    A) alg=${OPTARG} ;;
    t) typ=${OPTARG} ;;
    v) opt_verbose=1 ;; #set -x;;
    h | ?) usage 0 ;;
    *) usage 1 ;;
    esac
done

[[ -f "${pem_file}" ]] || { echo >&2 "ERROR: pem_file missing: ${pem_file}"; usage 1; }
[[ -z "${json_file}" ]] && { echo >&2 "ERROR: json_file undefined";  usage 1; }

[[ ! -f "${json_file}" ]] && { echo >&2 "json_file: unable to read file: ${json_file}";  usage 1; }


# header
readonly header=$(
  jq -n \
    --arg typ "${typ}" \
    --arg alg "${alg}" \
    --arg kid "${kid:-}" \
    '
    { typ: $typ }
    + { alg: $alg }
    + ( if ($kid | length) > 0 then { kid: $kid } else {} end )
    ' | b64url
)

# body
declare -r body=$(cat "${json_file}" | b64url)

declare alg_lower=$(echo -n "$alg" | tr '[:upper:]' '[:lower:]')

declare signature=''
if [[ ${alg_lower} != 'none' ]]; then
    if [[ ${alg_lower} == 'ps256' ]]; then
        # Use RSASSA-PSS padding for PS256
        signature=$(echo -n "${header}.${body}" | \
            openssl dgst -sha256 -sign "${pem_file}" -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -binary | \
            b64url)
    else
        # Default to RS256 (or other RS algorithms with PKCS#1 v1.5 padding)
        signature=$(echo -n "${header}.${body}" | \
            openssl dgst -sha256 -sign "${pem_file}" -binary | \
            b64url)
    fi
fi

# jwt
echo "${header}.${body}.${signature}"

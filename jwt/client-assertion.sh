#!/usr/bin/env bash
# shellcheck disable=SC2034

##########################################################################################
# Author: Amin Abbaspour
# Date: 2022-06-12
# License: LGPL 2.1 (https://github.com/abbaspour/oidc-bash/blob/main/LICENSE)
##########################################################################################

set -eo pipefail

DIR="${BASH_SOURCE[0]%/*}"
[ "$DIR" = "${BASH_SOURCE[0]}" ] && DIR="."
readonly DIR

command -v openssl >/dev/null || { echo >&2 "error: openssl not found"; exit 3; }
command -v sed >/dev/null || { echo >&2 "error: sed not found"; exit 3; }

declare alg='RS256'
declare TTL=300

function usage() {
    cat <<END >&2
USAGE: $0 [-e env] [-a audience] [-i client_id] [-f file] [-k kid] [-A alg] [-t ttl] [-v|-h]
        -e file         # .env file location (default cwd)
        -a audience     # audience
        -i client_id    # client_id
        -k kid          # key id. optional.
        -f file         # private key PEM  file
        -A alg          # algorithm. default ${alg}. supports: RS256, ES256, PS256
        -t ttl          # TTL in seconds. default is 300
        -h|?            # usage
        -v              # verbose

eg,
     $0 -t abbaspour -i 6KS0YSEQwsvE9qRqtzonX8SEgJEYVzVH -k mykid -f ../ca/mydomain.local.key
END
    exit "$1"
}

declare AUDIENCE=''
declare client_id=''
declare pem_file=''
declare kid=''
declare opt_verbose=''

while getopts "e:t:a:i:f:k:A:hv?" opt
do
    case ${opt} in
        e) source "${OPTARG}";;
        a) AUDIENCE="${OPTARG}";;
        i) client_id=${OPTARG};;
        f) pem_file=${OPTARG};;
        k) kid=${OPTARG};;
        A) alg=${OPTARG} ;;
        t) TTL=${OPTARG} ;;
        v) opt_verbose=1 ;; #set -x;;
        h|?) usage 0;;
        *) usage 1;;
    esac
done


[[ -z "${AUDIENCE}" ]] && { echo >&2 "ERROR: AUDIENCE undefined"; usage 1; }
[[ -z "${client_id}" ]] && { echo >&2 "ERROR: client_id undefined."; usage 1; }
[[ -z "${kid}" ]] && kid='' # { echo >&2 "ERROR: kid undefined."; usage 1; }
[[ -z "${pem_file}" ]] && { echo >&2 "ERROR: pem_file undefined."; usage 1; }
[[ -f "${pem_file}" ]] || { echo >&2 "ERROR: pem_file missing: ${pem_file}"; usage 1; }

[[ ${DOMAIN} =~ ^http ]] || DOMAIN=https://${DOMAIN}

declare ALG="${alg^^}"

declare now
now=$(date +%s)
readonly now
declare -r exp=$((now + TTL))
declare JTI
JTI="$(openssl rand -hex 16)"
readonly JTI

body=$(printf '{"iat": %s, "iss":"%s","sub":"%s","aud":"%s","exp":%s, "jti": "%s"}' "${now}" "${client_id}" "${client_id}" "${AUDIENCE}" "${exp}" "${JTI}")
readonly body

json=$(mktemp --suffix=.json)
readonly json

echo "${body}" > "${json}"

case "${ALG}" in
  RS256|PS256) "${DIR}"/sign-rs256.sh -a "${AUDIENCE}" -i "${client_id}" -k "${kid}" -f "${json}" -p "${pem_file}" -A "${ALG}";;
  HS256) "${DIR}"/sign-hs256.sh -a "${AUDIENCE}" -i "${client_id}" -k "${kid}" -f "${json}" -p "${pem_file}";;
  ES256) "${DIR}"/sign-es256-jose.sh -a "${AUDIENCE}" -i "${client_id}" -k "${kid}" -f "${json}" -p "${pem_file}";;
  *)  echo >&2 "ERROR: unsupported algorithm: ${ALG}"; usage 1;;
esac


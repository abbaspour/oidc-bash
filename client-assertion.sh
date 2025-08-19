#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2022-06-12
# License: MIT (https://github.com/abbaspour/auth0-bash/blob/master/LICENSE)
##########################################################################################

set -eo pipefail

command -v openssl >/dev/null || { echo >&2 "error: openssl not found"; exit 3; }
command -v sed >/dev/null || { echo >&2 "error: sed not found"; exit 3; }

declare alg='RS256'
declare TTL=300

function usage() {
    cat <<END >&2
USAGE: $0 [-t tenant] [-d domain] [-i client_id] [-f file] [-k kid] [-v|-h]
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
    exit $1
}

declare AUDIENCE=''
declare client_id=''
declare pem_file=''
declare kid=''

while getopts "e:t:a:i:f:k:A:hv?" opt
do
    case ${opt} in
        e) source ${OPTARG};;
        a) AUDIENCE="${OPTARG}";;
        i) client_id=${OPTARG};;
        f) pem_file=${OPTARG};;
        k) kid=${OPTARG};;
        A) alg=${OPTARG} ;;
        t) TTL=${OPTARG} ;;
        v) set -x;;
        h|?) usage 0;;
        *) usage 1;;
    esac
done


[[ -z "${AUDIENCE}" ]] && { echo >&2 "ERROR: AUDIENCE undefined"; usage 1; }
[[ -z "${client_id}" ]] && { echo >&2 "ERROR: client_id undefined."; usage 1; }
[[ -z "${kid}" ]] && kid='' # { echo >&2 "ERROR: kid undefined."; usage 1; }
[[ -z "${pem_file}" ]] && { echo >&2 "ERROR: pem_file undefined."; usage 1; }
[[ -f "${pem_file}" ]] || { echo >&2 "ERROR: pem_file missing: ${pem_file}"; usage 1; }

[[ ${AUTH0_DOMAIN} =~ ^http ]] || AUTH0_DOMAIN=https://${AUTH0_DOMAIN}

declare ALG="${alg^^}"

declare -r now=$(date +%s);
declare -r exp=$((now + TTL));
declare -r JTI="$(openssl rand -hex 16)"

readonly body=$(printf '{"iat": %s, "iss":"%s","sub":"%s","aud":"%s","exp":%s, "jti": "%s"}' "${now}" "${client_id}" "${client_id}" "${AUDIENCE}" "${exp}" "${JTI}")

readonly json=$(mktemp --suffix=.json)

echo "${body}" > "${json}"

case "${ALG}" in
  RS256|PS256) ./jwt/sign-rs256.sh -a "${AUDIENCE}" -i "${client_id}" -k "${kid}" -f "${json}" -p "${pem_file}" -A "${ALG}";;
  HS256) ./jwt/sign-hs256.sh -a "${AUDIENCE}" -i "${client_id}" -k "${kid}" -f "${json}" -p "${pem_file}";;
  ES256) ./jwt/sign-es256-jose.sh -a "${AUDIENCE}" -i "${client_id}" -k "${kid}" -f "${json}" -p "${pem_file}";;
  *)  echo >&2 "ERROR: unsupported algorithm: ${ALG}"; usage 1;;
esac


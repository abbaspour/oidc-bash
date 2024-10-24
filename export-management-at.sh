#!/usr/bin/env bash

set -euo pipefail

####
# how to use this? eval `./export-management-at.sh`
####

readonly DIR=$(dirname "${BASH_SOURCE[0]}")

#readonly active_env="${DIR}/.env"
readonly active_env="${DIR}/.env-abbaspour-api-explorer"

[[ -f "${active_env}" ]] || { echo >&2 "ERROR: no active .env file found"; exit 3; }

readonly access_token=$("${DIR}"/client-credentials.sh -e "${active_env}" -m | jq -r .access_token)

echo "export access_token='${access_token}'"

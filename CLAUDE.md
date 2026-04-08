# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Repo Is

A Bash script collection acting as an OAuth2/OIDC Relying Party (RP), primarily for education. **Intentional code duplication is by design** — simplicity is valued over reuse, so each script is self-contained per flow even if it repeats token endpoint logic.

## Setup

```bash
cp env.sample .env
# Edit .env with your Auth0 tenant details
```

Required system tools: `curl`, `jq`, `openssl`

For JWT signing scripts under `jwt/`:
```bash
cd jwt && npm install
```

## Running Scripts

All scripts follow the same CLI pattern and load `.env` from their directory:

```bash
# Using tenant shorthand (expands to tenant.region.auth0.com)
./client-credentials.sh -t amin01@au -c CLIENT_ID -x CLIENT_SECRET -m

# Using explicit domain
./client-credentials.sh -d myapp.auth0.com -c CLIENT_ID -x CLIENT_SECRET -a https://my-api/

# Load alternate env file
./refresh.sh -e /path/to/other.env -r REFRESH_TOKEN
```

Common flags across most scripts:
- `-t tenant@region` — shorthand for Auth0 domain (e.g. `-t myapp@us` → `myapp.us.auth0.com`)
- `-d domain` — explicit domain override
- `-e file` — alternate `.env` file path
- `-v` — verbose (shows request body; some scripts use `set -x`)
- `-D` — disable OIDC discovery (skip `.well-known/openid-configuration` lookup)

## Script Map by OAuth Flow

| Script | Flow |
|---|---|
| `exchange.sh` | Authorization Code (also Device Code via `-C`, CIBA via `-r`) |
| `client-credentials.sh` | Client Credentials |
| `refresh.sh` | Refresh Token |
| `device-flow.sh` | Device Authorization initiation |
| `token-exchange.sh` | Token Exchange (RFC 8693) |
| `cross-origin.sh` | Cross-Origin Authentication |
| `userinfo.sh` | UserInfo endpoint |
| `logout.sh` | RP-Initiated Logout |
| `revoke-refresh-token.sh` | Token Revocation |
| `export-management-at.sh` | Management API access token |
| `export-myaccount-at.sh` | MyAccount API access token |

## Key Helper Scripts

**`client-assertion.sh`** — Generates a signed JWT for private key JWT client authentication. Called by `exchange.sh` and `client-credentials.sh` when `-k kid -f private.pem` flags are passed. Delegates signing to `jwt/sign-rs256.sh` (RS256/PS256) or `jwt/sign-es256-jose.sh` (ES256).

**`dpop.sh`** — Generates DPoP proof JWTs (RFC 9449) using OpenSSL. Takes `-r private.pem -u URL -m METHOD`. Called by `exchange.sh` when `-P dpop.pem` is passed. Hardcodes OpenSSL to `/opt/homebrew/bin/openssl`.

**`jwt/sign-rs256.sh`** — Low-level JWT signer using `openssl dgst`. Supports RS256 and PS256 (RSASSA-PSS).

**`jwt/sign-es256-jose.sh`** / **`jwt/sign-es256.sh`** — ES256 JWT signing via Node.js `jose` library.

**`ca/self-sign.sh`** / **`ca/jwk-to-pkc8-pem.sh`** — Certificate and key management utilities.

## Architecture Patterns

- Scripts start with `set -ueo pipefail` (or `set -eo pipefail`) and `readonly DIR=$(dirname "${BASH_SOURCE[0]}")`
- Config load order: `.env` in script dir → CLI flags override
- OIDC Discovery is **on by default** — scripts fetch `/.well-known/openid-configuration` and use the discovered `token_endpoint`; disable with `-D`
- All responses are piped through `jq .` for pretty-printed JSON output
- mTLS client certificate flows use URL-encoded PEM passed as HTTP headers (see `client-credentials.sh -C cert.pem`)

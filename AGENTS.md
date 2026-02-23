# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OIDC Bash is an educational collection of Bash scripts that implement OAuth2/OIDC Relying Party (RP) functionality. Each script demonstrates a specific OAuth2/OIDC flow with emphasis on simplicity over code reuse. Scripts are primarily tested against Auth0.

## Environment Setup

1. Copy `env.sample` to `.env` and configure Auth0 credentials:
   ```bash
   cp env.sample .env
   # Edit .env with your AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET
   ```

2. Required dependencies: `bash` (v5+), `curl`, `jq`, `openssl`

## Common Script Patterns

All scripts follow consistent conventions:
- Start with `#!/usr/bin/env bash` and `set -euo pipefail`
- Use `getopts` for argument parsing with these common flags:
  - `-e <file>`: Path to .env file
  - `-t tenant`: Auth0 tenant in format `tenant@region`  
  - `-d domain`: Fully qualified domain
  - `-v`: Verbose mode (prints request URL and body)
  - `-h`: Help/usage information
- Include `usage()` function with heredoc format
- Check dependencies with `command -v`
- Use 4-space indentation and quote all variables

## Key Script Categories

### Authorization Flows
- `authorize.sh`: Authorization code flow with various response types
- `device-flow.sh`: OAuth 2.0 Device Authorization Grant

### Token Operations  
- `client-credentials.sh`: Client Credentials grant
- `exchange.sh`: Authorization code exchange for tokens
- `refresh.sh`: Token refresh
- `revoke-refresh-token.sh`: Token revocation
- `resource-owner.sh`: Resource Owner Password Credentials

### Authentication Methods
- `client-assertion.sh`: JWT client assertion
- `dpop.sh`: Demonstrating Proof-of-Possession (DPoP)
- Files in `ca/`: Client certificate authentication (mTLS)

### Utilities
- `userinfo.sh`: Fetch user information
- `jwt/`: JWT signing and verification tools
- `discovery/`: OIDC discovery endpoints

## Subdirectories

- `ca/`: Certificate authority tools and client certificates for mTLS
- `jwt/`: JWT manipulation utilities (uses Node.js with jose library)  
- `discovery/`: OIDC discovery and JWKS utilities
- `.junie/`: Development guidelines for Junie AI assistant

## Code Style Requirements

- **Portability**: Compatible with both Linux and macOS bash
- **Error handling**: Use `set -euo pipefail` 
- **Variable naming**: Uppercase for globals/env vars, lowercase for locals
- **Quoting**: Always quote variables to prevent word splitting
- **Portable commands**: Avoid GNU-specific flags (use `sed -E`, avoid `date --date`)

## Testing

No formal test suite exists. Verify changes by:
1. Running affected scripts with appropriate parameters
2. Checking script output matches expected results  
3. Ensuring scripts exit with non-zero codes on error

## Node.js Components

Two subdirectories contain Node.js utilities:
- `jwt/package.json`: Uses jose v3.15.4 for JWT operations
- `ca/package.json`: Uses jose v6.0.12 for key tools

Install dependencies in these directories with `npm install` when working with JWT utilities.
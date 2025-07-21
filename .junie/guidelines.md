# OIDC Bash Project Guidelines for Junie

## Project Overview
OIDC Bash is a collection of Bash scripts that act as an OAuth2/OIDC Relying Party (RP). 
The main purpose of this project is educational, focusing on simplicity over code reuse. 
Each script implements a specific OAuth2/OIDC flow or functionality, making it easier to understand individual concepts.
Scripts in this project are primarily built and tested against Auth0.

The project supports various standards from the OAuth 2 family and OpenID Connect (OIDC) family, including:
- OAuth 2.0/2.1 Authorization Framework
- OAuth 2.0 Device Authorization Grant
- OAuth 2.0 Pushed Authorization Requests (PAR)
- OAuth 2.0 JWT-Secured Authorization Request (JAR)
- OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)
- OpenID Connect Core 1.0
- CIBA - Core 1.0

## Project Structure
- Scripts are organized in a flat structure at the root level, with some subject-area scripts in subdirectories
- Main subdirectories include:
  - `ca/`: Contains certificates and keys for client authentication
  - `discovery/`: Scripts related to OIDC discovery
  - `jwt/`: Scripts for JWT manipulation
- Each script is self-contained and executable, implementing a specific OAuth2/OIDC flow

## Running the Scripts
1. **Environment Setup**:
   - Copy `env.sample` to `.env` and fill in your Auth0 credentials
   - Ensure you have the required dependencies: `bash`, `curl`, `jq`, `openssl`

2. **Script Execution**:
   - Most scripts can be run with `./script-name.sh` and provide usage information with `-h` flag
   - Example: `./client-assertion.sh -d yourdomain.auth0.com -i your_client_id -k your_kid -f path/to/key.pem`

3. **Testing**:
   - No formal test suite is provided
   - Verify script functionality by checking their output against expected results
   - Scripts should exit with non-zero status codes on error

4. Common parameters across scripts include:
   - `-e <file>`: Path to .env file for environment variables
   - `-v`: Verbose mode for debugging; In verbose mode, prints request URL and body to console
   - `-h`: Display help/usage information
   - `-t tenant`: Auth0 tenant in the format of tenant@region
   - `-t tenant`: Auth0 tenant in the format of tenant@region
   - `-d domain`: fully qualified Auth0 domain

## Code Style Guidelines
The project follows specific conventions to ensure consistency and maintainability:

1. **General Principles**:
   - **Portability**: Scripts should be compatible with Bash v5+ and run on both Linux and macOS
   - **Clarity**: Code should be easy to read and understand
   - **Robustness**: Scripts should handle errors gracefully

2. **Shell Scripting Conventions**:
   - **Shebang**: All scripts must start with `#!/usr/bin/env bash`
   - **Error Handling**: Use `set -euo pipefail` at the beginning of scripts
   - **Variable Declaration**: Use `declare` for all variables, `readonly` for constants
   - **Variable Naming**: Uppercase for global/environment variables, lowercase for local variables
   - **Functions**: Define using `function_name() { ... }` syntax
   - **Argument Parsing**: Use `getopts` for command-line options
   - **Dependencies**: Check for external commands using `command -v`

3. **Formatting**:
   - **Indentation**: 4 spaces
   - **Heredocs**: Use `cat <<END ... END` for multi-line strings
   - **Command Substitution**: Prefer `$(command)` over backticks
   - **Quoting**: Always quote variables to prevent word splitting

4. **Portability Considerations**:
   - Avoid GNU-specific flags for commands like `date`, `base64`, and `sed`
   - Use `sed -E` for extended regular expressions
   - Avoid platform-specific commands without portable alternatives

## Instructions for Junie
When working with this project, Junie should:

1. **Maintain Consistency**: Follow the existing code style and conventions
2. **Preserve Self-Containment**: Keep scripts independent and focused on specific flows
3. **Ensure Portability**: Test changes on both Linux and macOS when possible
4. **Handle Errors**: Implement proper error checking and reporting
5. **Document Changes**: Update comments and usage information when modifying scripts
6. **Test Manually**: Verify script functionality by running them with appropriate parameters

There is no formal build process or test suite for this project. Changes should be verified by running the affected scripts and checking their output.

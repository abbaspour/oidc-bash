# Gemini Code Assistant Project Guidelines

This document outlines the conventions and coding style for the `oidc-bash` project to ensure consistency and maintainability.

## General Principles

- **Portability**: Scripts should be compatible with Bash v5+ and run on both Linux and macOS.
- **Clarity**: Code should be easy to read and understand.
- **Robustness**: Scripts should handle errors gracefully.

## File Structure

- Scripts are organized into a flat structure, with subject-area scripts in subdirectories (e.g., `jwt/`, `discovery/`).
- Each script is self-contained and executable.

## Shell Scripting Conventions

### Shebang

- All scripts must start with `#!/usr/bin/env bash`.

### Error Handling

- Use `set -euo pipefail` at the beginning of scripts to ensure they exit on error and that pipeline failures are detected.

### Variable Declaration and Naming

- Declare all variables with `declare`.
- Use `readonly` for constants.
- Use uppercase for global and environment variables (e.g., `AUTH0_DOMAIN`).
- Use lowercase for local variables.

### Functions

- Define functions using the `function_name() { ... }` syntax.
- A `usage()` function should be present in each script to provide help information.

### Argument Parsing

- Use `getopts` for parsing command-line options.

### Dependencies

- Explicitly check for the existence of external commands like `curl` and `jq` using `command -v`. If a command is not found, print an error message to `stderr` and exit with a non-zero status code.

### Readability and Style

- **Indentation**: Use 4 spaces for indentation.
- **Heredocs**: Use `cat <<END ... END` for multi-line strings, especially in `usage()` functions.
- **Command Substitution**: Prefer `$(command)` over backticks `` `command` ``.
- **Quoting**: Always quote variables (`"$variable"`) to prevent word splitting and globbing issues.

### Portability Considerations

- **`date` command**: For date calculations that are portable between GNU and BSD/macOS `date`, avoid GNU-specific flags like `--date`.
- **`base64` command**: Avoid non-portable flags like `-w0`.
- **`sed` command**: Use `sed -E` for extended regular expressions to maintain compatibility between GNU and BSD/macOS `sed`.
- **macOS specific commands**: Avoid commands like `pbcopy` if a portable alternative is not provided.

### JSON and API Interaction

- **`curl`**: Use `curl` for making HTTP requests.
- **`jq`**: Use `jq` for parsing and manipulating JSON data. Do not parse JSON with `sed` or `awk`.

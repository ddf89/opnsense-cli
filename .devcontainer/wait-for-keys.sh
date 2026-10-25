#!/usr/bin/env bash
#
# devcontainer postStartCommand: wait for the OPNsense API key file written by
# the other container, then expose it as OPNSENSE_API_KEY / OPNSENSE_API_SECRET.
#
# Env vars set here can't reach the parent process, so we write them to a
# private env file and source it from the shell rc files. New terminals pick
# it up automatically.

set -euo pipefail

KEY_FILE="${KEY_FILE:-/keys/.opnsense_api_key.json}"
ENV_FILE="${ENV_FILE:-/home/vscode/.opnsense-env}"
VSCENV_FILE="${VSCENV_FILE:-/home/vscode/.vscopnsense-env}"
TIMEOUT="${TIMEOUT:-300}"    # seconds to wait before giving up
INTERVAL=2

if [ -e "$ENV_FILE" ]
then
    echo "keys already present"
    exit 0
fi

command -v jq >/dev/null 2>&1 || {
    echo "wait-for-keys: jq is required but not installed" >&2
    exit 1
}

echo "wait-for-keys: waiting for $KEY_FILE (timeout ${TIMEOUT}s)..."
waited=0
# Require valid JSON with both fields so we never read a half-written file.
until [[ -s "$KEY_FILE" ]] && jq -e '.key and .secret' "$KEY_FILE" >/dev/null 2>&1; do
    if (( waited >= TIMEOUT )); then
        echo "wait-for-keys: timed out waiting for $KEY_FILE" >&2
        exit 1
    fi
    sleep "$INTERVAL"
    waited=$(( waited + INTERVAL ))
done

key=$(jq -r '.key' "$KEY_FILE")
secret=$(jq -r '.secret' "$KEY_FILE")

# Write the env file (printf %q quotes the / + = characters in the values).
umask 077
{
    printf 'export OPNSENSE_API_KEY=%q\n' "$key"
    printf 'export OPNSENSE_API_SECRET=%q\n' "$secret"
} > "$ENV_FILE"

chown vscode: $ENV_FILE

umask 077
{
    printf 'OPN_APIKEY=%q\n' "$key"
    printf 'OPN_APISECRET=%q\n' "$secret"
} > "$VSCENV_FILE"

chown vscode: $VSCENV_FILE

# source $ENV_FILE

# Source it from shell rc files, once.
line="[ -f \"$ENV_FILE\" ] && . \"$ENV_FILE\""
for rc in "/home/vscode/.bashrc" "/home/vscode/.zshrc"; do
    [[ -f "$rc" ]] || continue
    grep -qxF "$line" "$rc" || echo "$line" >> "$rc"
done

echo "wait-for-keys: API credentials written to $ENV_FILE"

rm -f $KEY_FILE

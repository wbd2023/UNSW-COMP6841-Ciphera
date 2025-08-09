#!/usr/bin/env bash
set -euo pipefail

RELAY_URL="http://127.0.0.1:8080"
ALICE_HOME="/tmp/alice-ciphera-basic-alice"
BOB_HOME="/tmp/bob-ciphera-basic-bob"
ALICE_USER="alice"
BOB_USER="bob"
ALICE_PASS="Alice-pass1234"
BOB_PASS="Bob-pass1234"

ROOT_DIR="$(
  git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel 2>/dev/null \
    || (cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
)"
BIN_DIR="${ROOT_DIR}/bin"
CIPHERA_BIN="${BIN_DIR}/ciphera"
RELAY_BIN="${BIN_DIR}/relay"
RELAY_LOG="/tmp/ciphera-relay-basic.log"

cleanup() {
  if [[ -n "${RELAY_PID:-}" ]]; then
    kill "${RELAY_PID}" >/dev/null 2>&1 || true
    wait "${RELAY_PID}" >/dev/null 2>&1 || true
  fi
  rm -rf "${ALICE_HOME}" "${BOB_HOME}"
}
trap cleanup EXIT

# Build binaries
mkdir -p "${BIN_DIR}"
(
  cd "${ROOT_DIR}"
  go build -o "${CIPHERA_BIN}" ./cmd/ciphera
  go build -o "${RELAY_BIN}"   ./cmd/relay
)

# Start relay
"${RELAY_BIN}" >"${RELAY_LOG}" 2>&1 & RELAY_PID=$!
for _ in {1..50}; do
  curl -s "${RELAY_URL}/prekey/does-not-exist" >/dev/null 2>&1 && break
  sleep 0.1
done

# Prepare fresh home directories
rm -rf "${ALICE_HOME}" "${BOB_HOME}"
mkdir -p "${ALICE_HOME}" "${BOB_HOME}"

# Initialise & register Alice
"${CIPHERA_BIN}" init \
  --home       "${ALICE_HOME}" \
  --passphrase "${ALICE_PASS}"
"${CIPHERA_BIN}" register \
  --home       "${ALICE_HOME}" \
  --relay      "${RELAY_URL}" \
  "${ALICE_USER}" \
  --passphrase "${ALICE_PASS}"

# Initialise & register Bob
"${CIPHERA_BIN}" init \
  --home       "${BOB_HOME}" \
  --passphrase "${BOB_PASS}"
"${CIPHERA_BIN}" register \
  --home       "${BOB_HOME}" \
  --relay      "${RELAY_URL}" \
  "${BOB_USER}" \
  --passphrase "${BOB_PASS}"

# Establish sessions (Bob -> Alice then Alice -> Bob)
"${CIPHERA_BIN}" start-session \
  --home       "${BOB_HOME}" \
  --relay      "${RELAY_URL}" \
  "${ALICE_USER}" \
  --passphrase "${BOB_PASS}"
"${CIPHERA_BIN}" start-session \
  --home       "${ALICE_HOME}" \
  --relay      "${RELAY_URL}" \
  "${BOB_USER}" \
  --passphrase "${ALICE_PASS}"

# Send and receive a test message
"${CIPHERA_BIN}" send \
  --home       "${ALICE_HOME}" \
  --username   "${ALICE_USER}" \
  --relay      "${RELAY_URL}" \
  --passphrase "${ALICE_PASS}" \
  "${BOB_USER}" \
  "hello-bob"
MESSAGE_OUT="$("${CIPHERA_BIN}" recv \
  --home       "${BOB_HOME}" \
  --username   "${BOB_USER}" \
  --relay      "${RELAY_URL}" \
  --passphrase "${BOB_PASS}")"

echo "[+] Received message: ${MESSAGE_OUT}"

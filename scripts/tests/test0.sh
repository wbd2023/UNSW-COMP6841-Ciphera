#!/usr/bin/env bash
set -euo pipefail

# Config
RELAY_URL="http://127.0.0.1:8080"
ALICE_HOME="/tmp/alice-ciphera"
BOB_HOME="/tmp/bob-ciphera"
ALICE_USER="alice"
BOB_USER="bob"
ALICE_PASS="alice-pass"
BOB_PASS="bob-pass"

# Paths
ROOT_DIR="$(
  git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel 2>/dev/null \
  || ( cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P )
)" || { echo "Cannot determine repo root"; exit 1; }
BIN_DIR="${ROOT_DIR}/bin"
CIPHERA_BIN="${BIN_DIR}/ciphera"
RELAY_BIN="${BIN_DIR}/relay"
BIN_DIR="${ROOT_DIR}/bin"
CIPHERA_BIN="${BIN_DIR}/ciphera"
RELAY_BIN="${BIN_DIR}/relay"

# Temp artefacts
RELAY_LOG="/tmp/ciphera-relay.log"
ALICE_RECV_OUT="/tmp/alice-recv.out"
BOB_RECV_OUT="/tmp/bob-recv.out"

# Clean up relay and temp files even on failure
cleanup() {
  if [[ -n "${RELAY_PID:-}" ]]; then
    kill "${RELAY_PID}" >/dev/null 2>&1 || true
    wait "${RELAY_PID}" 2>/dev/null || true
  fi
  rm -rf "${ALICE_HOME}" "${BOB_HOME}" "${ALICE_RECV_OUT}" "${BOB_RECV_OUT}"
}
trap cleanup EXIT

# Build binaries
mkdir -p "${BIN_DIR}"
cd "${ROOT_DIR}"
go mod tidy
go build -o "${CIPHERA_BIN}" ./cmd/ciphera
go build -o "${RELAY_BIN}"   ./cmd/relay

# Start relay and wait until it answers
"${RELAY_BIN}" >"${RELAY_LOG}" 2>&1 &
RELAY_PID=$!
for _ in {1..50}; do
  if curl -s "${RELAY_URL}/prekey/does-not-exist" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

# Fresh homes
rm -rf "${ALICE_HOME}" "${BOB_HOME}"
mkdir -p "${ALICE_HOME}" "${BOB_HOME}"

# Generate identities and register prekeys
"${CIPHERA_BIN}" init --home "${ALICE_HOME}" --passphrase "${ALICE_PASS}"
"${CIPHERA_BIN}" register --home "${ALICE_HOME}" --relay "${RELAY_URL}" "${ALICE_USER}" --passphrase "${ALICE_PASS}"

"${CIPHERA_BIN}" init --home "${BOB_HOME}" --passphrase "${BOB_PASS}"
"${CIPHERA_BIN}" register --home "${BOB_HOME}" --relay "${RELAY_URL}" "${BOB_USER}" --passphrase "${BOB_PASS}"

# Establish sessions both ways
"${CIPHERA_BIN}" start-session --home "${BOB_HOME}" --relay "${RELAY_URL}" "${ALICE_USER}" --passphrase "${BOB_PASS}"
"${CIPHERA_BIN}" start-session --home "${ALICE_HOME}" --relay "${RELAY_URL}" "${BOB_USER}" --passphrase "${ALICE_PASS}"

# Send and receive messages, assert contents
"${CIPHERA_BIN}" send --home "${ALICE_HOME}" --username "${ALICE_USER}" --relay "${RELAY_URL}" --passphrase "${ALICE_PASS}" "${BOB_USER}" "hello bob"
"${CIPHERA_BIN}" recv --home "${BOB_HOME}" --username "${BOB_USER}" --relay "${RELAY_URL}" --passphrase "${BOB_PASS}" | tee "${BOB_RECV_OUT}"
grep -q "\[${ALICE_USER}\] hello bob" "${BOB_RECV_OUT}"

"${CIPHERA_BIN}" send --home "${BOB_HOME}" --username "${BOB_USER}" --relay "${RELAY_URL}" --passphrase "${BOB_PASS}" "${ALICE_USER}" "hi alice"
"${CIPHERA_BIN}" recv --home "${ALICE_HOME}" --username "${ALICE_USER}" --relay "${RELAY_URL}" --passphrase "${ALICE_PASS}" | tee "${ALICE_RECV_OUT}"
grep -q "\[${BOB_USER}\] hi alice" "${ALICE_RECV_OUT}"

echo "[+] E2E test passed"

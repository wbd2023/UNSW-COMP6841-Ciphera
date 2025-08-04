#!/usr/bin/env bash
set -euo pipefail

RELAY_URL="http://127.0.0.1:8080"
ALICE_HOME="/tmp/alice-ciphera-t4"
BOB_HOME="/tmp/bob-ciphera-t4"
ALICE_USER="alice"
BOB_USER="bob"
ALICE_PASS="alice-pass"
BOB_PASS="bob-pass"

ROOT_DIR="$(
  git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel 2>/dev/null \
  || ( cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P )
)"
BIN_DIR="${ROOT_DIR}/bin"
CIPHERA_BIN="${BIN_DIR}/ciphera"
RELAY_BIN="${BIN_DIR}/relay"
RELAY_LOG="/tmp/ciphera-relay-t4.log"

cleanup() {
  if [[ -n "${RELAY_PID:-}" ]]; then kill "${RELAY_PID}" >/dev/null 2>&1 || true; wait "${RELAY_PID}" 2>/dev/null || true; fi
  rm -rf "${ALICE_HOME}" "${BOB_HOME}"
}
trap cleanup EXIT

mkdir -p "${BIN_DIR}"
( cd "${ROOT_DIR}" && go build -o "${CIPHERA_BIN}" ./cmd/ciphera && go build -o "${RELAY_BIN}" ./cmd/relay )

"${RELAY_BIN}" >"${RELAY_LOG}" 2>&1 & RELAY_PID=$!
for _ in {1..50}; do curl -s "${RELAY_URL}/prekey/does-not-exist" >/dev/null 2>&1 && break; sleep 0.1; done

rm -rf "${ALICE_HOME}" "${BOB_HOME}"; mkdir -p "${ALICE_HOME}" "${BOB_HOME}"

"${CIPHERA_BIN}" init --home "${ALICE_HOME}" --passphrase "${ALICE_PASS}"
"${CIPHERA_BIN}" register --home "${ALICE_HOME}" --relay "${RELAY_URL}" "${ALICE_USER}" --passphrase "${ALICE_PASS}"

"${CIPHERA_BIN}" init --home "${BOB_HOME}" --passphrase "${BOB_PASS}"
"${CIPHERA_BIN}" register --home "${BOB_HOME}" --relay "${RELAY_URL}" "${BOB_USER}" --passphrase "${BOB_PASS}"

"${CIPHERA_BIN}" start-session --home "${BOB_HOME}" --relay "${RELAY_URL}" "${ALICE_USER}" --passphrase "${BOB_PASS}"
"${CIPHERA_BIN}" start-session --home "${ALICE_HOME}" --relay "${RELAY_URL}" "${BOB_USER}" --passphrase "${ALICE_PASS}"

# Send two messages
"${CIPHERA_BIN}" send --home "${ALICE_HOME}" --username "${ALICE_USER}" --relay "${RELAY_URL}" --passphrase "${ALICE_PASS}" "${BOB_USER}" "m0"
"${CIPHERA_BIN}" send --home "${ALICE_HOME}" --username "${ALICE_USER}" --relay "${RELAY_URL}" --passphrase "${ALICE_PASS}" "${BOB_USER}" "m1"

# Pull both envelopes, then re-post in reverse order to simulate reordering
ALL=$(curl -s "${RELAY_URL}/msg/${BOB_USER}")
e0=$(echo "${ALL}" | jq '.[0]')
e1=$(echo "${ALL}" | jq '.[1]')

# Clear Bob's queue by acking both (POST /ack/<user>/<n>)
curl -sS -X POST "${RELAY_URL}/ack/${BOB_USER}/2" >/dev/null

# Re-post out of order: first e1 then e0
echo "${e1}" | curl -sS -X POST -H 'Content-Type: application/json' -d @- "${RELAY_URL}/msg/${BOB_USER}" >/dev/null
echo "${e0}" | curl -sS -X POST -H 'Content-Type: application/json' -d @- "${RELAY_URL}/msg/${BOB_USER}" >/dev/null

# Bob should still decrypt both in some order
OUT=$("${CIPHERA_BIN}" recv --home "${BOB_HOME}" --username "${BOB_USER}" --relay "${RELAY_URL}" --passphrase "${BOB_PASS}")
echo "${OUT}"

echo "${OUT}" | grep -q "\[${ALICE_USER}\] m0"
echo "${OUT}" | grep -q "\[${ALICE_USER}\] m1"

echo "[+] Out-of-order delivery handled."

#!/usr/bin/env bash
set -euo pipefail

RELAY_URL="http://127.0.0.1:8080"
ALICE_HOME="/tmp/alice-ciphera-vis-alice"
BOB_HOME="/tmp/bob-ciphera-vis-bob"
ALICE_USER="alice"
BOB_USER="bob"
ALICE_PASS="alice-pass"
BOB_PASS="bob-pass"
SECRET_MSG="this-should-not-appear-on-the-relay"

ROOT_DIR="$(
  git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel 2>/dev/null \
    || (cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
)"
BIN_DIR="${ROOT_DIR}/bin"
CIPHERA_BIN="${BIN_DIR}/ciphera"
RELAY_BIN="${BIN_DIR}/relay"
RELAY_LOG="/tmp/ciphera-relay-vis.log"

cleanup() {
  if [[ -n "${RELAY_PID:-}" ]]; then
    kill "${RELAY_PID}" >/dev/null 2>&1 || true
    wait "${RELAY_PID}" >/dev/null 2>&1 || true
  fi
  rm -rf "${ALICE_HOME}" "${BOB_HOME}"
}
trap cleanup EXIT

# Build
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

# Fresh homes
rm -rf "${ALICE_HOME}" "${BOB_HOME}"
mkdir -p "${ALICE_HOME}" "${BOB_HOME}"

# Identities + prekeys
"${CIPHERA_BIN}" init \
  --home       "${ALICE_HOME}" \
  --passphrase "${ALICE_PASS}"
"${CIPHERA_BIN}" register \
  --home       "${ALICE_HOME}" \
  --relay      "${RELAY_URL}" \
  "${ALICE_USER}" \
  --passphrase "${ALICE_PASS}"

"${CIPHERA_BIN}" init \
  --home       "${BOB_HOME}" \
  --passphrase "${BOB_PASS}"
"${CIPHERA_BIN}" register \
  --home       "${BOB_HOME}" \
  --relay      "${RELAY_URL}" \
  "${BOB_USER}" \
  --passphrase "${BOB_PASS}"

# Sessions
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

# Send a message
"${CIPHERA_BIN}" send \
  --home       "${ALICE_HOME}" \
  --username   "${ALICE_USER}" \
  --relay      "${RELAY_URL}" \
  --passphrase "${ALICE_PASS}" \
  "${BOB_USER}" \
  "${SECRET_MSG}"

# Inspect relay queue for Bob
RAW="$(curl -s "${RELAY_URL}/msg/${BOB_USER}")"

echo "Envelope metadata:"
echo "${RAW}" | jq \
  '.[0] | {from, to, has_header:(.header|has("dh_pub")), has_cipher:has("cipher")}'

# Ensure plaintext is not visible
if echo "${RAW}" | grep -q "${SECRET_MSG}"; then
  echo "[-] Found plaintext on relay output!" && exit 1
fi

# Assert presence of cipher and snake_case header fields
echo "${RAW}" | jq -e \
  '.[0].cipher and (.[0].header|has("dh_pub")) and (.[0].header|has("n"))' \
  >/dev/null

echo "[+] Relay stores ciphertext + header only (no plaintext)."

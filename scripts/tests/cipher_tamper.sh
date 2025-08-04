#!/usr/bin/env bash
set -euo pipefail

RELAY_URL="http://127.0.0.1:8080"
ALICE_HOME="/tmp/alice-ciphera-t2-alice"
BOB_HOME="/tmp/bob-ciphera-t2-bob"
ALICE_USER="alice"
BOB_USER="bob"
ALICE_PASS="alice-pass"
BOB_PASS="bob-pass"
MSG="integrity-check"

ROOT_DIR="$(
  git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel 2>/dev/null \
  || ( cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P )
)"
BIN_DIR="${ROOT_DIR}/bin"
CIPHERA_BIN="${BIN_DIR}/ciphera"
RELAY_BIN="${BIN_DIR}/relay"
RELAY_LOG="/tmp/ciphera-relay-t2.log"

cleanup() {
  if [[ -n "${RELAY_PID:-}" ]]; then kill "${RELAY_PID}" >/dev/null 2>&1 || true; wait "${RELAY_PID}" 2>/dev/null || true; fi
  rm -rf "${ALICE_HOME}" "${BOB_HOME}"
}
trap cleanup EXIT

# Build
mkdir -p "${BIN_DIR}"
( cd "${ROOT_DIR}" && go build -o "${CIPHERA_BIN}" ./cmd/ciphera && go build -o "${RELAY_BIN}" ./cmd/relay )

# Start relay
"${RELAY_BIN}" >"${RELAY_LOG}" 2>&1 & RELAY_PID=$!
for _ in {1..50}; do curl -s "${RELAY_URL}/prekey/does-not-exist" >/dev/null 2>&1 && break; sleep 0.1; done

# Fresh homes
rm -rf "${ALICE_HOME}" "${BOB_HOME}"; mkdir -p "${ALICE_HOME}" "${BOB_HOME}"

# Identities + prekeys
"${CIPHERA_BIN}" init --home "${ALICE_HOME}" --passphrase "${ALICE_PASS}"
"${CIPHERA_BIN}" register --home "${ALICE_HOME}" --relay "${RELAY_URL}" "${ALICE_USER}" --passphrase "${ALICE_PASS}"

"${CIPHERA_BIN}" init --home "${BOB_HOME}" --passphrase "${BOB_PASS}"
"${CIPHERA_BIN}" register --home "${BOB_HOME}" --relay "${RELAY_URL}" "${BOB_USER}" --passphrase "${BOB_PASS}"

# Sessions
"${CIPHERA_BIN}" start-session --home "${BOB_HOME}" --relay "${RELAY_URL}" "${ALICE_USER}" --passphrase "${BOB_PASS}"
"${CIPHERA_BIN}" start-session --home "${ALICE_HOME}" --relay "${RELAY_URL}" "${BOB_USER}" --passphrase "${ALICE_PASS}"

# Send a legitimate message first
"${CIPHERA_BIN}" send --home "${ALICE_HOME}" --username "${ALICE_USER}" --relay "${RELAY_URL}" --passphrase "${ALICE_PASS}" "${BOB_USER}" "${MSG}"

# Fetch that envelope and craft a tampered copy (flip one base64 char)
ENV="$(curl -s "${RELAY_URL}/msg/${BOB_USER}" | jq '.[0]')"
TAMPERED="$(jq -r '.cipher' <<<"${ENV}")"
# crude tamper: replace first char with a different valid base64 char
FIRST="${TAMPERED:0:1}"; REP="A"; [[ "${FIRST}" == "A" ]] && REP="B"
TAMPERED="${REP}${TAMPERED:1}"

# Re-post a second, tampered envelope to Bob
jq --arg c "${TAMPERED}" '.cipher = $c' <<<"${ENV}" \
| curl -sS -X POST -H 'Content-Type: application/json' -d @- "${RELAY_URL}/msg/${BOB_USER}" >/dev/null

# Bob tries to receive; should fail due to AEAD verify error
set +e
"${CIPHERA_BIN}" recv --home "${BOB_HOME}" --username "${BOB_USER}" --relay "${RELAY_URL}" --passphrase "${BOB_PASS}" >/tmp/t2.out 2>&1
RC=$?
set -e

if [[ ${RC} -eq 0 ]]; then
  echo "[-] Tampered ciphertext was accepted!"; cat /tmp/t2.out; exit 1
fi

echo "[+] Tampered ciphertext rejected (AEAD integrity worked)."

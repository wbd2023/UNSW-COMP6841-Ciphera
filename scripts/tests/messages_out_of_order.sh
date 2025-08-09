#!/usr/bin/env bash
set -euo pipefail

RELAY_URL="http://127.0.0.1:8080"
ALICE_HOME="/tmp/alice-ciphera-t4-alice"
BOB_HOME="/tmp/bob-ciphera-t4-bob"
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
RELAY_LOG="/tmp/ciphera-relay-test-messages-out-of-order.log"

cleanup() {
  if [[ -n "${RELAY_PID:-}" ]]; then
    kill "${RELAY_PID}" >/dev/null 2>&1 || true
    wait "${RELAY_PID}" >/dev/null 2>&1 || true
  fi
  rm -rf "${ALICE_HOME}" "${BOB_HOME}"
}
trap cleanup EXIT

# Check deps
command -v jq >/dev/null 2>&1 || { echo "jq is required"; exit 1; }

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

# Initialise and register both peers
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

# Establish sessions
"${CIPHERA_BIN}" start-session \
  --home       "${ALICE_HOME}" \
  --relay      "${RELAY_URL}" \
  "${BOB_USER}" \
  --passphrase "${ALICE_PASS}"
"${CIPHERA_BIN}" start-session \
  --home       "${BOB_HOME}" \
  --relay      "${RELAY_URL}" \
  "${ALICE_USER}" \
  --passphrase "${BOB_PASS}"

# Bootstrap the conversation so later messages are in the same chain
"${CIPHERA_BIN}" send \
  --home       "${ALICE_HOME}" \
  --username   "${ALICE_USER}" \
  --relay      "${RELAY_URL}" \
  --passphrase "${ALICE_PASS}" \
  "${BOB_USER}" \
  "bootstrap"
# Bob receives and acks bootstrap
"${CIPHERA_BIN}" recv \
  --home       "${BOB_HOME}" \
  --username   "${BOB_USER}" \
  --relay      "${RELAY_URL}" \
  --passphrase "${BOB_PASS}" >/dev/null

# Alice sends two messages in the same chain
MSG1="first"
MSG2="second"
"${CIPHERA_BIN}" send \
  --home       "${ALICE_HOME}" \
  --username   "${ALICE_USER}" \
  --relay      "${RELAY_URL}" \
  --passphrase "${ALICE_PASS}" \
  "${BOB_USER}" \
  "${MSG1}"
"${CIPHERA_BIN}" send \
  --home       "${ALICE_HOME}" \
  --username   "${ALICE_USER}" \
  --relay      "${RELAY_URL}" \
  --passphrase "${ALICE_PASS}" \
  "${BOB_USER}" \
  "${MSG2}"

# Fetch only those two, then ack them to clear the queue
ENVS="$(curl -sSf "${RELAY_URL}/msg/${BOB_USER}?limit=2")"
COUNT="$(jq 'length' <<<"${ENVS}")"
if [[ "${COUNT}" -ne 2 ]]; then
  echo "[-] Expected 2 envelopes, got ${COUNT}"
  echo "${ENVS}"
  exit 1
fi
curl -sSf -X POST -H 'Content-Type: application/json' \
  -d "{\"count\": ${COUNT}}" \
  "${RELAY_URL}/msg/${BOB_USER}/ack" >/dev/null

# Reverse the order and re-post as two separate envelopes
FIRST="$(jq -c '.[0]' <<<"${ENVS}")"  # original first
SECOND="$(jq -c '.[1]' <<<"${ENVS}")" # original second

echo "Reposting in reversed order (second, then first)"
printf '%s' "${SECOND}" \
  | curl -sSf -X POST -H 'Content-Type: application/json' -d @- \
      "${RELAY_URL}/msg/${BOB_USER}" >/dev/null
printf '%s' "${FIRST}" \
  | curl -sSf -X POST -H 'Content-Type: application/json' -d @- \
      "${RELAY_URL}/msg/${BOB_USER}" >/dev/null

# Bob receives both messages (arrived out of order)
echo "[*] Bob receiving messages:"
RECV_OUTPUT="$("${CIPHERA_BIN}" recv \
  --home       "${BOB_HOME}" \
  --username   "${BOB_USER}" \
  --relay      "${RELAY_URL}" \
  --passphrase "${BOB_PASS}")"
echo "${RECV_OUTPUT}"

# Assert both are present once
if [[ "$(grep -o "first" <<<"${RECV_OUTPUT}" | wc -l | tr -d ' ')" -ne 1 ]]
then
  echo "[-] Expected exactly one 'first' in output"
  exit 1
fi
if [[ "$(grep -o "second" <<<"${RECV_OUTPUT}" | wc -l | tr -d ' ')" -ne 1 ]]
then
  echo "[-] Expected exactly one 'second' in output"
  exit 1
fi

# Ensure 'second' appears before 'first' for true out-of-order arrival
if ! awk '
    /second/ { pos2 = NR }
    /first/  { pos1 = NR }
    END { exit !(pos2 && pos1 && pos2 < pos1) }
  ' <<<"${RECV_OUTPUT}"; then
  echo "[-] Out-of-order handling failed (no ''second'' before ''first'')"
  exit 1
fi

echo "[+] Out-of-order delivery handled correctly."
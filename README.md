# Ciphera

Ciphera is a command line end-to-end encrypted chat client plus a tiny HTTP relay. The relay only stores ciphertext and prekey bundles. Your private keys never leave your machine.

## How it works

Ciphera uses **X3DH** for session setup and the **Double Ratchet** for ongoing encryption.

* **Identity keys**
  On first run, the client creates two key pairs:
  **X25519** for Diffie–Hellman (deriving shared secrets) and **Ed25519** for signatures (authenticating the signed prekey).
  Your identity keys are encrypted on disk with your passphrase.

* **Prekeys**
  The client prepares a **signed prekey** (X25519, signed by your Ed25519 key) and a batch of **one-time prekeys**. Peers verify the SPK signature and may consume an OPK at session start for extra forward secrecy.

* **Session setup (X3DH)**
  When someone wants to talk to you, they fetch your **prekey bundle** from the relay and run X3DH. Both sides derive the same **root key**, which seeds the Double Ratchet.

* **Message encryption (Double Ratchet)**
  Each message is encrypted with an AEAD scheme (ChaCha20-Poly1305) using a fresh per-message key derived from the ratchet. The header includes the sender’s current DH public key and counters, and is bound as associated data to detect tampering.

* **Relay role**
  The relay is a simple middleman that holds prekey bundles and queues encrypted envelopes until the recipient fetches them. It never sees plaintext or your private keys. Either a separate host can run the relay, or one endpoint can host it for others to use.

## Requirements

* Go **1.24.5**.
* Any platform where Go builds and runs (Linux, macOS, Windows).

## Build

You can use the Makefile (`make build`) or run `go build` directly.

### Linux / macOS

```sh
# From the repo root
go mod tidy
go build -o bin/ciphera ./cmd/ciphera
go build -o bin/relay   ./cmd/relay
```

### Windows (PowerShell)

```powershell
# From the repo root
go mod tidy
go build -o bin\ciphera.exe .\cmd\ciphera
go build -o bin\relay.exe   .\cmd\relay
```

### Cross-compiling

Set `GOOS` and `GOARCH` to target another platform.

```sh
# Examples
GOOS=linux   GOARCH=amd64 go build -o bin/ciphera-linux-amd64 ./cmd/ciphera
GOOS=darwin  GOARCH=arm64 go build -o bin/ciphera-darwin-arm64 ./cmd/ciphera
GOOS=windows GOARCH=amd64 go build -o bin/ciphera-windows-amd64.exe ./cmd/ciphera
```

For more information, read the Go documentation.

## Quick start

### 1) Run the relay (default port 8080)

```sh
./bin/relay
```

### 2) Generate your identity

```sh
./bin/ciphera init --passphrase "your strong passphrase"
```

### 3) Show your fingerprint

```sh
./bin/ciphera fingerprint --passphrase "your strong passphrase"
```

### 4) Register your prekeys with the relay

Pick a username that others will use to find you.

```sh
./bin/ciphera register --relay http://127.0.0.1:8080 alice --passphrase "your strong passphrase"
```

### 5) Start a session with someone

Assume the other person registered as `bob`.

```sh
./bin/ciphera start-session --relay http://127.0.0.1:8080 bob --passphrase "your strong passphrase"
```

You should see:

```text
Session created with bob. RootKey=...
```

A `sessions.json` file will appear in your config directory.

## Simulate two users on one machine

Use separate homes so each user has their own state.

### Alice

```sh
export ALICE_HOME=/tmp/alice-ciphera
./bin/ciphera init     --home "$ALICE_HOME" --passphrase "alice-pass"
./bin/ciphera register --home "$ALICE_HOME" --relay http://127.0.0.1:8080 alice --passphrase "alice-pass"
```

### Bob

```sh
export BOB_HOME=/tmp/bob-ciphera
./bin/ciphera init     --home "$BOB_HOME" --passphrase "bob-pass"
./bin/ciphera register --home "$BOB_HOME" --relay http://127.0.0.1:8080 bob --passphrase "bob-pass"
```

### Start sessions

```sh
./bin/ciphera start-session --home "$BOB_HOME"   --relay http://127.0.0.1:8080 alice --passphrase "bob-pass"
./bin/ciphera start-session --home "$ALICE_HOME" --relay http://127.0.0.1:8080 bob   --passphrase "alice-pass"
```

### Send and receive

```sh
./bin/ciphera send --home "$ALICE_HOME" --username alice --relay http://127.0.0.1:8080 --passphrase "alice-pass" bob "hello bob"
./bin/ciphera recv --home "$BOB_HOME"   --username bob   --relay http://127.0.0.1:8080 --passphrase "bob-pass"
```

Then reply:

```sh
./bin/ciphera send --home "$BOB_HOME" --username bob --relay http://127.0.0.1:8080 --passphrase "bob-pass" alice "hi alice"
./bin/ciphera recv --home "$ALICE_HOME" --username alice --relay http://127.0.0.1:8080 --passphrase "alice-pass"
```

## Relay topologies

Ciphera supports simple relay setups.

* **Middleman relay (recommended for most cases)**
  Run the relay on a third machine that both parties can reach. Share its URL, for example `http://relay.example:8080`. Each user points `--relay` at that URL for `register`, `start-session`, `send` and `recv`. The relay stores prekey bundles by username and queues encrypted envelopes until the recipient fetches them.

* **Endpoint-hosted relay**
  One of the participants can run the relay on their machine and provide the URL to peers. This is convenient on a LAN or over a private network such as WireGuard or Tailscale. The hosting endpoint is still an untrusted transport. It never sees plaintext or private keys.

### **Operational notes**

* If exposing the relay on the public Internet, place it behind TLS and a reverse proxy, and set basic limits on request size and rate.
* Avoid logging sensitive metadata. The application itself only deals with usernames, bundle posts and encrypted envelopes.

## Command reference

```text
ciphera init          --passphrase <pass> [--home <dir>]
ciphera fingerprint   --passphrase <pass> [--home <dir>]
ciphera register      --relay <url> <username> --passphrase <pass> [--home <dir>]
ciphera start-session --relay <url> <peer-username> --passphrase <pass> [--home <dir>]
ciphera send          --username <me> --relay <url> --passphrase <pass> <peer> <message> [--home <dir>]
ciphera recv          --username <me> --relay <url> --passphrase <pass> [--home <dir>]
```

Common flags:

* `--home` sets where Ciphera stores its files. Default is `~/.ciphera`.
* `--relay` sets the relay base URL.
* `--passphrase` protects your keys on disk and unlocks them when needed.

## Where Ciphera stores your data

Default `~/.ciphera`, or the directory you pass with `--home`:

* `identity.json` — encrypted identity keys (X25519 and Ed25519).
* `prekeys.json` — signed prekey and one-time prekeys.
* `sessions.json` — sessions you have established (root keys and peer info).
* `conversations.json` — Double Ratchet state per peer.

## Reset

```sh
rm -f ~/.ciphera/identity.json ~/.ciphera/prekeys.json ~/.ciphera/sessions.json ~/.ciphera/conversations.json
```

Replace `~/.ciphera` with your `--home` path if you set one.

## Troubleshooting

* **identity already exists**
  You ran `init` in a directory that already has an identity. Delete `identity.json` or choose another `--home`, then run `init`.

* **no relay configured**
  Provide `--relay http://host:8080` to commands that need the relay.

* **connection refused or timeouts**
  Start the relay, ensure host and port are reachable, and check firewall rules.

* **not found when starting a session**
  The peer’s username has not registered with the relay.

* **first message not received**
  Ensure both sides ran `start-session` and are pointing at the same relay. If you used different homes, pass `--home` consistently.

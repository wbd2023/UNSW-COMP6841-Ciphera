# Ciphera

Ciphera is a command line end to end encrypted chat client plus a tiny HTTP relay. The relay only stores ciphertext and prekey bundles. Your private keys never leave your machine.

## How it works

* The client (Ciphera) creates two key pairs:

  * **X25519** for Diffie–Hellman key agreement (used to derive shared secrets)
  * **Ed25519** for digital signatures (used to sign the signed prekey so others can verify it really came from you)
    These keys are encrypted on disk with your passphrase.

* The client also creates **prekeys**:

  * A **signed prekey**: a longish-lived X25519 public key signed by your Ed25519 key. Others verify this signature before using it.
  * A batch of **one-time prekeys**: X25519 public keys that are consumed once to give you forward secrecy and deniability at the session start.

* When someone wants to talk to you, they fetch your **prekey bundle** (your public identity keys, the signed prekey, and one-time prekeys) from the relay and perform the **X3DH** handshake (Extended Triple Diffie–Hellman). This derives a **root key** that seeds the messaging ratchet (not implemented here yet). The relay never sees plaintext.

## Requirements

* Go 1.24.5

## Build

### Linux

```sh
go mod vendor
go build -mod=vendor -o bin/ciphera ./cmd/ciphera
go build -mod=vendor -o bin/relay   ./cmd/relay
```

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

### **Alice**

```sh
export ALICE_HOME=/tmp/alice-ciphera
./bin/ciphera init     --home "$ALICE_HOME" --passphrase "alice-pass"
./bin/ciphera register --home "$ALICE_HOME" --relay http://127.0.0.1:8080 alice --passphrase "alice-pass"
```

### **Bob**

```sh
export BOB_HOME=/tmp/bob-ciphera
./bin/ciphera init     --home "$BOB_HOME" --passphrase "bob-pass"
./bin/ciphera register --home "$BOB_HOME" --relay http://127.0.0.1:8080 bob --passphrase "bob-pass"
```

### **Alice starts a session with Bob**

```sh
./bin/ciphera start-session --home "$ALICE_HOME" --relay http://127.0.0.1:8080 bob --passphrase "alice-pass"
```

(Optional) Bob can start his own session with Alice:

```sh
./bin/ciphera start-session --home "$BOB_HOME" --relay http://127.0.0.1:8080 alice --passphrase "bob-pass"
```

## Using it across multiple machines

1. Run the relay on one host that both parties can reach. By default it listens on `0.0.0.0:8080` (adjust firewall rules as needed).
2. Share the relay URL with your peers, for example `http://your.public.ip:8080` or a DNS name.
3. Each user runs:

   * `ciphera init --passphrase ...`
   * `ciphera register --relay http://your.public.ip:8080 <username> --passphrase ...`
4. To start a session, run:

   * `ciphera start-session --relay http://your.public.ip:8080 <peer-username> --passphrase ...`

If you do not want to expose your IP, you can place the relay behind a VPN (WireGuard, Tailscale) and use the private address, or later run it as a Tor hidden service.

## Command reference

```sh
ciphera init          --passphrase <pass> [--home <dir>]
ciphera fingerprint   --passphrase <pass> [--home <dir>]
ciphera register      --relay <url> <username> --passphrase <pass> [--home <dir>]
ciphera start-session --relay <url> <peer-username> --passphrase <pass> [--home <dir>]
```

Common flags:

* `--home` sets where Ciphera stores its files (default `~/.ciphera`)
* `--relay` sets the relay base URL (default none, you must provide it where needed)
* `--passphrase` protects your keys on disk

## Where Ciphera stores your data

(Default `~/.ciphera`, or the directory you pass with `--home`)

* `identity.json`   encrypted identity keys (X25519 and Ed25519)
* `prekeys.json`    signed prekey and one-time prekeys
* `sessions.json`   sessions you have established (root keys and peer info)

## Reset

```sh
rm -f ~/.ciphera/identity.json ~/.ciphera/prekeys.json ~/.ciphera/sessions.json
```

Replace `~/.ciphera` with your `--home` path if you set one.

## Troubleshooting (end users)

**identity already exists**
You tried to run `init` again. Delete `identity.json` or choose another `--home` and run `init`.

**no relay configured**
Provide `--relay http://host:8080` to commands that need the relay.

**connection refused or timeouts**
Start the relay, ensure the host and port are reachable, and check your firewall.

**not found when starting a session**
The username you typed has not registered with the relay. Ask the other person to run `register`.

**passphrase required**
Provide `--passphrase` and make sure it is the same one you used with `init`.

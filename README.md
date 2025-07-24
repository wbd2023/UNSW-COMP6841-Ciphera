# Ciphera

Ciphera is a command line end‑to‑end encrypted chat client plus a tiny HTTP relay. The relay only stores ciphertext and prekey bundles. Your private keys never leave your machine.

## How it works

* The **client (Ciphera)** runs on your machine. It generates two key pairs: X25519 for Diffie-Hellman and Ed25519 for signatures. These are stored encrypted on disk with your passphrase.
* The client also generates a **signed prekey** and a batch of **one‑time prekeys**. It uploads these, together with your public identity keys, to the **relay**.
* The **relay** is a very small HTTP service. It only stores prekey bundles and ciphertext messages. It never sees plaintext or your private keys.

## Requirements

* Go 1.24.5

## Build

```sh
go mod vendor
go build -mod=vendor -o bin/ciphera ./cmd/ciphera # build the ciphera app
go build -mod=vendor -o bin/relay   ./cmd/relay   # build the ciphera relay
```

## Quick start

### 1) Run the relay

```sh
./bin/relay
```

This starts an HTTP server on `:8080`.

### 2) Generate your identity

```sh
./bin/ciphera init --passphrase "your strong passphrase"
```

### 3) Show your fingerprint

```sh
./bin/ciphera fingerprint --passphrase "your strong passphrase"
```

### 4) Register prekeys with the relay

```sh
./bin/ciphera register --relay http://127.0.0.1:8080 alice --passphrase "your strong passphrase"
```

You should see "Registered prekeys with relay" in the client, and the relay should log that it received the bundle.

## Optional flags

You can choose where ciphera stores its files (default is `~/.ciphera`):

```sh
./bin/ciphera init --home /tmp/ciphera-test --passphrase "your strong passphrase"
```

All commands accept `--home` and `--passphrase`. Networked commands also accept `--relay`.

## Reset

Remove local state if you want to start again:

```sh
rm -f ~/.ciphera/identity.json ~/.ciphera/prekeys.json
```

(or the files under the directory you used with `--home`)

## Troubleshooting

**identity already exists**
Delete `~/.ciphera/identity.json` (or your custom `--home` path) and run `init` again.

**no relay configured**
Pass `--relay http://127.0.0.1:8080` (or whatever host and port your relay is using).

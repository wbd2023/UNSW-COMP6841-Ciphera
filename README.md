# Quick Startup Guide

## Build

```shell
go build -mod=vendor -o bin/ciphera ./cmd/ciphera
```

## Generate identity

```shell
./bin/ciphera init --passphrase ${YOUR PASSWORD}
```

## Print fingerprint

```shell
./bin/ciphera fingerprint --passphrase ${YOUR PASSWORD}
```

## Set config directory (Optional)

```shell
./bin/ciphera init --home ${YOUR CONFIG DIRECTORY} --passphrase ${YOUR PASSWORD}
```

#!/usr/bin/env bash

go mod tidy
go mod vendor
go build -mod=vendor -o bin/ciphera ./cmd/ciphera
go build -mod=vendor -o bin/relay   ./cmd/relay
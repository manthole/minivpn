#!/bin/sh
# Test de bout en bout avec une vraie interface réseau (Linux uniquement, droits root).
set -eu
cd "$(dirname "$0")/.."
go build -o minivpn .
sudo env "PATH=$PATH" "MINIVPN_BIN=$PWD/minivpn" go test -count=1 -tags e2e ./internal/e2e/ -v

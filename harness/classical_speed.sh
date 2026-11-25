#!/bin/sh
# classical_speed.sh — OpenSSL classical baseline (ECDH P-256, X25519,
# Ed25519 sign/verify). Writes benchmark-classical.log into $1
# (default outputs/). The ecdh/ed25519 run covers many curves at 2 s
# each; total runtime about one minute.
set -eu
OUTDIR="${1:-outputs}"
mkdir -p "$OUTDIR"
{
    echo "classical baseline: openssl speed (OpenSSL 3.0.13)"
    echo "command: timeout 90 openssl speed -elapsed -seconds 2 ecdh ed25519"
    timeout 90 openssl speed -elapsed -seconds 2 ecdh ed25519 2>&1
    echo "note: X25519 keygen/derive measured directly in harness/bench_hybrid.c section A (EVP)"
} > "$OUTDIR/benchmark-classical.log" 2>&1
echo "wrote $OUTDIR/benchmark-classical.log"

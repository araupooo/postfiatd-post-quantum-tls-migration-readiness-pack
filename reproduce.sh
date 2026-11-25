#!/usr/bin/env bash
# Reproduce every check from a fresh clone and verify all digests.
# Deterministic: the self-check log contains only PASS/FAIL lines and
# the digest verification output — no timestamps, no absolute paths, no
# measured rates — so a fresh run regenerates it byte-identically.
#
# The measurement logs are re-run on every reproduce, but into a
# scratch directory, NOT into outputs/: the vendored measurement logs
# (outputs/benchmark-kem.log, outputs/benchmark-classical.log,
# outputs/hybrid_bench.log, outputs/environment.txt) are the recorded
# evidence from the original run, and overwriting them with a new
# run's rates would silently change the evidence the docs cite.
# reproduce.sh proves the measurements can be re-derived by running
# them into scratch and structurally checking them there
# (scripts/check_measurements.py: every block present, every control
# PASS, every measured length equal to the parameter table). See
# docs/REPRODUCTION.md.
#
# Usage: bash reproduce.sh   (run from the pack root)
# Exit code 0 and "REPRODUCE OK" mean every check passed and every
# vendored file matches its recorded SHA-256.
set -e
cd "$(dirname "$0")"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
MEASUREMENT_OUTDIR="$SCRATCH" bash scripts/run_all.sh
bash verify_digests.sh
{
  echo "== tls_inventory =="
  cat outputs/tls_inventory.log
  echo "== hybrid_model =="
  cat outputs/hybrid_model.log
  echo "== migration_model =="
  cat outputs/migration_model.log
  echo "== measurement structure check =="
  MEASUREMENT_OUTDIR="$SCRATCH" python3 scripts/check_measurements.py
  echo "== digest verification =="
  bash verify_digests.sh
  echo "REPRODUCE OK"
} > outputs/reproduce_selfcheck.log
tail -5 outputs/reproduce_selfcheck.log
echo "REPRODUCE OK"

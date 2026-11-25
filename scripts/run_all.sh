#!/usr/bin/env bash
# run_all.sh — run every check and regenerate every derived log.
# Measurements go to $MEASUREMENT_OUTDIR (a scratch dir when called
# from reproduce.sh) so re-running never overwrites the vendored logs
# in outputs/. Derived model logs go to outputs/ and are deterministic.
set -e
cd "$(dirname "$0")/.."
SCRATCH="${MEASUREMENT_OUTDIR:-}"
if [ -n "$SCRATCH" ]; then
    echo "step: measurements into scratch dir"
else
    echo "step: measurements into outputs/"
fi
bash harness/run_benchmarks.sh
echo "step: tls inventory"
python3 scripts/tls_inventory.py > outputs/tls_inventory.log 2>&1
echo "step: hybrid model"
python3 scripts/hybrid_model.py > outputs/hybrid_model.log 2>&1
echo "step: migration model"
python3 scripts/migration_model.py > outputs/migration_model.log 2>&1
echo "step: measurement structure check"
MEASUREMENT_OUTDIR="${MEASUREMENT_OUTDIR:-outputs}" python3 scripts/check_measurements.py
echo "RUN_ALL OK"

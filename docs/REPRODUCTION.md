# Reproduction

## Quick check (no build)

```sh
bash verify_digests.sh
```

Checks every file listed in `SHA256SUMS` against its recorded
SHA-256. Exits 0 only when every covered file matches.

## Full reproduction

```sh
bash reproduce.sh   # exit 0, REPRODUCE OK
```

What it does, in order:

1. Creates a scratch directory (`mktemp -d`) and sets
   `MEASUREMENT_OUTDIR` to it.
2. Runs `scripts/run_all.sh`: builds liboqs 0.14.0 from the
   pinned commit (or reuses a local checkout at that commit),
   compiles both harnesses, runs the KEM, classical, and hybrid
   benchmarks **into the scratch directory**, runs the TLS
   inventory, the hybrid model, and the migration model, and
   structurally checks the fresh measurement logs.
3. Runs `bash verify_digests.sh`.
4. Writes `outputs/reproduce_selfcheck.log`, which contains only
   PASS/FAIL lines and the digest verification output — no
   timestamps, no absolute paths, no measured rates — so a fresh
   run regenerates it byte-identically. Run `bash reproduce.sh`
   three times and compare the log with `sha256sum` to confirm.

## Why the vendored measurement logs are never overwritten

The measurement logs (`outputs/benchmark-kem.log`,
`outputs/benchmark-classical.log`, `outputs/hybrid_bench.log`,
`outputs/environment.txt`) are the recorded evidence from the
original run, and the docs cite their exact numbers and line
numbers. Overwriting them with a new run's rates would silently
change the evidence. `reproduce.sh` therefore runs the
measurements into a scratch directory and proves they can be
re-derived by structurally checking them there
(`scripts/check_measurements.py`: every expected block present,
every control PASS, every measured length equal to the parameter
table in `data/kem_params.json`).

## CI

`.github/workflows/ci.yml` runs `bash reproduce.sh` on
ubuntu-latest with Python 3.12. On a fresh runner, liboqs is
cloned at tag 0.14.0 into `.deps/liboqs` and built from source
(a few minutes). No local checkout paths are used anywhere:
the inventory reads vendored excerpts from
`data/source_excerpts.json`, and `--pin` is only an optional
cross-check that never changes the printed output.

## Requirements

- Python 3.10+ (stdlib only), `cc`, `cmake`, `git`,
  OpenSSL development headers (`libssl-dev` on Ubuntu).
- Network access once, to clone liboqs 0.14.0, unless a local
  checkout at the pinned commit exists at `~/liboqs` (or
  `LIBOQS_SRC` is set).

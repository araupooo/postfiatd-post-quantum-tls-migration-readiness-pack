# Failure modes

Each mode names the symptom, the cause, and what to do. Modes
marked [REPRO] were observed during the build of this pack.

## FM-01 — liboqs source not found

- Symptom: `run_benchmarks.sh` reports "liboqs not found
  locally" and clones tag 0.14.0, or fails without network.
- Cause: no local checkout at the pinned commit and no network.
- Fix: set `LIBOQS_SRC` to a checkout of tag 0.14.0, or let the
  script clone it once.

## FM-02 — liboqs commit mismatch

- Symptom: `ERROR: liboqs HEAD is not the pinned 0.14.0 commit`.
- Cause: `LIBOQS_SRC` (or `~/liboqs`) is a different commit.
- Fix: check out tag 0.14.0 (`94b421ebb82405c843dba4e9aa521a56ee5a333d`)
  in that tree.

## FM-03 — compile fails: oqs.h not found [REPRO]

- Symptom: `fatal error: oqs/oqs.h: No such file or directory`.
- Cause: the liboqs build include directory was not on the
  include path (the generated headers live in
  `<build>/include/oqs/`, the source headers in `<src>/`).
- Fix: compile with both `-I<src>` and `-I<build>/include`.
  `harness/run_benchmarks.sh` does this.

## FM-04 — compile output piped through head [REPRO]

- Symptom: the compiler is killed by SIGPIPE and the failure is
  masked.
- Cause: piping a `cc` invocation through `head`.
- Fix: never pipe a compile through `head`; run it directly and
  check the exit code.

## FM-05 — decaps timing measures encaps+decaps [REPRO]

- Symptom: the decaps rate looks identical to the encaps rate.
- Cause: the benchmark loop re-ran encaps inside the decaps
  timing arm.
- Fix: pre-generate the ciphertext and time pure decaps.
  `harness/bench_kem.c` does this; the fix is verified by the
  distinct keygen/encaps/decaps figures in section B.

## FM-06 — openssl speed rejects the algorithm name [REPRO]

- Symptom: `unknown cipher` / `unknown option` for
  `openssl speed -evp x25519`.
- Cause: `-evp` does not accept x25519 / prime256v1 / ed25519.
- Fix: use plain `openssl speed -elapsed -seconds 2 ecdh ed25519`
  (see `harness/classical_speed.sh`).

## FM-07 — pkill matches the caller's own shell [REPRO]

- Symptom: the exec session dies while killing `openssl speed`.
- Cause: `pkill -f "openssl speed"` matches the shell command
  string itself.
- Fix: never `pkill -f` with a pattern that matches your own
  command line; use `timeout` instead (the classical script
  already wraps the run in `timeout 90`).

## FM-08 — reproduce overwrites vendored logs

- Symptom: docs cite log line numbers that no longer match.
- Cause: a reproduce run writing into `outputs/` instead of a
  scratch directory.
- Fix: `reproduce.sh` always sets `MEASUREMENT_OUTDIR` to a
  fresh `mktemp -d`. Never run `run_benchmarks.sh` with
  `MEASUREMENT_OUTDIR=outputs` after the pack is frozen.

## FM-09 — digest mismatch on reproduce_selfcheck.log

- Symptom: `verify_digests.sh` reports a mismatch for
  `outputs/reproduce_selfcheck.log`.
- Cause: the log embeds the digest output, so it can never be
  in its own digest set.
- Fix: the log is excluded from `SHA256SUMS` by design; verify
  it by byte-identical regeneration across three runs instead.

## FM-10 — inventory excerpt drift

- Symptom: `tls_inventory.py --pin` reports a mismatch.
- Cause: the pinned checkout moved or a different commit was
  checked out.
- Fix: restore the checkout to `0085a1ff885d6a446369cf73a4430f75af22be55`
  and re-run; the vendored excerpts are the reference.

## FM-11 — CI fails: cmake or libssl-dev missing

- Symptom: the CI run fails at the build step.
- Cause: the runner lacks the build tools.
- Fix: `.github/workflows/ci.yml` installs `cmake` and
  `libssl-dev` before running `reproduce.sh`.

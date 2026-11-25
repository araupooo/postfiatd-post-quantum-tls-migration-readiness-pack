#!/usr/bin/env python3
"""check_measurements.py — structural check of the measurement logs.

The measurement logs (benchmark-kem.log, benchmark-classical.log,
hybrid_bench.log) contain rates that vary between runs, so they are
NOT covered by SHA256SUMS and are NOT copied into
outputs/reproduce_selfcheck.log. This script is the reproducibility
check for them: it verifies that every expected block is present,
every control passed, every measured length equals the parameter
table in data/kem_params.json, and every log ends with its OK line.
It prints only PASS/FAIL lines (no measured numbers), so its output
is deterministic.

Usage: python3 scripts/check_measurements.py
  (reads the logs from $MEASUREMENT_OUTDIR, default outputs/)
  Exit 0 when every structural check passes.
"""
import json
import os
import re
import sys

PACK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
fails = 0


def check(cond, what):
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {what}")
    if not cond:
        fails += 1


def read_logs():
    logs_dir = os.environ.get("MEASUREMENT_OUTDIR",
                              os.path.join(PACK, "outputs"))
    out = {}
    for name in ("benchmark-kem.log", "benchmark-classical.log",
                 "hybrid_bench.log", "environment.txt"):
        path = os.path.join(logs_dir, name)
        out[name] = open(path).read() if os.path.exists(path) else ""
        if not out[name]:
            print(f"FAIL: {name} is missing from {logs_dir}")
            global fails
            fails += 1
    return out


def main() -> int:
    with open(os.path.join(PACK, "data", "kem_params.json")) as fh:
        params = json.load(fh)
    by_name = {a["display"]: a for a in params["algorithms"]}
    logs = read_logs()
    kem = logs["benchmark-kem.log"]
    hyb = logs["hybrid_bench.log"]
    cls = logs["benchmark-classical.log"]
    env = logs["environment.txt"]

    print("== measurement logs structural check ==")
    print("[step] KEM parameter lengths (section A)")
    for m in re.finditer(
            r"  (ML-KEM-\d+): liboqs pk=(\d+) sk=(\d+) ct=(\d+) ss=(\d+)",
            kem):
        name, pk, sk, ct, ss = m.groups()
        want = by_name[name]
        check(int(pk) == want["public_key_bytes"] and
              int(sk) == want["secret_key_bytes"] and
              int(ct) == want["ciphertext_bytes"] and
              int(ss) == want["shared_secret_bytes"],
              f"{name} lengths pk {pk} sk {sk} ct {ct} ss {ss} match params")
    print("[step] KEM RESULT lines (section B)")
    for name in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"):
        check(re.search(rf"RESULT {name} keygen_us=[\d.]+ "
                        rf"encaps_us=[\d.]+ decaps_us=[\d.]+ n=\d+", kem)
              is not None,
              f"{name} keygen/encaps/decaps RESULT line present")
    print("[step] implicit rejection (section C)")
    check("RESULT implicit_rejection_total 108/108" in kem,
          "implicit rejection total is 108/108")
    for name in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"):
        check(f"RESULT {name} implicit_rejection 36/36" in kem,
              f"{name} implicit rejection 36/36")
    print("[step] timing + key reuse (sections D, E)")
    check(re.search(r"RESULT ML-KEM-768 decaps_timing valid_us=[\d.]+ "
                    r"invalid_us=[\d.]+ n=1000", kem) is not None,
          "ML-KEM-768 valid/invalid decaps timing RESULT present")
    check("RESULT ML-KEM-768 key_reuse roundtrips=100/100 "
          "distinct_ciphertexts=100/100" in kem,
          "ML-KEM-768 key reuse 100/100 roundtrips, 100/100 distinct")
    check("RESULT ML-KEM-768 wrong_key_decaps rc=0 matches_ref=0" in kem,
          "wrong-key decaps does not recover the secret")
    check("RESULT ML-KEM-768 replay_decaps deterministic=1" in kem,
          "replay decaps is deterministic")
    check("RESULT bench_kem OK" in kem, "bench_kem ends OK")
    print("[step] hybrid bench")
    check("RESULT X25519 keygen_us=" in hyb, "X25519 keygen RESULT present")
    check("RESULT X25519 derive_us=" in hyb, "X25519 derive RESULT present")
    for name in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"):
        check(re.search(rf"RESULT {name} hybrid client_us=[\d.]+ "
                        rf"server_us=[\d.]+ total_us=[\d.]+ n=\d+", hyb)
              is not None,
              f"{name} hybrid handshake RESULT present")
        check(f"RESULT {name} wire_bytes x25519_pub=32" in hyb,
              f"{name} hybrid wire-bytes RESULT present")
    check("RESULT hybrid all_zero_x25519 rc=-1 rejected_by_openssl" in hyb,
          "control C-1: all-zero X25519 peer key rejected")
    check("RESULT hybrid tampered_ct rc=0 matches_ref=0" in hyb,
          "control C-2: tampered ciphertext changes the hybrid secret")
    check("RESULT hybrid tampered_x25519 matches_ref=0" in hyb,
          "control C-3: tampered X25519 part changes the hybrid secret")
    check("RESULT bench_hybrid OK" in hyb, "bench_hybrid ends OK")
    print("[step] classical baseline + environment")
    check("253 bits ecdh (X25519)" in cls, "openssl speed X25519 line present")
    check("256 bits ecdh (nistp256)" in cls, "openssl speed P-256 line present")
    check("253 bits EdDSA (Ed25519)" in cls, "openssl speed Ed25519 line present")
    check("liboqs: 0.14.0 commit 94b421eb" in env,
          "environment records the pinned liboqs commit")
    check("postfiatd pin: 0085a1ff" in env,
          "environment records the pinned postfiatd commit")
    print(f"check_measurements: {'PASS' if fails == 0 else 'FAIL'} "
          f"({fails} failures)")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

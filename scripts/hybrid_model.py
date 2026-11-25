#!/usr/bin/env python3
"""Verify the hybrid KEM model arithmetic from data/hybrid_model.json.

Usage: python3 scripts/hybrid_model.py
  (run from the pack root; deterministic — prints only PASS/FAIL
  lines, no measured rates. The measured values live in the JSON
  file; this script checks the arithmetic that derives from them.)
Exit 0 only if every check passes.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
fails = 0


def check(cond, what):
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {what}")
    if not cond:
        fails += 1


def main() -> int:
    with open(os.path.join(ROOT, "data", "hybrid_model.json")) as fh:
        model = json.load(fh)
    with open(os.path.join(ROOT, "data", "kem_params.json")) as fh:
        params = json.load(fh)
    by_name = {a["display"]: a for a in params["algorithms"]}

    print("== hybrid model arithmetic ==")
    for combo in model["combinations"]:
        kem = combo["kem"]
        p = by_name[kem]
        print(f"[step] {kem}")
        check(combo["kem_ct_bytes"] == p["ciphertext_bytes"],
              f"{kem} ciphertext bytes match params "
              f"({combo['kem_ct_bytes']} == {p['ciphertext_bytes']})")
        check(combo["kem_pk_bytes"] == p["public_key_bytes"],
              f"{kem} public key bytes match params")
        check(combo["wire_client_to_server_bytes"] ==
              3 + 32 + combo["kem_ct_bytes"],
              f"{kem} wire bytes = 3 header + 32 X25519 + "
              f"{combo['kem_ct_bytes']} ct = "
              f"{combo['wire_client_to_server_bytes']}")
        check(abs(combo["total_us"] - (combo["client_us"] + combo["server_us"])) < 0.01,
              f"{kem} total = client + server "
              f"({combo['total_us']} == {combo['client_us']} + {combo['server_us']})")
        overhead = combo["total_us"] - model["x25519_only_reference"]["client_and_server_derive_us"]
        recorded = model["x25519_only_reference"]["overhead_us"][kem]
        check(abs(overhead - recorded) < 0.01,
              f"{kem} hybrid overhead vs X25519-only = {overhead:.2f} us "
              f"(recorded {recorded})")
    print("[step] wire format completeness")
    fields = model["wire_format"]["fields"]
    total_fixed = sum(f["length_bytes"] for f in fields
                      if isinstance(f["length_bytes"], int))
    check(total_fixed == 35,
          f"fixed header+key bytes = 35 (version 1 + kem_id 1 + mode 1 + "
          f"X25519 pub 32); ciphertext length fixed by kem_id")
    check(all("value" in f for f in fields),
          "every wire-format field has a fixed value or length")
    check(model["wire_format"]["note"].startswith("Every byte"),
          "wire format declares no unspecified bytes")
    print(f"hybrid_model: {'PASS' if fails == 0 else 'FAIL'} "
          f"({fails} failures)")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

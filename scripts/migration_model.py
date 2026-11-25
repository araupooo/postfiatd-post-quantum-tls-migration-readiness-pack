#!/usr/bin/env python3
"""Verify the staged migration plan arithmetic from data/migration_plan.json.

Usage: python3 scripts/migration_model.py
  (run from the pack root; deterministic — prints only PASS/FAIL lines.)
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


def weeks(spec):
    if spec == "ongoing":
        return (0, 0)
    lo, hi = spec.split("-")
    return (int(lo), int(hi))


def main() -> int:
    with open(os.path.join(ROOT, "data", "migration_plan.json")) as fh:
        plan = json.load(fh)
    stages = plan["stages"]
    print("== migration plan model ==")
    print(f"[step] stages present: {[s['id'] for s in stages]}")
    check([s["id"] for s in stages] == ["S0", "S1", "S2", "S3", "S4"],
          "stages are S0..S4 in order")
    total_lo = total_hi = 0
    for s in stages:
        print(f"[step] {s['id']} {s['name']}")
        lo, hi = weeks(s["duration_estimate_weeks"])
        total_lo += lo
        total_hi += hi
        check(bool(s["gate"]), f"{s['id']} has a gate")
        check(len(s["work"]) >= 2, f"{s['id']} has at least 2 work items")
        check("Gate check:" in s["gate"], f"{s['id']} gate names its check")
    print(f"[step] planning horizon: S0..S3 total {total_lo}-{total_hi} weeks")
    check((total_lo, total_hi) == (15, 30),
          f"S0..S3 durations sum to 15-30 weeks "
          f"(got {total_lo}-{total_hi})")
    print("[step] open design decisions")
    for d in plan["open_design_decisions"]:
        check(d["label"] == "EXPLICIT OPEN DESIGN DECISION",
              f"{d['id']} is labelled an explicit open design decision")
        check(bool(d["question"]), f"{d['id']} states its question")
        check(d["status"] == "open", f"{d['id']} status is open")
    check(len(plan["open_design_decisions"]) == 3,
          "exactly 3 open design decisions (D-01, D-02, D-03)")
    print(f"migration_model: {'PASS' if fails == 0 else 'FAIL'} "
          f"({fails} failures)")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

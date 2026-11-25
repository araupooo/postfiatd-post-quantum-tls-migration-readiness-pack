#!/usr/bin/env python3
"""Generate data/source_excerpts.json from the pinned postfiatd checkout.

Run once by the pack author (NOT part of reproduce.sh):
  python3 scripts/make_excerpts.py --pin ~/workspace/postfiatd-pin-0085a1f

The output records exact source lines (file, line number, text) so the
pack's checks can run without a local checkout. scripts/tls_inventory.py
verifies every check against these excerpts, and --pin re-checks them
against a real checkout when one is present.
"""
import argparse
import json
import os
import sys

PINNED_COMMIT = "0085a1ff885d6a446369cf73a4430f75af22be55"

# (file, start_line, end_line) — 1-based, inclusive
RANGES = [
    ("src/libxrpl/basics/make_SSLContext.cpp", 60, 70),
    ("src/libxrpl/basics/make_SSLContext.cpp", 100, 106),
    ("src/libxrpl/basics/make_SSLContext.cpp", 168, 174),
    ("src/libxrpl/basics/make_SSLContext.cpp", 228, 236),
    ("src/libxrpl/basics/make_SSLContext.cpp", 346, 362),
    ("src/libxrpl/basics/make_SSLContext.cpp", 380, 392),
    ("src/libxrpl/basics/make_SSLContext.cpp", 394, 404),
    ("src/xrpld/overlay/detail/ConnectAttempt.cpp", 44, 54),
    ("src/xrpld/overlay/detail/ConnectAttempt.cpp", 170, 180),
    ("src/xrpld/overlay/detail/ConnectAttempt.h", 42, 46),
    ("src/xrpld/overlay/Overlay.h", 48, 70),
    ("src/xrpld/overlay/detail/OverlayImpl.cpp", 1546, 1554),
    ("src/xrpld/rpc/detail/ServerHandler.cpp", 1084, 1098),
    ("src/xrpld/rpc/detail/ServerHandler.cpp", 240, 248),
    ("src/xrpld/app/misc/detail/WorkSSL.cpp", 30, 62),
    ("src/libxrpl/net/HTTPClient.cpp", 292, 300),
    ("src/xrpld/overlay/README.md", 31, 36),
    ("src/xrpld/overlay/detail/PeerImp.cpp", 196, 206),
    ("src/xrpld/overlay/detail/PeerImp.cpp", 790, 800),
    ("src/xrpld/app/misc/detail/ValidatorSite.cpp", 266, 274),
    ("src/xrpld/app/misc/RemoteExclusionListFetcher.cpp", 192, 200),
    ("src/libxrpl/net/RegisterSSLCerts.cpp", 40, 55),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pin", required=True)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    pin = os.path.expanduser(args.pin)
    out = args.out or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data",
        "source_excerpts.json",
    )
    files = {}
    total = 0
    for rel, start, end in RANGES:
        path = os.path.join(pin, rel)
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        assert end <= len(lines), f"{rel} has only {len(lines)} lines"
        store = files.setdefault(rel, {})
        for ln in range(start, end + 1):
            store[str(ln)] = lines[ln - 1].rstrip("\n")
            total += 1
    data = {"pinned_commit": PINNED_COMMIT, "files": files}
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"wrote {out}: {total} lines across {len(files)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())

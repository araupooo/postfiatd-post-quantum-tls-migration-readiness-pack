#!/usr/bin/env python3
"""Verify the TLS/transport inventory against vendored source excerpts.

Usage:
  python3 scripts/tls_inventory.py [--pin <postfiatd-checkout>]
  (run from the pack root; --pin is optional and silent when the
  checkout is absent — it cross-checks every excerpt line against
  the real checkout and fails on mismatch.)

Writes data/tls_inventory.json and prints a verbose per-step log to
stdout (captured to outputs/tls_inventory.log by scripts/run_all.sh).
Exit 0 only if every check passes.
"""
import argparse
import json
import os
import re
import sys

PINNED_COMMIT = "0085a1ff885d6a446369cf73a4430f75af22be55"

# (check id, relative path, regex, description)
CHECKS = [
    ("I-01", "src/xrpld/overlay/README.md",
     r"outgoing TLS encrypted",
     "peer protocol connections are TLS encrypted (README handshake)"),
    ("I-02", "src/xrpld/overlay/detail/ConnectAttempt.h",
     r"using stream_type = boost::beast::ssl_stream<middle_type>;",
     "outgoing peer stream is a Beast SSL stream over TCP"),
    ("I-03", "src/xrpld/overlay/detail/ConnectAttempt.cpp",
     r"stream_\.set_verify_mode\(boost::asio::ssl::verify_none\);",
     "outgoing peer TLS verifies nothing (verify_none)"),
    ("I-04", "src/xrpld/overlay/detail/ConnectAttempt.cpp",
     r"stream_\.async_handshake\(",
     "outgoing peer performs a TLS client handshake"),
    ("I-05", "src/xrpld/overlay/detail/ConnectAttempt.cpp",
     r"boost::asio::ssl::stream_base::client,",
     "outgoing peer handshake is in the client role"),
    ("I-06", "src/xrpld/overlay/Overlay.h",
     r"using stream_type = boost::beast::ssl_stream<socket_type>;",
     "overlay peer stream type is a Beast SSL stream"),
    ("I-07", "src/xrpld/overlay/detail/OverlayImpl.cpp",
     r"setup\.context = make_SSLContext\(\"\"\);",
     "peer listener SSL context comes from make_SSLContext (anonymous)"),
    ("I-08", "src/libxrpl/basics/make_SSLContext.cpp",
     r'defaultCipherList = "TLSv1\.2:!CBC:!DSS:!PSK:!eNULL:!aNULL";',
     "default cipher list is TLS 1.2, no CBC/DSS/PSK/eNULL/aNULL"),
    ("I-09", "src/libxrpl/basics/make_SSLContext.cpp",
     r"int defaultRSAKeyBits = 2048;",
     "anonymous cert uses an ephemeral 2048-bit RSA key"),
    ("I-10", "src/libxrpl/basics/make_SSLContext.cpp",
     r"X509_gmtime_adj\(X509_get_notAfter\(x509\), 2 \* 365 \* 24 \* 60 \* 60\);",
     "anonymous self-signed cert is valid for two years"),
    ("I-11", "src/libxrpl/basics/make_SSLContext.cpp",
     r"X509_sign\(x509, defaultEphemeralPrivateKey, EVP_sha256\(\)\)",
     "anonymous cert is self-signed with SHA-256"),
    ("I-12", "src/libxrpl/basics/make_SSLContext.cpp",
     r"boost::asio::ssl::context::no_tlsv1 \|",
     "TLS 1.0 is disabled in the SSL context options"),
    ("I-13", "src/libxrpl/basics/make_SSLContext.cpp",
     r"boost::asio::ssl::context::no_tlsv1_1 \|",
     "TLS 1.1 is disabled in the SSL context options"),
    ("I-14", "src/libxrpl/basics/make_SSLContext.cpp",
     r"context->set_verify_mode\(boost::asio::ssl::verify_none\);",
     "make_SSLContext sets verify_none (anonymous context)"),
    ("I-15", "src/xrpld/rpc/detail/ServerHandler.cpp",
     r"p\.context = make_SSLContext\(p\.ssl_ciphers\);",
     "secure RPC/WebSocket ports use make_SSLContext when no files given"),
    ("I-16", "src/xrpld/rpc/detail/ServerHandler.cpp",
     r"p\.context = make_SSLContextAuthed\(",
     "secure RPC/WebSocket ports use file-based certs when files given"),
    ("I-17", "src/xrpld/rpc/detail/ServerHandler.cpp",
     r"if \(bundle && p\.count\(\"peer\"\) > 0\)",
     "incoming peer connections are routed from ServerHandler to overlay"),
    ("I-18", "src/xrpld/app/misc/detail/WorkSSL.cpp",
     r"boost::asio::ssl::context::tlsv12_client\)",
     "outbound HTTPS client uses a TLS 1.2 client context"),
    ("I-19", "src/xrpld/app/misc/detail/WorkSSL.cpp",
     r"auto ec = context_\.preConnectVerify\(stream_, host_\);",
     "outbound HTTPS client verifies before connecting"),
    ("I-20", "src/xrpld/app/misc/detail/WorkSSL.cpp",
     r"auto err = ec \? ec : context_\.postConnectVerify\(stream_, host_\);",
     "outbound HTTPS client verifies after connecting"),
    ("I-21", "src/xrpld/app/misc/detail/WorkSSL.cpp",
     r"stream_\.async_handshake\(",
     "outbound HTTPS client performs a TLS client handshake"),
    ("I-22", "src/libxrpl/net/HTTPClient.cpp",
     r"mSocket\.async_handshake\(",
     "HTTPClient performs a TLS client handshake when SSL is on"),
    ("I-23", "src/xrpld/app/misc/detail/ValidatorSite.cpp",
     r"sp = std::make_shared<detail::WorkSSL>\(",
     "validator-site fetches use the verifying WorkSSL client"),
    ("I-24", "src/xrpld/app/misc/RemoteExclusionListFetcher.cpp",
     r"sp = std::make_shared<detail::WorkSSL>\(",
     "exclusion-list fetches use the verifying WorkSSL client"),
    ("I-25", "src/libxrpl/net/RegisterSSLCerts.cpp",
     r'CertOpenSystemStore\(0, "ROOT"\)',
     "system cert store registration is Windows-only (ROOT store)"),
    ("I-26", "src/xrpld/overlay/detail/PeerImp.cpp",
     r"auto const sharedValue = makeSharedValue\(\*stream_ptr_, journal_\);",
     "inbound peer acceptance derives the shared value from the TLS stream"),
    ("I-27", "src/xrpld/overlay/detail/PeerImp.cpp",
     r"if \(inbound_\)",
     "inbound peers take the accept path (doAccept) after the handshake"),
]

# Negative searches, run by the author against the pinned tree and
# recorded here as measured absence (the absence is the finding).
NEGATIVE = [
    {"pattern": "stream_base::server",
     "scope": "src/ excluding src/test and src/tests",
     "verdict": "no server-role async_handshake call in the non-test tree; "
                "the only hit in the whole tree is in "
                "src/test/jtx/TrustedPublisherServer.h:560; the incoming TLS "
                "handshake is performed inside the Beast "
                "server Session implementation, not in postfiatd code"},
    {"pattern": "tlsv1_2|tlsv1_3|min_proto|max_proto|set_min_proto|"
                "SSL_CTX_set_min_proto_version|SSL_CTX_set_max_proto_version",
     "scope": "src/ excluding src/test and src/tests",
     "verdict": "no explicit TLS version floor/ceiling is set anywhere; "
                "only SSLv2/SSLv3/TLS 1.0/TLS 1.1 are disabled, so TLS 1.2 "
                "and TLS 1.3 are both negotiable where OpenSSL offers them"},
    {"pattern": "ssl_ciphers",
     "scope": "config documentation for the peer (overlay) port",
     "verdict": "the peer listener calls make_SSLContext(\"\") with an empty "
                "cipher list, so it always uses the default cipher list; "
                "ssl_ciphers overrides apply to RPC/WebSocket ports only"},
]


def load_excerpts(root):
    with open(os.path.join(root, "data", "source_excerpts.json")) as fh:
        return json.load(fh)


def grep_lines(pin, rel, pattern):
    hits = []
    with open(os.path.join(pin, rel), errors="replace") as fh:
        for i, line in enumerate(fh, 1):
            if re.search(pattern, line):
                hits.append((i, line.rstrip("\n")))
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pin", default=None)
    args = ap.parse_args()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    excerpts = load_excerpts(root)
    assert excerpts["pinned_commit"] == PINNED_COMMIT, "excerpt pin mismatch"
    print(f"tls_inventory: pinned commit {PINNED_COMMIT}")
    print(f"tls_inventory: excerpts cover {len(excerpts['files'])} files")
    results = []
    failures = 0
    for cid, rel, pattern, desc in CHECKS:
        print(f"[step] {cid} {rel} /{pattern}/")
        store = excerpts["files"].get(rel, {})
        hits = [(int(ln), tx) for ln, tx in store.items()
                if re.search(pattern, tx)]
        if not hits:
            print(f"  [FAIL] {cid}: no match in excerpts — {desc}")
            failures += 1
            results.append({"id": cid, "path": rel, "status": "FAIL",
                            "description": desc})
            continue
        ln, tx = hits[0]
        print(f"  [PASS] {cid}: line {ln}: {tx.strip()[:110]}")
        results.append({"id": cid, "path": rel, "line": ln,
                        "text": tx.strip(), "status": "PASS",
                        "description": desc})
    if args.pin:
        pin = os.path.expanduser(args.pin)
        if os.path.isdir(pin):
            print("[step] --pin cross-check against real checkout")
            mismatches = 0
            for r in results:
                if r["status"] != "PASS":
                    continue
                hits = grep_lines(pin, r["path"], "")
                # verify the recorded line still holds the recorded text
                with open(os.path.join(pin, r["path"]), errors="replace") as fh:
                    lines = fh.readlines()
                actual = lines[r["line"] - 1].rstrip("\n")
                if actual.strip() != r["text"]:
                    print(f"  [FAIL] pin mismatch {r['id']} line {r['line']}")
                    mismatches += 1
            if mismatches == 0:
                print("  [PASS] pin cross-check: all excerpt lines match")
            else:
                failures += mismatches
        else:
            print("[step] --pin given but checkout absent; skipping cross-check")
    print(f"tls_inventory: {len(results) - failures}/{len(results)} checks PASS")
    out = {
        "pinned_commit": PINNED_COMMIT,
        "checks": results,
        "negative_searches": NEGATIVE,
        "summary": f"{len(results) - failures}/{len(results)} checks passed",
    }
    with open(os.path.join(root, "data", "tls_inventory.json"), "w") as fh:
        json.dump(out, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"wrote data/tls_inventory.json")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

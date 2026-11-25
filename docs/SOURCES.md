# Sources

## Primary — postfiatd pinned tree

- Repository: postfiatd (fork of rippled), pinned commit
  `0085a1ff885d6a446369cf73a4430f75af22be55` (2026-10-10,
  version 1.0.9).
- Every source line cited in this pack was verified with
  `grep -n` against the local checkout of that commit and
  vendored as an exact excerpt in `data/source_excerpts.json`
  (262 lines across 13 files). The inventory script
  `scripts/tls_inventory.py` re-verifies every excerpt with
  `--pin` against a checkout when one is present.
- Files used (with the inventory checks that cite them; the
  pinned tree uses the modern rippled layout, `src/xrpld/...`
  and `src/libxrpl/...`):
  `src/xrpld/overlay/README.md` (I-01),
  `src/xrpld/overlay/detail/ConnectAttempt.h` (I-02),
  `src/xrpld/overlay/detail/ConnectAttempt.cpp` (I-03, I-04, I-05),
  `src/xrpld/overlay/Overlay.h` (I-06),
  `src/xrpld/overlay/detail/OverlayImpl.cpp` (I-07),
  `src/libxrpl/basics/make_SSLContext.cpp` (I-08..I-14),
  `src/xrpld/rpc/detail/ServerHandler.cpp` (I-15, I-16, I-17),
  `src/xrpld/app/misc/detail/WorkSSL.cpp` (I-18..I-21),
  `src/libxrpl/net/HTTPClient.cpp` (I-22),
  `src/xrpld/app/misc/detail/ValidatorSite.cpp` (I-23),
  `src/xrpld/app/misc/RemoteExclusionListFetcher.cpp` (I-24),
  `src/libxrpl/net/RegisterSSLCerts.cpp` (I-25),
  `src/xrpld/overlay/detail/PeerImp.cpp` (I-26, I-27).

## Primary — measurement stack

- liboqs 0.14.0, commit
  `94b421ebb82405c843dba4e9aa521a56ee5a333d`
  (https://github.com/open-quantum-safe/liboqs, tag 0.14.0).
  FIPS 203 sizes confirmed in
  `src/kem/ml_kem/kem_ml_kem.h`.
- OpenSSL 3.0.13 (system `openssl`), compiler cc 13.3.0,
  Ubuntu 24.04.5 LTS, single thread throughout.
- Measurement harnesses in `harness/bench_kem.c` and
  `harness/bench_hybrid.c`; unedited logs in `outputs/`.

## Standards

- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) — parameter sizes and
  the implicit-rejection requirement.
- draft-connolly-cfrg-xwing-kem-11 — X-Wing, the standards-track
  hybrid KEM combiner, considered as alternative H-2.
- RFC 8446 (TLS 1.3), RFC 8446 §4.2.8 (key share) — the TLS
  handshake the stage S3 simulation is derived from.

## Prior pack (context only, nothing copied)

- The ML-KEM measurements in this pack were re-run fresh
  (n=500 / n=1000). Earlier packs' ML-KEM figures were not
  reused; the numbers differ, as expected between runs.

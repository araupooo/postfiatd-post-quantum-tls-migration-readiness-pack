# Claim index

Labels: [MEASURED] — a value read from a run of this pack's
harness on the recorded machine; [SIMULATED] — a value computed
by this pack's model scripts from measured inputs;
[UNSUPPORTED] — a statement this pack could not verify, listed
so it is not mistaken for a fact.

## [MEASURED]

| ID | Claim | Evidence |
|---|---|---|
| M-01 | ML-KEM-512 keygen 13.36 µs, encaps 12.87 µs, decaps 16.75 µs (n=500) | outputs/benchmark-kem.log section B, line 25 |
| M-02 | ML-KEM-768 keygen 20.03 µs, encaps 24.45 µs, decaps 28.30 µs (n=500) | outputs/benchmark-kem.log section B, line 28 |
| M-03 | ML-KEM-1024 keygen 27.07 µs, encaps 25.24 µs, decaps 32.65 µs (n=500) | outputs/benchmark-kem.log section B, line 31 |
| M-04 | ML-KEM sizes pk 800/1184/1568, sk 1632/2400/3168, ct 768/1088/1568, ss 32 | outputs/benchmark-kem.log section A, lines 5, 11, 17; liboqs kem_ml_kem.h |
| M-05 | Implicit rejection 108/108 invalid ciphertexts (36 per KEM) | outputs/benchmark-kem.log section C, lines 41, 51, 61, 63 |
| M-06 | ML-KEM-768 decaps timing valid 26.219 µs vs invalid 25.300 µs (-3.5%, n=1000) | outputs/benchmark-kem.log section D, line 68 |
| M-07 | ML-KEM-768 key reuse 100/100 roundtrips, 100/100 distinct ciphertexts | outputs/benchmark-kem.log section E, line 74 |
| M-08 | Wrong-key decaps does not recover the secret; replay decaps is deterministic | outputs/benchmark-kem.log section E, lines 79, 82 |
| M-09 | X25519 EVP keygen 80.31 µs, derive 65.32 µs | outputs/hybrid_bench.log section A, lines 6, 9 |
| M-10 | Hybrid handshake totals 171.99 / 174.99 / 197.10 µs (ML-KEM-512/768/1024, n=200) | outputs/hybrid_bench.log section B, lines 18, 25, 32 |
| M-11 | Hybrid wire bytes 803 / 1123 / 1603 | outputs/hybrid_bench.log section B, lines 21, 28, 35 |
| M-12 | Controls C-1 (all-zero X25519 rejected), C-2 (tampered ct changes secret), C-3 (tampered X25519 changes secret) all PASS | outputs/hybrid_bench.log section C, lines 40, 44, 48 |
| M-13 | Classical baseline: X25519 18,272 ops/s (54.7 µs), P-256 14,154.5 ops/s (70.7 µs), Ed25519 sign 18,383.5/s, verify 7,163/s | outputs/benchmark-classical.log |
| M-14 | Peer TLS is anonymous: `verify_none` on the outgoing handshake and in the shared context | ConnectAttempt.cpp:175-177; make_SSLContext.cpp:391 |
| M-15 | Peer certificate is an ephemeral 2048-bit RSA self-signed cert, regenerated at every start, valid 2 years | make_SSLContext.cpp:66,172,233 |
| M-16 | Default cipher list `TLSv1.2:!CBC:!DSS:!PSK:!eNULL:!aNULL`; no TLS version floor/ceiling is set anywhere | make_SSLContext.cpp:104,350-357; negative search N-02 |
| M-17 | TLS inventory: 27/27 checks PASS | outputs/tls_inventory.log |
| M-18 | Outbound HTTPS client uses a TLS 1.2 client context with pre/post connect verification | WorkSSL.cpp:41,44,53,57 |
| M-19 | No ML-KEM / ML-DSA / hybrid key exchange exists in the pinned tree | negative search N-03 |
| M-20 | No `stream_base::server` async_handshake call exists in the non-test tree (only hit: src/test/jtx/TrustedPublisherServer.h:560) | negative search N-01 |

## [SIMULATED]

| ID | Claim | Evidence |
|---|---|---|
| S-01 | Hybrid overhead vs X25519-only: +41.35 / +44.35 / +66.46 µs (M-10 minus 2 × 65.32 µs derive) | outputs/hybrid_model.log; data/hybrid_model.json |
| S-02 | H-1 wire format is fully fixed: 35 bytes fixed header+key, ciphertext length fixed by kem_id, no unspecified bytes | outputs/hybrid_model.log; data/hybrid_model.json |
| S-03 | TLS 1.3 ML-KEM handshake adds roughly the H-1 wire bytes plus tens of bytes of record overhead | docs/CERT_HANDSHAKE.md (derived from M-11) |
| S-04 | ML-KEM-768 key distribution at 25 validators: 25 × 1,184 bytes ≈ 29.6 KB | docs/CERT_HANDSHAKE.md (M-04 × 25) |
| S-05 | Migration horizon S0–S3: 15–30 weeks | outputs/migration_model.log; data/migration_plan.json |

## [UNSUPPORTED]

| ID | Statement | Why it is unsupported |
|---|---|---|
| U-01 | Which channel will distribute the peer ML-KEM public key | Open decision D-01; the pack does not choose |
| U-02 | Which OpenSSL provider will supply ML-KEM in stage S3 | Open decision D-02; no provider is chosen or tested here |
| U-03 | Whether authed RPC ports will migrate to ML-DSA certificates | Open decision D-03; the pack recommends keeping RSA |
| U-04 | The TLS version actually negotiated by deployed peers | No live deployment was observed; only the code policy was inventoried |
| U-05 | Whether any deployment configures authed RPC certificates | No operator configuration was observed |
| U-06 | The size of a production ML-DSA certificate | FIPS 204 specification sizes only; no certificate was generated here |
| U-07 | The wall-clock duration of stages S0–S3 | Planning estimates from one maintainer and the release cadence, not measurements |

# KEM comparison: ML-KEM vs the classical baseline

All figures are [MEASURED] on the machine recorded in
`outputs/environment.txt` (single thread, liboqs 0.14.0 commit
`94b421ebb82405c843dba4e9aa521a56ee5a333d`), re-measured for this
pack. They are not copied from any earlier pack.

## 1. ML-KEM measurements

Source: `outputs/benchmark-kem.log` (harness `harness/bench_kem.c`,
n=500 for the rate lines, n=1000 for the timing comparison).

| KEM | keygen µs | encaps µs | decaps µs | pk B | sk B | ct B | ss B |
|---|---:|---:|---:|---:|---:|---:|---:|
| ML-KEM-512 | 13.36 | 12.87 | 16.75 | 800 | 1,632 | 768 | 32 |
| ML-KEM-768 | 20.03 | 24.45 | 28.30 | 1,184 | 2,400 | 1,088 | 32 |
| ML-KEM-1024 | 27.07 | 25.24 | 32.65 | 1,568 | 3,168 | 1,568 | 32 |

Sizes are confirmed against the FIPS 203 parameter sets in the
liboqs headers (`src/kem/ml_kem/kem_ml_kem.h`): pk 800/1184/1568,
sk 1632/2400/3168, ct 768/1088/1568, ss 32 for all three.

## 2. Implicit rejection

FIPS 203 requires that a decapsulation of an invalid ciphertext
returns a pseudorandom secret derived from the secret key, with
no signal that the ciphertext was invalid.

- 108/108 invalid ciphertexts (36 per KEM) decapsulated to a
  secret that differs from the reference shared secret
  (`outputs/benchmark-kem.log` section C).
- Timing (ML-KEM-768, n=1000): valid decaps 26.219 µs, invalid
  decaps 25.300 µs, delta -3.5%. No timing oracle is visible at
  this sample size; the delta is within run-to-run noise and is
  recorded as measured, not as a claim of constant time.
- Key reuse: 100/100 roundtrips with 100/100 distinct ciphertexts;
  wrong-key decapsulation does not recover the secret; replay
  decapsulation is deterministic (section E).

## 3. Classical baseline

Source: `outputs/benchmark-classical.log` (`openssl speed`,
OpenSSL 3.0.13) and `outputs/hybrid_bench.log` section A
(OpenSSL EVP, measured directly in the harness).

| Primitive | rate | µs/op |
|---|---:|---:|
| X25519 ECDH (`openssl speed`) | 18,272 ops/s | 54.7 |
| X25519 derive (EVP, harness) | — | 65.32 |
| X25519 keygen (EVP, harness) | — | 80.31 |
| P-256 ECDH (`openssl speed`) | 14,154.5 ops/s | 70.7 |
| Ed25519 sign (`openssl speed`) | 18,383.5 ops/s | 54.4 |
| Ed25519 verify (`openssl speed`) | 7,163 ops/s | 139.6 |

The EVP figures include OpenSSL object allocation overhead
(keygen 80.31 µs, derive 65.32 µs vs 54.7 µs for the raw
primitive). A production implementation should use the raw
curve APIs on hot paths (finding R-08).

## 4. Hybrid handshake cost

Source: `outputs/hybrid_bench.log` (harness `harness/bench_hybrid.c`,
n=200; combiner `ss = SHA-256(x25519_ss || mlkem_ss)`).

| Combination | client µs | server µs | total µs | wire B | overhead vs X25519-only |
|---|---:|---:|---:|---:|---:|---:|
| X25519 + ML-KEM-512 | 80.99 | 91.00 | 171.99 | 803 | +41.35 µs |
| X25519 + ML-KEM-768 | 84.72 | 90.27 | 174.99 | 1,123 | +44.35 µs |
| X25519 + ML-KEM-1024 | 93.12 | 103.98 | 197.10 | 1,603 | +66.46 µs |

X25519-only reference: 2 × 65.32 µs derive = 130.64 µs.
The hybrid overhead is under 70 µs for every combination —
negligible against a peer round-trip of milliseconds. The
binding constraint is wire size, not CPU (see
`docs/CERT_HANDSHAKE.md`).

Controls (all PASS, `outputs/hybrid_bench.log` section C):

- C-1: all-zero X25519 peer key is rejected by OpenSSL EVP
  (rc=-1, low-order point). The hybrid cannot complete with a
  zero X25519 part.
- C-2: a tampered ML-KEM ciphertext decapsulates to a different
  shared secret (implicit rejection); the hybrid secret differs
  from the reference.
- C-3: a tampered X25519 shared secret changes the hybrid secret.

## 5. What to choose

- ML-KEM-768 is the recommended default: NIST category 3,
  174.99 µs total handshake cost, 1,123 bytes of wire.
- ML-KEM-512 for bandwidth-constrained peers (803 bytes,
  171.99 µs). ML-KEM-1024 only where category 5 is required
  (1,603 bytes, 197.10 µs).
- The combiner is a model combiner, not X-Wing and not
  RFC 10024. See `docs/HYBRID_KEM.md` for the design and the
  standards-track alternatives.

# Post-quantum TLS migration readiness assessment for postfiatd

Assesses migrating postfiatd's TLS and peer transport to hybrid
post-quantum key exchange (X25519 + ML-KEM), measured against
liboqs 0.14.0 and the pinned postfiatd source tree.

- Pinned postfiatd commit: `0085a1ff885d6a446369cf73a4430f75af22be55`
  (2026-10-10, version 1.0.9). All source citations are verified
  against this checkout with `grep -n`; excerpts are vendored in
  `data/source_excerpts.json`.
- liboqs 0.14.0, commit `94b421ebb82405c843dba4e9aa521a56ee5a333d`.
  All measurements are single-threaded on the machine in
  `outputs/environment.txt`.

## Headline results

Measured (single thread, fresh run, `outputs/benchmark-kem.log`):

| KEM | keygen µs | encaps µs | decaps µs | pk B | ct B |
|---|---:|---:|---:|---:|---:|
| ML-KEM-512 | 13.36 | 12.87 | 16.75 | 800 | 768 |
| ML-KEM-768 | 20.03 | 24.45 | 28.30 | 1,184 | 1,088 |
| ML-KEM-1024 | 27.07 | 25.24 | 32.65 | 1,568 | 1,568 |

Implicit rejection: 108/108 invalid ciphertexts rejected to a
pseudorandom secret. Valid vs invalid decaps (ML-KEM-768):
26.219 vs 25.300 µs (-3.5%).

Hybrid handshake (X25519 + ML-KEM, `outputs/hybrid_bench.log`):

| Hybrid | client µs | server µs | total µs | wire B |
|---|---:|---:|---:|---:|
| X25519 + ML-KEM-512 | 80.99 | 91.00 | 171.99 | 803 |
| X25519 + ML-KEM-768 | 84.72 | 90.27 | 174.99 | 1,123 |
| X25519 + ML-KEM-1024 | 93.12 | 103.98 | 197.10 | 1,603 |

X25519-only reference: 130.64 µs (2 × derive). Hybrid overhead:
+41.35 / +44.35 / +66.46 µs. Controls C-1..C-3 all PASS.

## Headline inventory findings

- Peer connections **are** TLS-encrypted (Beast `ssl_stream`),
  but the TLS is **anonymous**: `verify_none` on both ends, an
  ephemeral self-signed RSA-2048 certificate regenerated at every
  server start. Peer authentication comes from the manifest /
  signature layer above TLS, not from TLS.
- RPC/WebSocket secure ports use the same anonymous context unless
  the operator supplies certificate files (`make_SSLContextAuthed`).
- The outbound HTTPS client (validator sites, exclusion lists) is
  the only verifying TLS client in the tree: TLS 1.2, pre/post
  connect verification.
- No TLS version floor/ceiling is set anywhere: only SSLv2/SSLv3
  and TLS 1.0/1.1 are disabled, so TLS 1.2 and TLS 1.3 are both
  negotiable. The default cipher list (`TLSv1.2:!CBC:!DSS:!PSK:
  !eNULL:!aNULL`) does not govern TLS 1.3 ciphersuites.
- No ML-KEM support exists in the TLS stack (OpenSSL 3.0.13 /
  Boost.Asio). Post-quantum TLS needs a provider (open decision
  D-02). The recommended first step is the application-layer
  hybrid KEM in the peer handshake (stage S1), not the TLS stack.

## Layout

- `harness/` — measurement harnesses (`bench_kem.c`,
  `bench_hybrid.c`) and the run scripts.
- `scripts/` — inventory, model, and structure checks.
- `data/` — parameter tables, vendored source excerpts, inventory
  results, hybrid and migration models.
- `docs/` — comparison, inventory, hybrid design, certificate /
  handshake analysis, migration plan, remediation, claim index,
  sources, reproduction, failure modes, decision memo.
- `outputs/` — unedited measurement logs and deterministic model logs.

## Reproduce

```sh
bash reproduce.sh   # exit 0, REPRODUCE OK
bash verify_digests.sh
```

See `docs/REPRODUCTION.md`. The measurement logs are re-run into a
scratch directory on every reproduce and structurally checked; the
vendored logs in `outputs/` are never overwritten.

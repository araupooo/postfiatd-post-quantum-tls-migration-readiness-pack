# Migration plan

Five stages, S0–S4. Durations are [ESTIMATE] (planning figures
assuming one maintainer and the existing release cadence). The
gates are the binding part: a stage is complete only when its
gate check passes. Model data: `data/migration_plan.json`;
checks: `scripts/migration_model.py`.

## S0 — Pin the TLS policy and finish the inventory (1–2 weeks)

- Document the current TLS surface (peer TLS, RPC/WebSocket
  TLS, outbound HTTPS client) from `data/tls_inventory.json`.
- Record the explicit version policy: TLS 1.0/1.1 already
  disabled; TLS 1.2 floor; TLS 1.3 negotiable where OpenSSL
  offers it.
- No code change in this stage.
- **Gate:** a written TLS policy exists and
  `scripts/tls_inventory.py` exits 0 (27/27 checks PASS).

## S1 — Application-layer hybrid KEM in the peer handshake (2–4 weeks)

- Implement the H-1 wire format (`docs/HYBRID_KEM.md`, every
  byte fixed) in the peer handshake behind a feature flag.
- Distribute peer ML-KEM public keys via the channel chosen in
  open decision D-01.
- Ship peers that speak both classical-only and hybrid
  handshakes; hybrid is negotiated, never forced.
- **Gate:** the H-1 format is implemented and
  `harness/bench_hybrid.c` controls C-1..C-3 pass.

## S2 — Peers require the hybrid half (4–8 weeks)

- Require the ML-KEM half for handshakes at or above the
  cutover version.
- Policy flag: before the cutover version, classical-only is
  accepted with a warning; at/after it, classical-only is
  rejected.
- Publish the cutover version and date in the release notes.
- **Gate:** all supported peers accept hybrid handshakes and
  reject a hybrid envelope with a tampered or missing part.

## S3 — TLS-stack migration: OpenSSL provider, RPC/WebSocket (8–16 weeks)

- Load the ML-KEM provider (open decision D-02) into the TLS
  stack used by `make_SSLContext` / `make_SSLContextAuthed`.
- Negotiate hybrid X25519+ML-KEM key exchange on secure
  RPC/WebSocket ports.
- Decide the authed-certificate question (open decision D-03);
  keep RSA certificates unless ML-DSA certificates are chosen.
- **Gate:** a test TLS handshake completes with an ML-KEM key
  exchange and the handshake is captured in a log.

## S4 — Review and re-evaluate (ongoing)

- Re-run the full pack (`bash reproduce.sh`) against the
  current release.
- Retire classical-only peer handshakes for new releases when
  the fleet allows it.
- Re-evaluate the provider and certificate decisions (D-02,
  D-03) yearly.
- **Gate:** repeat of the S2 and S3 gate checks on the current
  release.

Planning horizon S0–S3: **15–30 weeks**.

## Backwards compatibility

| Peer A | Peer B | Result |
|---|---|---|
| classical-only | classical-only | works (pre-S1) |
| hybrid (S1) | classical-only | works, classical handshake, warning logged |
| hybrid (S1) | hybrid (S1) | works, hybrid handshake negotiated |
| hybrid, ≥ cutover (S2) | classical-only | rejected — no shared handshake |
| hybrid, ≥ cutover (S2) | hybrid, ≥ cutover (S2) | works, hybrid handshake |

There is no wire-format version that silently falls back: the
H-1 message carries an explicit version byte (`0x01`) and
kem_id, so a peer that does not understand the message rejects
it rather than mis-parsing it.

## Open design decisions

- **D-01:** Which channel distributes the peer ML-KEM public
  key (validator manifest, the peer handshake itself, or a new
  peer-info gossip message). The pack does not choose; the H-1
  wire format is unaffected.
- **D-02:** Which OpenSSL provider supplies ML-KEM to the TLS
  stack in stage S3 (oqs-provider vs a future OpenSSL-native
  implementation). The pack does not choose; stage S3 is gated
  on a provider being available and audited.
- **D-03:** Whether authed RPC ports migrate to ML-DSA
  certificates (stage S3) or keep RSA certificates while only
  the key exchange goes post-quantum. The pack recommends
  keeping RSA certificates in S3 and treating ML-DSA
  certificates as a separate later decision.

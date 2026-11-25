# Decision memo — post-quantum TLS migration readiness

## Recommendation

**Adopt the staged plan in `docs/MIGRATION_PLAN.md`, starting
with stage S1 (application-layer hybrid KEM in the peer
handshake) using ML-KEM-768.** Do not start with the TLS stack.

## Why S1 first

1. The inventory proves peer TLS is anonymous: `verify_none`
   on both ends, an ephemeral self-signed certificate. Peer
   identity lives in the manifest layer above TLS. Moving the
   key exchange into the peer handshake therefore changes the
   confidentiality layer without touching TLS at all, and it
   works with the stack as it is today.
2. The cost is small and measured: 174.99 µs total handshake
   time for X25519 + ML-KEM-768, +44.35 µs over X25519-only,
   1,123 bytes of wire. The binding constraint is key
   distribution (1,184 bytes per peer public key), not CPU.
3. The TLS stack cannot be migrated yet: OpenSSL 3.0.13 as used
   here has no ML-KEM support, and no provider has been chosen
   or audited (open decision D-02). Stage S3 is 8–16 weeks of
   work gated on that choice; S1 delivers the
   harvest-now-decrypt-later protection now.

## What this pack proves

- ML-KEM-512/768/1024 rates, sizes, and implicit rejection are
  re-measured (108/108 invalid ciphertexts rejected; key reuse
  100/100; wrong-key decaps does not recover the secret).
- The H-1 hybrid wire format fixes every byte (3-byte header +
  32-byte X25519 public key + ciphertext), so there is no
  unspecified byte to argue about later.
- The TLS surface is inventoried end to end (27/27 checks):
  peer TLS, RPC/WebSocket TLS, and the outbound HTTPS client,
  with exact file:line evidence.
- The migration is staged with gates, a backwards-compatibility
  matrix, and three labelled open design decisions (D-01 key
  distribution, D-02 provider, D-03 authed certificates).

## Risks and honest limits

- The combiner is a model combiner (`SHA-256(x25519_ss ||
  mlkem_ss)`), not X-Wing and not RFC 10024. If the migration
  must match a standard, switch to H-2 (X-Wing) before shipping.
- The -3.5% valid/invalid decaps timing delta is within
  run-to-run noise at n=1000; it is recorded as measured, not
  as a constant-time claim.
- Stage durations (15–30 weeks for S0–S3) are planning
  estimates, not measurements.
- No live deployment was observed: the TLS version actually
  negotiated by deployed peers and whether any deployment uses
  authed RPC certificates are both [UNSUPPORTED] (U-04, U-05).
- The peer certificate needs no migration, but the RPC
  certificate question (D-03) is deliberately left open.

## Next step

Approve stage S0 (write the TLS policy, 1–2 weeks) and the
D-01 decision (which channel distributes the peer ML-KEM public
key), then implement stage S1 behind a feature flag.

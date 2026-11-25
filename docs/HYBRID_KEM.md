# Hybrid KEM design and threat model

## H-1 — recommended: X25519 + ML-KEM, concatenated combiner

The client sends one handshake message; the server derives the
same 32-byte hybrid shared secret. Verification accepts only
when **both** halves complete (AND policy): a classical-only or
ML-KEM-only secret is never accepted in a hybrid handshake.

### Wire format (every byte fixed — no unspecified bytes)

| Bytes | Field | Value |
|---|---|---|
| 0 | version | `0x01` (fixed) |
| 1 | kem_id | `0x01` = ML-KEM-512, `0x02` = ML-KEM-768, `0x03` = ML-KEM-1024 (fixed) |
| 2 | mode | `0x00` = X25519+ML-KEM concatenated combiner (fixed) |
| 3–34 | X25519 ephemeral public key | 32 bytes, client ephemeral |
| 35.. | ML-KEM ciphertext | 768 / 1,088 / 1,568 bytes, length fixed by kem_id |

Total message length: 35 + ciphertext bytes = **803 / 1,123 /
1,603 bytes**. The server ML-KEM public key (800 / 1,184 /
1,568 bytes) is **not** part of this message; it is distributed
out of band with the peer identity material (open decision D-01:
which channel).

### Combiner

```
ss = SHA-256(x25519_ss || mlkem_ss)
```

Both halves are 32 bytes; the output is a 32-byte hybrid shared
secret. This is a **model combiner**, not X-Wing and not
RFC 10024. It is measured in `harness/bench_hybrid.c` (controls
C-1..C-3, all PASS).

### Security properties

- **Harvest-now-decrypt-later resistance:** an adversary that
  records the handshake must break ML-KEM to recover the shared
  secret, even if X25519 falls.
- **Classical fallback:** an adversary that breaks ML-KEM must
  still break X25519. Either half alone is insufficient.
- **Implicit rejection:** a tampered ML-KEM ciphertext yields a
  pseudorandom secret (108/108 verified, control C-2); the
  handshake fails at the first authenticated message, and the
  failure is indistinguishable from a wrong-key failure.
- **Low-order point:** an all-zero X25519 peer key is rejected by
  OpenSSL EVP (control C-1).

## Alternatives considered

- **H-2 X-Wing** (draft-connolly-cfrg-xwing-kem-11): the
  standards-track combiner, SHA3-256 over a structured input
  with domain labels. Stronger domain separation than H-1, more
  code to audit. Recommended if the migration is standardised
  rather than shipped as a local change.
- **H-3 pure ML-KEM:** no classical fallback. Rejected for the
  migration step: a flaw in ML-KEM would leave the fleet with no
  working key exchange, and the hybrid costs under 70 µs extra.
- **H-4 RFC 10024-style hybrid:** the IETF hybrid KEM
  construction. Not measured here; adopt only if the deployment
  must match an IETF profile.

## Threat model

- **Adversary:** passive recorder (harvest now, decrypt later)
  and active man-in-the-middle on the peer port.
- **Assumptions:** peer identity is established by the manifest /
  signature layer above TLS (the inventory shows peer TLS is
  anonymous — finding R-01). The hybrid KEM protects the
  confidentiality of the peer session, not peer identity.
- **Out of scope:** signature migration (ML-DSA for manifests and
  release signing), certificate migration (open decision D-03),
  and the TLS-stack provider choice (open decision D-02).
- **Downgrade:** during the transition (stage S2) a classical-only
  handshake is accepted with a warning before the cutover
  version and rejected at/after it. A downgrade attacker can only
  force classical key exchange before the cutover; after the
  cutover there is no classical-only path to downgrade to.
  The cutover version and date must be published in the release
  notes (stage S2 gate).

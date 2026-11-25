# Certificate and handshake size analysis

## Certificates

The peer TLS certificate is an ephemeral, self-signed RSA-2048
certificate regenerated at every server start
(`make_SSLContext.cpp:66,172,233-234`). Consequences:

- There is **no long-term peer certificate to migrate**. The
  certificate is created fresh on every start, so a post-quantum
  certificate is not needed for the peer port at all.
- Certificate size is not a migration cost for peers: the RSA-2048
  certificate (~700–900 bytes, DER) is replaced by nothing — the
  peer port keeps its ephemeral RSA certificate while the key
  exchange moves to the hybrid KEM above TLS (stage S1).
- RPC/WebSocket ports with operator-supplied certificate files
  (`make_SSLContextAuthed`) are the only place a certificate
  migration could bite. ML-DSA certificates are not supported by
  the pinned OpenSSL 3.0.13 stack, so the plan keeps RSA
  certificates in stage S3 and treats ML-DSA certificates as a
  separate later decision (open decision D-03).

For reference, an ML-DSA-44 public key is 1,312 bytes and a
signature 2,420 bytes; an ML-DSA-65 public key is 1,952 bytes
and a signature 3,309 bytes (FIPS 204). A certificate carrying
one would be roughly 2–4× the size of the current RSA-2048
certificate. These figures are specification sizes, not measured
here.

## Handshake size

### Peer handshake (H-1 hybrid KEM, measured design)

| Combination | client→server B | server ML-KEM public key (out of band) B |
|---|---:|---:|
| X25519 + ML-KEM-512 | 803 | 800 |
| X25519 + ML-KEM-768 | 1,123 | 1,184 |
| X25519 + ML-KEM-1024 | 1,603 | 1,568 |

The client→server message is one packet on any normal MTU.
The server public key is the larger distribution cost: it must
reach every peer that wants to connect (open decision D-01).
At 25 validators the total distribution is 25 × 1,184 bytes ≈
29.6 KB for ML-KEM-768 — trivial against the manifest traffic
already exchanged.

### TLS handshake (stage S3, simulated)

A TLS 1.3 handshake with an ML-KEM key exchange adds the KEM
public key and ciphertext to the ClientHello/ServerHello
exchange: roughly the same 803 / 1,123 / 1,603 bytes as the
peer handshake, plus the TLS record overhead (tens of bytes).
This is a [SIMULATED] figure derived from the measured H-1
wire sizes; no TLS 1.3 ML-KEM handshake was performed here
because the pinned stack has no ML-KEM provider.

### CPU cost (measured)

Hybrid handshake totals: 171.99 / 174.99 / 197.10 µs
(ML-KEM-512 / 768 / 1024). Overhead vs X25519-only:
+41.35 / +44.35 / +66.46 µs. Against a peer round-trip measured
in milliseconds, the CPU cost is not the binding constraint;
wire size and key distribution are.

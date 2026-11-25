# Remediation — findings and recommended actions

Severity is judged by exploitability against the pinned tree.
Findings are also listed in `docs/CLAIMS.md` (measured claims
only); the findings themselves live here.

## R-01 — HIGH: peer TLS is anonymous; peer identity is not established by TLS

- Evidence: `ConnectAttempt.cpp:175-177`
  (`set_verify_mode(verify_none)` on the outgoing handshake);
  `make_SSLContext.cpp:391` (`set_verify_mode(verify_none)` in
  the shared context). Peer authentication comes from the
  manifest / signature layer above TLS.
- Impact: a man-in-the-middle can terminate the TLS session.
  Impersonation is stopped only by the signature layer, not by
  TLS. Any defect in that layer is directly reachable from the
  network.
- Fix: do not rely on TLS for peer identity. Stage S1 (hybrid
  KEM in the peer handshake) protects session confidentiality;
  peer identity must stay in the manifest layer and be reviewed
  as the trust anchor.

## R-02 — HIGH: ephemeral self-signed RSA-2048 peer certificate, no pinning

- Evidence: `make_SSLContext.cpp:66,172,233` — a 2048-bit RSA
  self-signed certificate, regenerated at every server start,
  valid 2 years.
- Impact: the certificate carries no identity and is never
  verified, so it adds nothing beyond the key exchange. It is
  not a vulnerability by itself, but any code path that ever
  starts trusting it would be trusting a fresh self-signed key.
- Fix: keep the certificate ephemeral and anonymous; never add
  verification of peer certificates without a pinning or PKI
  design. The certificate needs no migration (see
  `docs/CERT_HANDSHAKE.md`).

## R-03 — MEDIUM: no TLS version floor/ceiling; cipher list does not cover TLS 1.3

- Evidence: `make_SSLContext.cpp:350-357` disables only SSLv2,
  SSLv3, TLS 1.0 and TLS 1.1. No min/max version is set anywhere
  (negative search N-02). The default cipher list
  (`TLSv1.2:!CBC:!DSS:!PSK:!eNULL:!aNULL`, :104) does not govern
  TLS 1.3 ciphersuites.
- Impact: TLS 1.3 negotiates with OpenSSL's default
  ciphersuites, which the operator never reviewed. A future
  OpenSSL default change silently changes the negotiated policy.
- Fix: set an explicit TLS version floor and, for TLS 1.3, an
  explicit ciphersuite list; record both in the written TLS
  policy (stage S0).

## R-04 — MEDIUM: operator `ssl_ciphers` does not apply to the peer port

- Evidence: `OverlayImpl.cpp:1550` — the peer listener always
  uses `make_SSLContext("")`; `ServerHandler.cpp:1090,1092`
  applies `p.ssl_ciphers` only to the RPC/WebSocket contexts.
- Impact: an operator who hardens `ssl_ciphers` gets no
  hardening on the peer port.
- Fix: pass the configured cipher list to the peer listener
  context, or document that the peer port intentionally uses the
  default list (stage S0).

## R-05 — MEDIUM: outbound HTTPS client pins TLS 1.2

- Evidence: `WorkSSL.cpp:41` — `tlsv12_client` context for the
  validator-site and exclusion-list fetches.
- Impact: the client cannot negotiate TLS 1.3, and any server
  that drops TLS 1.2 breaks the fetches. The client is the only
  verifying TLS client in the tree, so its version policy is the
  one that matters for validator data.
- Fix: allow TLS 1.3 in the outbound client when the OpenSSL
  build supports it (stage S3).

## R-06 — MEDIUM: no ML-KEM support in the TLS stack

- Evidence: negative search N-03 — no ML-KEM, ML-DSA, or hybrid
  key exchange anywhere in the tree; OpenSSL 3.0.13 as used here
  has no ML-KEM support.
- Impact: post-quantum TLS cannot be switched on; it needs a
  provider (open decision D-02) and the stage S3 work.
- Fix: follow the staged plan. Do not attempt a TLS-stack
  migration before stage S1 is live: the application-layer
  hybrid KEM delivers the harvest-now-decrypt-later protection
  without waiting on the provider.

## R-07 — LOW: ephemeral certificate valid 2 years

- Evidence: `make_SSLContext.cpp:172` (validity 2 years), :233
  (regenerated at every start).
- Impact: none in practice — the certificate is discarded at
  shutdown. The 2-year validity is only a number in the
  generated certificate.
- Fix: none required. If the generation code is ever reused for
  a long-lived certificate, shorten the validity then.

## R-08 — LOW: X25519 EVP keygen/derive overhead on hot paths

- Evidence (measured): X25519 keygen 80.31 µs and derive
  65.32 µs via OpenSSL EVP vs 54.7 µs for the raw primitive
  (`openssl speed`). The difference is object allocation.
- Impact: at most tens of microseconds per handshake — not the
  binding cost, but it is the largest single avoidable cost in
  the hybrid handshake.
- Fix: use the raw curve APIs on hot paths when the hybrid KEM
  is implemented (stage S1).

## R-09 — LOW: ML-KEM-1024 key distribution size

- Evidence (measured): ML-KEM-1024 public key 1,568 bytes,
  ciphertext 1,568 bytes; hybrid wire 1,603 bytes.
- Impact: at 25 validators the distribution is 25 × 1,568 bytes
  ≈ 39.2 KB — small, but it is the largest of the three parameter
  sets and the one that stresses gossip the most.
- Fix: default to ML-KEM-768 (1,184-byte public key) unless
  category 5 is required (see `docs/KEM_COMPARISON.md`).

## R-10 — INFO: server-side TLS handshake call site is outside the pinned tree

- Evidence: negative search N-01 — no `stream_base::server`
  `async_handshake` call in the non-test tree (the only hit in
  the whole tree is `src/test/jtx/TrustedPublisherServer.h:560`). The incoming
  handshake is performed inside the Beast server Session.
- Impact: the server-side handshake behaviour (version, cipher
  selection, error handling) is inherited from the Beast/Boost
  version, not from postfiatd code, and must be audited at that
  layer.
- Fix: none in this tree. Record the Beast version in the TLS
  policy (stage S0).

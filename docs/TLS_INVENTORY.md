# TLS / transport inventory of the pinned postfiatd tree

Inventory script: `scripts/tls_inventory.py` (27 checks I-01..I-27
plus 3 negative searches; 27/27 PASS). Results in
`data/tls_inventory.json`; every cited line is vendored in
`data/source_excerpts.json` and verified against the pinned
checkout (`0085a1ff885d6a446369cf73a4430f75af22be55`) with
`--pin`. Summary below; the full check list with file:line is in
the JSON file.

Note on paths: the pinned tree uses the modern rippled layout —
`src/xrpld/...` and `src/libxrpl/...` — not the older
`src/ripple/...` layout.

## Where TLS is used

### Peer overlay — TLS encrypted, anonymous

- Peers connect over TLS. `src/xrpld/overlay/README.md:33-34`:
  "a peer makes an outgoing TLS encrypted connection to a remote
  peer".
- Outgoing handshake:
  `src/xrpld/overlay/detail/ConnectAttempt.cpp:175-177` —
  `set_verify_mode(verify_none)` then
  `async_handshake(ssl::stream_base::client, ...)`. The stream type
  is `boost::beast::ssl_stream<middle_type>`
  (`ConnectAttempt.h:44`, `Overlay.h:52`).
- Peer listener context: `src/xrpld/overlay/detail/OverlayImpl.cpp:1550`
  — `setup.context = make_SSLContext("")`.
- Incoming peers are handed off by
  `src/xrpld/rpc/detail/ServerHandler.cpp:245-247`
  (`onHandoff` routes "peer" protocol ports to
  `app_.overlay().onHandoff`); `PeerImp::doAccept` derives the
  shared value from the TLS stream (`PeerImp.cpp:798`).
- No `stream_base::server` `async_handshake` call exists in the
  non-test tree (negative search N-01; the only hit in the whole
  tree is in `src/test/jtx/TrustedPublisherServer.h:560`): the
  incoming TLS handshake is performed inside the Beast server
  Session implementation, not in postfiatd code (finding R-10).

### The TLS context — anonymous, ephemeral, self-signed

`src/libxrpl/basics/make_SSLContext.cpp`:

- Default cipher list (:104): `TLSv1.2:!CBC:!DSS:!PSK:!eNULL:!aNULL`.
- Ephemeral 2048-bit RSA self-signed certificate, regenerated at
  every server start, valid 2 years (:66, :172, :233;
  `X509_sign` with `EVP_sha256`).
- `set_verify_mode(verify_none)` (:391) — the peer side never
  verifies a peer certificate.
- Context is `sslv23` with `no_sslv2`, `no_sslv3`, `no_tlsv1`,
  `no_tlsv1_1` (:350-357). No TLS 1.2/1.3 min/max version is set
  anywhere in the tree (negative search N-02): TLS 1.2 and TLS 1.3
  are both negotiable where OpenSSL offers them, and the default
  cipher list does not govern TLS 1.3 ciphersuites (finding R-03).

### RPC / WebSocket secure ports — anonymous unless configured

- `ServerHandler.cpp:1090,1092` (`makeContexts`): `make_SSLContext(
  p.ssl_ciphers)` when no certificate files are configured,
  `make_SSLContextAuthed(...)` (defined in
  `make_SSLContext.cpp:396`) when key/cert/chain files are given.
- The peer listener always uses the default cipher list
  (`make_SSLContext("")`); an operator `ssl_ciphers` setting does
  not apply to the peer port (finding R-04).

### Outbound HTTPS client — the only verifying TLS client

- `src/xrpld/app/misc/detail/WorkSSL.cpp:41` — `tlsv12_client` context;
  :44 `preConnectVerify`, :53 `postConnectVerify`, :57 client
  `async_handshake`. Used by `ValidatorSite.cpp:270` (validator
  sites) and `RemoteExclusionListFetcher.cpp:196` (exclusion lists).
- `HTTPClient.cpp:297` — client `async_handshake`.
- `RegisterSSLCerts.cpp:49` — `CertOpenSystemStore(0, "ROOT")`,
  Windows-only system store.
- This client pins TLS 1.2 (finding R-05).

## Where TLS is NOT used

- The manifest / validator-list layer authenticates peers by
  signature above TLS; TLS itself carries no peer identity.
- No ML-KEM, no ML-DSA, no hybrid key exchange exists anywhere
  in the tree (negative search N-03). OpenSSL 3.0.13 as used
  here has no ML-KEM support; a provider is required (finding
  R-06, open decision D-02).
- The negative UNL / validator-list machinery is not TLS.

## Consequence for the migration

Because peer TLS is anonymous and peer identity lives above TLS,
the first migration step (stage S1) can be an application-layer
hybrid KEM inside the peer handshake — it does not need the TLS
stack to change. The TLS-stack migration (stage S3) is a separate,
later step that touches only the RPC/WebSocket ports and the
outbound client.

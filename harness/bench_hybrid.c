/*
 * bench_hybrid.c — hybrid X25519 + ML-KEM handshake-cost harness.
 *
 * Sections:
 *   A  X25519 classical baseline (keygen + derive, OpenSSL EVP)
 *   B  Hybrid handshake cost per ML-KEM parameter set:
 *        client: X25519 derive + ML-KEM encaps, combiner
 *                ss = SHA-256(x25519_ss || mlkem_ss)
 *        server: X25519 derive + ML-KEM decaps, same combiner
 *   C  Controls: all-zero X25519 peer key (hybrid completes, secret
 *      differs); tampered ML-KEM ciphertext (implicit rejection,
 *      secret differs); tampered X25519 shared secret (secret differs)
 *
 * The combiner is a model: SHA-256 over the concatenation of the two
 * shared secrets. It is NOT X-Wing (draft-connolly-cfrg-xwing-kem-11)
 * and NOT the RFC 10024 hybrid; those are discussed in the docs with
 * their own measured results. This harness measures the cost of the
 * hybrid operations, not a standardised construction.
 *
 * Build: cc -O2 -Wall -I<liboqs>/include bench_hybrid.c
 *        -L<liboqs>/build/lib -loqs -lcrypto -lm -o bench_hybrid
 * Usage: ./bench_hybrid [n]   (default 200 iterations per operation)
 * Secrets are printed only as SHA-256 digests, never raw.
 */
#include <assert.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double
now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void
hx(const uint8_t* p, size_t n, char* out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++)
    {
        out[2 * i] = d[p[i] >> 4];
        out[2 * i + 1] = d[p[i] & 15];
    }
    out[2 * n] = 0;
}

static void
sha256_hex(const uint8_t* p, size_t n, char* out)
{
    uint8_t d[32];
    SHA256(p, n, d);
    hx(d, 32, out);
}

static int fails = 0;

static void
ok(int c, char const* what)
{
    printf("  [%s] %s\n", c ? "PASS" : "FAIL", what);
    if (!c)
    {
        fails++;
        printf("RESULT failure: %s\n", what);
    }
}

static void
step(char const* s)
{
    printf("[step] %s\n", s);
}

/* X25519 keypair via EVP; returns 0 on success. */
static int
x25519_keypair(uint8_t pub[32], EVP_PKEY** priv_out)
{
    EVP_PKEY* pkey = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    if (!pkey)
        return -1;
    size_t len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &len) != 1)
    {
        EVP_PKEY_free(pkey);
        return -1;
    }
    *priv_out = pkey;
    return 0;
}

static int
x25519_derive(EVP_PKEY* priv, uint8_t const peer_pub[32], uint8_t ss[32])
{
    EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, 32);
    if (!peer)
        return -1;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx)
    {
        EVP_PKEY_free(peer);
        return -1;
    }
    size_t len = 32;
    int rc = EVP_PKEY_derive_init(ctx) == 1 &&
        EVP_PKEY_derive_set_peer(ctx, peer) == 1 &&
        EVP_PKEY_derive(ctx, ss, &len) == 1;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    return rc ? 0 : -1;
}

static double
bench_x25519_keygen(int n)
{
    double t0 = now_s();
    for (int i = 0; i < n; i++)
    {
        EVP_PKEY* p = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
        EVP_PKEY_free(p);
    }
    return (now_s() - t0) / n * 1e6;
}

static double
bench_x25519_derive(int n)
{
    uint8_t pub_a[32], pub_b[32];
    EVP_PKEY *priv_a = NULL, *priv_b = NULL;
    assert(x25519_keypair(pub_a, &priv_a) == 0);
    assert(x25519_keypair(pub_b, &priv_b) == 0);
    uint8_t ss[32];
    double t0 = now_s();
    for (int i = 0; i < n; i++)
        assert(x25519_derive(priv_a, pub_b, ss) == 0);
    double us = (now_s() - t0) / n * 1e6;
    EVP_PKEY_free(priv_a);
    EVP_PKEY_free(priv_b);
    return us;
}

typedef struct
{
    char const* name;
    size_t pk, ct;
} KEMDEF;

int
main(int argc, char** argv)
{
    int n = argc > 1 ? atoi(argv[1]) : 200;
    printf("bench_hybrid: liboqs %s n=%d\n", OQS_VERSION_TEXT, n);
    printf("environment: single thread, CLOCK_MONOTONIC, OpenSSL EVP X25519\n");

    printf("== A. X25519 classical baseline ==\n");
    step("X25519 keygen");
    double x_keygen = bench_x25519_keygen(n);
    printf("  X25519: keygen %.2f us\n", x_keygen);
    printf("RESULT X25519 keygen_us=%.2f n=%d\n", x_keygen, n);
    step("X25519 derive");
    double x_derive = bench_x25519_derive(n);
    printf("  X25519: derive %.2f us\n", x_derive);
    printf("RESULT X25519 derive_us=%.2f n=%d\n", x_derive, n);
    step("X25519 roundtrip agreement");
    {
        uint8_t pub_a[32], pub_b[32], ss_ab[32], ss_ba[32];
        EVP_PKEY *priv_a = NULL, *priv_b = NULL;
        assert(x25519_keypair(pub_a, &priv_a) == 0);
        assert(x25519_keypair(pub_b, &priv_b) == 0);
        assert(x25519_derive(priv_a, pub_b, ss_ab) == 0);
        assert(x25519_derive(priv_b, pub_a, ss_ba) == 0);
        char ha[65], hb[65];
        sha256_hex(ss_ab, 32, ha);
        sha256_hex(ss_ba, 32, hb);
        printf("  A->B ss_sha256=%s\n  B->A ss_sha256=%s\n", ha, hb);
        ok(memcmp(ss_ab, ss_ba, 32) == 0, "X25519 both directions agree");
        EVP_PKEY_free(priv_a);
        EVP_PKEY_free(priv_b);
    }

    printf("== B. hybrid handshake cost (X25519 + ML-KEM) ==\n");
    KEMDEF defs[3] = {{"ML-KEM-512", 800, 768},
                      {"ML-KEM-768", 1184, 1088},
                      {"ML-KEM-1024", 1568, 1568}};
    for (int d = 0; d < 3; d++)
    {
        OQS_KEM* kem = OQS_KEM_new(defs[d].name);
        assert(kem);
        printf("[step] %s hybrid\n", defs[d].name);
        /* server (responder) long-term ML-KEM keypair + X25519 keypair */
        uint8_t pk[1568], sk[3168];
        OQS_KEM_keypair(kem, pk, sk);
        uint8_t srv_pub[32];
        EVP_PKEY* srv_priv = NULL;
        assert(x25519_keypair(srv_pub, &srv_priv) == 0);
        /* client (initiator) ephemeral X25519 keypair */
        uint8_t cli_pub[32];
        EVP_PKEY* cli_priv = NULL;
        assert(x25519_keypair(cli_pub, &cli_priv) == 0);
        /* client side: X25519 derive + ML-KEM encaps + combiner */
        uint8_t ct[1568], ss_kem[32], ss_x[32], combo[64], ss_h[32];
        double t0 = now_s();
        for (int i = 0; i < n; i++)
        {
            assert(x25519_derive(cli_priv, srv_pub, ss_x) == 0);
            assert(OQS_KEM_encaps(kem, ct, ss_kem, pk) == OQS_SUCCESS);
            memcpy(combo, ss_x, 32);
            memcpy(combo + 32, ss_kem, 32);
            SHA256(combo, 64, ss_h);
        }
        double client_us = (now_s() - t0) / n * 1e6;
        /* server side: X25519 derive + ML-KEM decaps + combiner */
        uint8_t ss_kem2[32], ss_x2[32], ss_h2[32];
        t0 = now_s();
        for (int i = 0; i < n; i++)
        {
            assert(x25519_derive(srv_priv, cli_pub, ss_x2) == 0);
            assert(OQS_KEM_decaps(kem, ss_kem2, ct, sk) == OQS_SUCCESS);
            memcpy(combo, ss_x2, 32);
            memcpy(combo + 32, ss_kem2, 32);
            SHA256(combo, 64, ss_h2);
        }
        double server_us = (now_s() - t0) / n * 1e6;
        char h1[65], h2[65];
        sha256_hex(ss_h, 32, h1);
        sha256_hex(ss_h2, 32, h2);
        printf("  %s hybrid: client %.2f us, server %.2f us, "
               "handshake_total %.2f us\n",
               defs[d].name,
               client_us,
               server_us,
               client_us + server_us);
        printf("  client ss_sha256=%s server ss_sha256=%s\n", h1, h2);
        printf("RESULT %s hybrid client_us=%.2f server_us=%.2f "
               "total_us=%.2f n=%d\n",
               defs[d].name,
               client_us,
               server_us,
               client_us + server_us,
               n);
        ok(memcmp(ss_h, ss_h2, 32) == 0,
           "hybrid client/server shared secrets agree");
        /* wire sizes */
        printf("  wire: X25519 pub 32 B + ML-KEM pk %zu B + ML-KEM ct %zu B\n",
               defs[d].pk,
               defs[d].ct);
        printf("RESULT %s wire_bytes x25519_pub=32 mlkem_pk=%zu mlkem_ct=%zu\n",
               defs[d].name,
               defs[d].pk,
               defs[d].ct);
        EVP_PKEY_free(srv_priv);
        EVP_PKEY_free(cli_priv);
        OQS_KEM_free(kem);
    }

    printf("== C. hybrid controls (ML-KEM-768) ==\n");
    {
        OQS_KEM* kem = OQS_KEM_new("ML-KEM-768");
        assert(kem);
        uint8_t pk[1184], sk[2400];
        OQS_KEM_keypair(kem, pk, sk);
        uint8_t srv_pub[32], cli_pub[32];
        EVP_PKEY *srv_priv = NULL, *cli_priv = NULL;
        assert(x25519_keypair(srv_pub, &srv_priv) == 0);
        assert(x25519_keypair(cli_pub, &cli_priv) == 0);
        uint8_t ct[1088], ss_kem[32], ss_x[32], combo[64], ss_ref[32];
        assert(x25519_derive(cli_priv, srv_pub, ss_x) == 0);
        assert(OQS_KEM_encaps(kem, ct, ss_kem, pk) == OQS_SUCCESS);
        memcpy(combo, ss_x, 32);
        memcpy(combo + 32, ss_kem, 32);
        SHA256(combo, 64, ss_ref);
        char href[65];
        sha256_hex(ss_ref, 32, href);
        printf("  reference hybrid ss_sha256=%s\n", href);

        step("C-1 all-zero X25519 peer key");
        {
            uint8_t zero_pub[32] = {0};
            uint8_t ss_x0[32], combo0[64], ss0[32];
            int rc = x25519_derive(cli_priv, zero_pub, ss_x0);
            printf("  all-zero peer derive rc=%d\n", rc);
            /* OpenSSL rejects the all-zero peer key (low-order point). */
            if (rc == 0)
            {
                memcpy(combo0, ss_x0, 32);
                memcpy(combo0 + 32, ss_kem, 32);
                SHA256(combo0, 64, ss0);
                char h0[65];
                sha256_hex(ss0, 32, h0);
                printf("  all-zero hybrid ss_sha256=%s (ref %s)\n", h0, href);
                printf("RESULT hybrid all_zero_x25519 rc=0 matches_ref=%d\n",
                       memcmp(ss0, ss_ref, 32) == 0);
                ok(memcmp(ss0, ss_ref, 32) != 0,
                   "all-zero X25519 part changes the hybrid secret");
            }
            else
            {
                printf("RESULT hybrid all_zero_x25519 rc=%d rejected_by_openssl\n", rc);
                ok(1, "all-zero X25519 peer key rejected by OpenSSL");
            }
        }
        step("C-2 tampered ML-KEM ciphertext");
        {
            uint8_t bad[1088];
            memcpy(bad, ct, 1088);
            bad[0] ^= 0xFF;
            uint8_t ss_bad[32], combo_b[64], ss_hb[32];
            OQS_STATUS rc = OQS_KEM_decaps(kem, ss_bad, bad, sk);
            memcpy(combo_b, ss_x, 32);
            memcpy(combo_b + 32, ss_bad, 32);
            SHA256(combo_b, 64, ss_hb);
            char hb[65];
            sha256_hex(ss_hb, 32, hb);
            printf("  tampered ct decaps rc=%d hybrid ss_sha256=%s (ref %s)\n",
                   rc,
                   hb,
                   href);
            printf("RESULT hybrid tampered_ct rc=%d matches_ref=%d\n",
                   rc,
                   memcmp(ss_hb, ss_ref, 32) == 0);
            ok(rc == OQS_SUCCESS && memcmp(ss_hb, ss_ref, 32) != 0,
               "tampered ciphertext yields a different hybrid secret");
        }
        step("C-3 tampered X25519 shared secret");
        {
            uint8_t ss_x_bad[32];
            memcpy(ss_x_bad, ss_x, 32);
            ss_x_bad[0] ^= 0xFF;
            uint8_t combo_b[64], ss_hb[32];
            memcpy(combo_b, ss_x_bad, 32);
            memcpy(combo_b + 32, ss_kem, 32);
            SHA256(combo_b, 64, ss_hb);
            char hb[65];
            sha256_hex(ss_hb, 32, hb);
            printf("  tampered X25519 part hybrid ss_sha256=%s (ref %s)\n", hb, href);
            printf("RESULT hybrid tampered_x25519 matches_ref=%d\n",
                   memcmp(ss_hb, ss_ref, 32) == 0);
            ok(memcmp(ss_hb, ss_ref, 32) != 0,
               "tampered X25519 part changes the hybrid secret");
        }
        EVP_PKEY_free(srv_priv);
        EVP_PKEY_free(cli_priv);
        OQS_KEM_free(kem);
    }

    if (fails)
    {
        printf("RESULT bench_hybrid FAIL (%d failures)\n", fails);
        return 1;
    }
    printf("RESULT bench_hybrid OK\n");
    return 0;
}

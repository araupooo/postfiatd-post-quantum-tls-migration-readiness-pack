/*
 * bench_kem.c — ML-KEM measurement harness for the post-quantum TLS
 * migration readiness assessment.
 *
 * Sections:
 *   A  FIPS 203 parameter table (sizes) vs liboqs headers
 *   B  keygen / encaps / decaps performance (single thread)
 *   C  Implicit-rejection spot check: invalid ciphertexts must decapsulate
 *      to a pseudorandom shared secret, never the original one
 *   D  Coarse timing: valid vs invalid decaps (ML-KEM-768)
 *   E  Key reuse: many encapsulations under one keypair (ML-KEM-768)
 *
 * Build (liboqs 0.14.0, commit 94b421ebb82405c843dba4e9aa521a56ee5a333d):
 *   cc -O2 -Wall -Wextra -I<liboqs>/include bench_kem.c \
 *      -L<liboqs>/build/lib -loqs -lcrypto -lm -o bench_kem
 *
 * Usage: ./bench_kem [bench_n] [timing_n]
 *   bench_n  : iterations per benchmark (default 200)
 *   timing_n : decaps iterations per timing arm (default 1000)
 *
 * All shared secrets are printed only as SHA-256 digests. The harness
 * never prints a raw secret, key, or ciphertext.
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

static void
ok(bool c, char const* what)
{
    printf("  [%s] %s\n", c ? "PASS" : "FAIL", what);
    if (!c)
    {
        printf("RESULT failure: %s\n", what);
        exit(1);
    }
}

static void
step(char const* s)
{
    printf("[step] %s\n", s);
}

static void
rand_bytes(uint8_t* p, size_t n)
{
    FILE* f = fopen("/dev/urandom", "rb");
    assert(f);
    assert(fread(p, 1, n, f) == n);
    fclose(f);
}

typedef struct
{
    char const* name;
    size_t pk, sk, ct, ss;
    double keygen_us, encaps_us, decaps_us;
} K;

static double
bench_oneside(
    OQS_KEM const* kem,
    int what, /* 0 keygen, 1 encaps, 2 decaps */
    int n)
{
    uint8_t pk[1568], sk[3168], ct[1568], ss[32], ss2[32];
    OQS_KEM_keypair(kem, pk, sk);
    if (what == 2) /* decaps arm: pre-generate one ciphertext */
        OQS_KEM_encaps(kem, ct, ss, pk);
    double t0 = now_s();
    for (int i = 0; i < n; i++)
    {
        switch (what)
        {
        case 0:
            OQS_KEM_keypair(kem, pk, sk);
            break;
        case 1:
            OQS_KEM_encaps(kem, ct, ss, pk);
            break;
        case 2:
            /* pure decaps: ciphertext generated once before the loop */
            OQS_KEM_decaps(kem, ss2, ct, sk);
            break;
        }
    }
    return (now_s() - t0) / n * 1e6;
}

static double
bench_decaps(
    OQS_KEM const* kem,
    int n,
    uint8_t const* ct,
    uint8_t const* sk)
{
    uint8_t ss[32];
    double t0 = now_s();
    for (int i = 0; i < n; i++)
        OQS_KEM_decaps(kem, ss, ct, sk);
    return (now_s() - t0) / n * 1e6;
}

int
main(int argc, char** argv)
{
    int bench_n = argc > 1 ? atoi(argv[1]) : 200;
    int timing_n = argc > 2 ? atoi(argv[2]) : 1000;
    printf("bench_kem: liboqs %s bench_n=%d timing_n=%d\n",
           OQS_VERSION_TEXT,
           bench_n,
           timing_n);
    printf("environment: single thread, CLOCK_MONOTONIC, liboqs 0.14.0\n");

    K k[3] = {{"ML-KEM-512", 800, 1632, 768, 32},
              {"ML-KEM-768", 1184, 2400, 1088, 32},
              {"ML-KEM-1024", 1568, 3168, 1568, 32}};

    /* ---- Section A: sizes ---- */
    printf("== A. FIPS 203 parameter table (sizes) ==\n");
    for (int i = 0; i < 3; i++)
    {
        OQS_KEM* kem = OQS_KEM_new(k[i].name);
        assert(kem);
        step(k[i].name);
        printf("  %s: liboqs pk=%zu sk=%zu ct=%zu ss=%zu\n",
               k[i].name,
               kem->length_public_key,
               kem->length_secret_key,
               kem->length_ciphertext,
               kem->length_shared_secret);
        ok(kem->length_public_key == k[i].pk, "public key length");
        ok(kem->length_secret_key == k[i].sk, "secret key length");
        ok(kem->length_ciphertext == k[i].ct, "ciphertext length");
        ok(kem->length_shared_secret == k[i].ss, "shared secret length");
        OQS_KEM_free(kem);
    }

    /* ---- Section B: performance ---- */
    printf("== B. keygen/encaps/decaps performance (single thread) ==\n");
    for (int i = 0; i < 3; i++)
    {
        OQS_KEM* kem = OQS_KEM_new(k[i].name);
        assert(kem);
        step(k[i].name);
        k[i].keygen_us = bench_oneside(kem, 0, bench_n);
        k[i].encaps_us = bench_oneside(kem, 1, bench_n);
        k[i].decaps_us = bench_oneside(kem, 2, bench_n);
        printf("  %s: keygen %.2f us, encaps %.2f us, decaps %.2f us "
               "(n=%d)\n",
               k[i].name,
               k[i].keygen_us,
               k[i].encaps_us,
               k[i].decaps_us,
               bench_n);
        printf("RESULT %s keygen_us=%.2f encaps_us=%.2f decaps_us=%.2f "
               "n=%d\n",
               k[i].name,
               k[i].keygen_us,
               k[i].encaps_us,
               k[i].decaps_us,
               bench_n);
        OQS_KEM_free(kem);
    }

    /* ---- Section C: implicit rejection ---- */
    printf("== C. implicit-rejection spot check ==\n");
    int total_invalid = 0, total_rejected = 0;
    for (int i = 0; i < 3; i++)
    {
        OQS_KEM* kem = OQS_KEM_new(k[i].name);
        assert(kem);
        step(k[i].name);
        uint8_t pk[1568], sk[3168], ct[1568], ss[32], ss_bad[32];
        char h_ref[65], h_bad[65];
        OQS_KEM_keypair(kem, pk, sk);
        OQS_KEM_encaps(kem, ct, ss, pk);
        sha256_hex(ss, 32, h_ref);
        int invalid = 0, rejected = 0;
        /* 3 single-bit flips */
        for (int b = 0; b < 3; b++)
        {
            uint8_t bad[1568];
            memcpy(bad, ct, k[i].ct);
            bad[b * 311] ^= 1;
            OQS_STATUS rc = OQS_KEM_decaps(kem, ss_bad, bad, sk);
            sha256_hex(ss_bad, 32, h_bad);
            printf("  %s bitflip byte %d: rc=%d ss_sha256=%s (ref %s)\n",
                   k[i].name,
                   b * 311,
                   rc,
                   h_bad,
                   h_ref);
            invalid++;
            if (rc == OQS_SUCCESS && memcmp(ss_bad, ss, 32) != 0)
                rejected++;
            else
                printf("  NOTE %s bitflip %d NOT rejected as pseudorandom\n",
                       k[i].name,
                       b);
        }
        /* 32 random ciphertexts */
        for (int t = 0; t < 32; t++)
        {
            uint8_t bad[1568];
            rand_bytes(bad, k[i].ct);
            OQS_STATUS rc = OQS_KEM_decaps(kem, ss_bad, bad, sk);
            sha256_hex(ss_bad, 32, h_bad);
            if (t < 3)
                printf("  %s random %d: rc=%d ss_sha256=%s\n",
                       k[i].name,
                       t,
                       rc,
                       h_bad);
            invalid++;
            if (rc == OQS_SUCCESS && memcmp(ss_bad, ss, 32) != 0)
                rejected++;
        }
        /* 1 all-zero ciphertext */
        {
            uint8_t bad[1568] = {0};
            OQS_STATUS rc = OQS_KEM_decaps(kem, ss_bad, bad, sk);
            sha256_hex(ss_bad, 32, h_bad);
            printf("  %s all-zero: rc=%d ss_sha256=%s\n",
                   k[i].name,
                   rc,
                   h_bad);
            invalid++;
            if (rc == OQS_SUCCESS && memcmp(ss_bad, ss, 32) != 0)
                rejected++;
        }
        printf("RESULT %s implicit_rejection %d/%d invalid ciphertexts "
               "rejected to a pseudorandom shared secret\n",
               k[i].name,
               rejected,
               invalid);
        total_invalid += invalid;
        total_rejected += rejected;
        ok(rejected == invalid, "all invalid ciphertexts rejected");
        OQS_KEM_free(kem);
    }
    printf("RESULT implicit_rejection_total %d/%d\n",
           total_rejected,
           total_invalid);

    /* ---- Section D: timing valid vs invalid ---- */
    printf("== D. coarse timing: valid vs invalid decaps (ML-KEM-768) ==\n");
    {
        OQS_KEM* kem = OQS_KEM_new("ML-KEM-768");
        assert(kem);
        uint8_t pk[1184], sk[2400], ct[1088], ss[32];
        step("valid decaps");
        OQS_KEM_keypair(kem, pk, sk);
        OQS_KEM_encaps(kem, ct, ss, pk);
        double valid_us = bench_decaps(kem, timing_n, ct, sk);
        step("invalid decaps (random ciphertext)");
        uint8_t bad[1088];
        rand_bytes(bad, 1088);
        double invalid_us = bench_decaps(kem, timing_n, bad, sk);
        printf("  ML-KEM-768 decaps valid %.3f us invalid %.3f us "
               "(n=%d, delta %.3f us, %.1f%%)\n",
               valid_us,
               invalid_us,
               timing_n,
               invalid_us - valid_us,
               (invalid_us - valid_us) / valid_us * 100.0);
        printf("RESULT ML-KEM-768 decaps_timing valid_us=%.3f "
               "invalid_us=%.3f n=%d\n",
               valid_us,
               invalid_us,
               timing_n);
        OQS_KEM_free(kem);
    }

    /* ---- Section E: key reuse ---- */
    printf("== E. key reuse (ML-KEM-768, one keypair) ==\n");
    {
        OQS_KEM* kem = OQS_KEM_new("ML-KEM-768");
        assert(kem);
        uint8_t pk[1184], sk[2400];
        OQS_KEM_keypair(kem, pk, sk);
        int roundtrips = 0;
        char seen_ct[100][65];
        for (int t = 0; t < 100; t++)
        {
            uint8_t ct[1088], ss[32], ss2[32];
            char h_ct[65];
            OQS_STATUS rc1 = OQS_KEM_encaps(kem, ct, ss, pk);
            OQS_STATUS rc2 = OQS_KEM_decaps(kem, ss2, ct, sk);
            sha256_hex(ct, 1088, h_ct);
            strcpy(seen_ct[t], h_ct);
            if (t < 3 || t == 99)
                printf("  encaps %d: rc=%d/%d ct_sha256=%s\n",
                       t,
                       rc1,
                       rc2,
                       h_ct);
            if (rc1 == OQS_SUCCESS && rc2 == OQS_SUCCESS &&
                memcmp(ss, ss2, 32) == 0)
                roundtrips++;
        }
        int distinct = 0;
        for (int i = 0; i < 100; i++)
        {
            int dup = 0;
            for (int j = 0; j < i; j++)
                if (!strcmp(seen_ct[i], seen_ct[j]))
                    dup = 1;
            if (!dup)
                distinct++;
        }
        printf("RESULT ML-KEM-768 key_reuse roundtrips=%d/100 "
               "distinct_ciphertexts=%d/100\n",
               roundtrips,
               distinct);
        ok(roundtrips == 100, "100/100 roundtrips under one keypair");
        ok(distinct == 100, "100/100 distinct ciphertexts");
        /* wrong-key decaps must not recover the original secret */
        step("wrong-key decaps");
        uint8_t pk2[1184], sk2[2400], ct[1088], ss[32], ss_wrong[32];
        OQS_KEM_keypair(kem, pk2, sk2);
        OQS_KEM_encaps(kem, ct, ss, pk);
        OQS_STATUS rc = OQS_KEM_decaps(kem, ss_wrong, ct, sk2);
        char h_ref[65], h_wrong[65];
        sha256_hex(ss, 32, h_ref);
        sha256_hex(ss_wrong, 32, h_wrong);
        printf("  wrong-key decaps: rc=%d ss_sha256=%s (ref %s)\n",
               rc,
               h_wrong,
               h_ref);
        printf("RESULT ML-KEM-768 wrong_key_decaps rc=%d matches_ref=%d\n",
               rc,
               memcmp(ss, ss_wrong, 32) == 0);
        ok(rc == OQS_SUCCESS && memcmp(ss, ss_wrong, 32) != 0,
           "wrong key does not recover the shared secret");
        /* replay: same ciphertext decapsulates to the same secret twice */
        step("replay decaps");
        uint8_t ss_a[32], ss_b[32];
        OQS_KEM_decaps(kem, ss_a, ct, sk);
        OQS_KEM_decaps(kem, ss_b, ct, sk);
        printf("RESULT ML-KEM-768 replay_decaps deterministic=%d\n",
               memcmp(ss_a, ss_b, 32) == 0);
        ok(memcmp(ss_a, ss_b, 32) == 0, "replay decaps is deterministic");
        OQS_KEM_free(kem);
    }

    printf("RESULT bench_kem OK\n");
    return 0;
}

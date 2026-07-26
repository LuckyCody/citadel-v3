/*
 * Citadel FFI C roundtrip test.
 *
 * Build and run (Linux):
 *   cargo build --release -p citadel-ffi
 *   gcc -o test_citadel citadel-ffi/bindings/c/test_citadel.c \
 *       -L target/release -lcitadel -Wl,-rpath,target/release
 *   ./test_citadel
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Forward declarations matching citadel-ffi/src/lib.rs */
extern int citadel_keygen(
    unsigned char **pk_out, size_t *pk_len,
    unsigned char **sk_out, size_t *sk_len);

extern int citadel_seal(
    const unsigned char *pk, size_t pk_len,
    const unsigned char *pt, size_t pt_len,
    const unsigned char *aad, size_t aad_len,
    const unsigned char *ctx, size_t ctx_len,
    unsigned char **ct_out, size_t *ct_len);

extern int citadel_open(
    const unsigned char *sk, size_t sk_len,
    const unsigned char *ct, size_t ct_len,
    const unsigned char *aad, size_t aad_len,
    const unsigned char *ctx, size_t ctx_len,
    unsigned char **pt_out, size_t *pt_len);

extern void citadel_free(unsigned char *ptr, size_t len);

/* --- 0xA4 (P-384 + ML-KEM-1024) additive symbols; 0xA3 above is unchanged --- */
extern size_t citadel_public_key_bytes_for_suite(unsigned char suite);
extern size_t citadel_secret_key_bytes_for_suite(unsigned char suite);

extern int citadel_p384_keygen(
    unsigned char **pk_out, size_t *pk_len,
    unsigned char **sk_out, size_t *sk_len);

extern int citadel_p384_seal(
    const unsigned char *pk, size_t pk_len,
    const unsigned char *pt, size_t pt_len,
    const unsigned char *aad, size_t aad_len,
    const unsigned char *ctx, size_t ctx_len,
    unsigned char **ct_out, size_t *ct_len);

extern int citadel_p384_open(
    const unsigned char *sk, size_t sk_len,
    const unsigned char *ct, size_t ct_len,
    const unsigned char *aad, size_t aad_len,
    const unsigned char *ctx, size_t ctx_len,
    unsigned char **pt_out, size_t *pt_len);

#define PASS(msg) printf("  OK  %s\n", msg)
#define FAIL(msg) do { fprintf(stderr, "FAIL  %s\n", msg); exit(1); } while(0)

int main(void) {
    printf("Citadel FFI C roundtrip test\n");
    printf("========================================\n");

    /* Test 1: keygen */
    unsigned char *pk = NULL, *sk = NULL;
    size_t pk_len = 0, sk_len = 0;
    int rc = citadel_keygen(&pk, &pk_len, &sk, &sk_len);
    if (rc != 0) FAIL("keygen returned error");
    if (pk_len != 1216) FAIL("pk wrong length (expected 1216)");
    if (sk_len != 2432) FAIL("sk wrong length (expected 2432)");
    PASS("keygen: correct key lengths");

    /* Test 2: seal + open roundtrip */
    const char *plaintext = "c-roundtrip-test";
    const char *aad = "test-aad";
    unsigned char *ct = NULL;
    size_t ct_len = 0;

    rc = citadel_seal(pk, pk_len,
                      (const unsigned char *)plaintext, strlen(plaintext),
                      (const unsigned char *)aad, strlen(aad),
                      NULL, 0,
                      &ct, &ct_len);
    if (rc != 0) FAIL("seal failed");
    PASS("seal: succeeded");

    unsigned char *pt_out = NULL;
    size_t pt_len = 0;
    rc = citadel_open(sk, sk_len,
                      ct, ct_len,
                      (const unsigned char *)aad, strlen(aad),
                      NULL, 0,
                      &pt_out, &pt_len);
    if (rc != 0) FAIL("open failed");
    if (pt_len != strlen(plaintext)) FAIL("plaintext length mismatch");
    if (memcmp(pt_out, plaintext, pt_len) != 0) FAIL("plaintext content mismatch");
    PASS("open: plaintext matches");

    citadel_free(ct, ct_len);
    citadel_free(pt_out, pt_len);

    /* Test 3: wrong AAD must fail */
    rc = citadel_seal(pk, pk_len,
                      (const unsigned char *)"secret", 6,
                      (const unsigned char *)"correct", 7,
                      NULL, 0, &ct, &ct_len);
    if (rc != 0) FAIL("seal for wrong-aad test failed");

    rc = citadel_open(sk, sk_len, ct, ct_len,
                      (const unsigned char *)"wrong", 5,
                      NULL, 0, &pt_out, &pt_len);
    if (rc == 0) FAIL("wrong-AAD open must fail");
    PASS("wrong-AAD rejection: correctly failed");
    citadel_free(ct, ct_len);

    /* Test 4: null free is safe */
    citadel_free(NULL, 0);
    citadel_free(NULL, 64);
    PASS("null free: no crash");

    citadel_free(pk, pk_len);
    citadel_free(sk, sk_len);

    /* Test 5: 0xA4 (P-384 + ML-KEM-1024) — additive, does not touch 0xA3 above */
    if (citadel_public_key_bytes_for_suite(0xA3) != 1216) FAIL("0xA3 pk size accessor");
    if (citadel_secret_key_bytes_for_suite(0xA3) != 2432) FAIL("0xA3 sk size accessor");
    if (citadel_public_key_bytes_for_suite(0xA4) != 1665) FAIL("0xA4 pk size accessor");
    if (citadel_secret_key_bytes_for_suite(0xA4) != 112)  FAIL("0xA4 sk size accessor");
    if (citadel_public_key_bytes_for_suite(0x00) != 0)    FAIL("unknown suite must be 0");
    PASS("suite size accessors: 0xA3=1216/2432, 0xA4=1665/112, unknown=0");

    unsigned char *p4_pk = NULL, *p4_sk = NULL;
    size_t p4_pk_len = 0, p4_sk_len = 0;
    rc = citadel_p384_keygen(&p4_pk, &p4_pk_len, &p4_sk, &p4_sk_len);
    if (rc != 0) FAIL("p384 keygen returned error");
    if (p4_pk_len != 1665) FAIL("p384 pk wrong length (expected 1665)");
    if (p4_sk_len != 112)  FAIL("p384 sk wrong length (expected 112)");
    PASS("p384 keygen: correct key lengths");

    const char *p4_pt = "c-p384-roundtrip (CNSA category-5)";
    unsigned char *p4_ct = NULL;
    size_t p4_ct_len = 0;
    rc = citadel_p384_seal(p4_pk, p4_pk_len,
                           (const unsigned char *)p4_pt, strlen(p4_pt),
                           (const unsigned char *)aad, strlen(aad),
                           NULL, 0, &p4_ct, &p4_ct_len);
    if (rc != 0) FAIL("p384 seal failed");
    PASS("p384 seal: succeeded");

    unsigned char *p4_out = NULL;
    size_t p4_out_len = 0;
    rc = citadel_p384_open(p4_sk, p4_sk_len, p4_ct, p4_ct_len,
                           (const unsigned char *)aad, strlen(aad),
                           NULL, 0, &p4_out, &p4_out_len);
    if (rc != 0) FAIL("p384 open failed");
    if (p4_out_len != strlen(p4_pt)) FAIL("p384 plaintext length mismatch");
    if (memcmp(p4_out, p4_pt, p4_out_len) != 0) FAIL("p384 plaintext content mismatch");
    PASS("p384 open: plaintext matches");

    citadel_free(p4_ct, p4_ct_len);
    citadel_free(p4_out, p4_out_len);
    citadel_free(p4_pk, p4_pk_len);
    citadel_free(p4_sk, p4_sk_len);

    printf("========================================\n");
    printf("ALL TESTS PASSED\n");
    return 0;
}

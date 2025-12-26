/* test_ksm.c
 *
 * wolfKSM - Test Suite
 *
 * Copyright (C) 2024
 * License: GPLv2+
 */

#include <stdio.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfksm/ksm.h>
#include "../src/ksm_internal.h"  /* For KSM_MAX_KEYS */

#define TEST_PASS 0
#define TEST_FAIL 1

static int tests_run = 0;
static int tests_passed = 0;

#define RUN_TEST(test) do { \
    printf("  %-40s", #test); \
    tests_run++; \
    if (test() == TEST_PASS) { \
        printf("[PASS]\n"); \
        tests_passed++; \
    } else { \
        printf("[FAIL]\n"); \
    } \
} while(0)

/* ============================================================
 * Test: ECC Key Generation
 * ============================================================ */
static int test_generate_ecc_p256(void)
{
    ksm_key_id key_id;
    ksm_key_type type;
    int ret;

    ret = ksm_generate(KSM_TYPE_ECC_P256, &key_id);
    if (ret != KSM_SUCCESS) return TEST_FAIL;

    if (key_id == KSM_KEY_INVALID) return TEST_FAIL;

    ret = ksm_get_type(key_id, &type);
    if (ret != KSM_SUCCESS) return TEST_FAIL;
    if (type != KSM_TYPE_ECC_P256) return TEST_FAIL;

    ret = ksm_destroy(key_id);
    if (ret != KSM_SUCCESS) return TEST_FAIL;

    return TEST_PASS;
}

/* ============================================================
 * Test: Public Key Export
 * ============================================================ */
static int test_export_pubkey(void)
{
    ksm_key_id key_id;
    byte pubkey[65];  /* Uncompressed P-256 point */
    word32 publen = sizeof(pubkey);
    int ret;

    ret = ksm_generate(KSM_TYPE_ECC_P256, &key_id);
    if (ret != KSM_SUCCESS) return TEST_FAIL;

    ret = ksm_export_pubkey(key_id, pubkey, &publen);
    if (ret != KSM_SUCCESS) {
        ksm_destroy(key_id);
        return TEST_FAIL;
    }

    /* Uncompressed point: 0x04 || x || y = 65 bytes */
    if (publen != 65 || pubkey[0] != 0x04) {
        ksm_destroy(key_id);
        return TEST_FAIL;
    }

    ksm_destroy(key_id);
    return TEST_PASS;
}

/* ============================================================
 * Test: Sign and Verify
 * ============================================================ */
static int test_sign_verify(void)
{
    ksm_key_id key_id;
    byte pubkey[65];
    word32 publen = sizeof(pubkey);
    byte hash[32];
    byte sig[72];
    word32 siglen = sizeof(sig);
    ecc_key verify_key;
    int ret, verified;

    /* Generate signing key */
    ret = ksm_generate(KSM_TYPE_ECC_P256, &key_id);
    if (ret != KSM_SUCCESS) return TEST_FAIL;

    /* Export public key */
    ret = ksm_export_pubkey(key_id, pubkey, &publen);
    if (ret != KSM_SUCCESS) {
        ksm_destroy(key_id);
        return TEST_FAIL;
    }

    /* Create test hash */
    memset(hash, 0x42, sizeof(hash));

    /* Sign with KSM (private key never exposed) */
    ret = ksm_sign(key_id, hash, sizeof(hash), sig, &siglen);
    if (ret != KSM_SUCCESS) {
        ksm_destroy(key_id);
        return TEST_FAIL;
    }

    /* Verify using wolfCrypt directly with exported pubkey */
    ret = wc_ecc_init(&verify_key);
    if (ret != 0) {
        ksm_destroy(key_id);
        return TEST_FAIL;
    }

    ret = wc_ecc_import_x963(pubkey, publen, &verify_key);
    if (ret != 0) {
        wc_ecc_free(&verify_key);
        ksm_destroy(key_id);
        return TEST_FAIL;
    }

    ret = wc_ecc_verify_hash(sig, siglen, hash, sizeof(hash),
                             &verified, &verify_key);
    wc_ecc_free(&verify_key);
    ksm_destroy(key_id);

    if (ret != 0 || verified != 1) return TEST_FAIL;

    return TEST_PASS;
}

/* ============================================================
 * Test: ECDH Key Agreement
 * ============================================================ */
static int test_ecdh(void)
{
    ksm_key_id key_a, key_b;
    byte pub_a[65], pub_b[65];
    word32 pub_a_len = sizeof(pub_a), pub_b_len = sizeof(pub_b);
    byte secret_a[32], secret_b[32];
    word32 secret_a_len = sizeof(secret_a), secret_b_len = sizeof(secret_b);
    int ret;

    /* Generate two keys */
    ret = ksm_generate(KSM_TYPE_ECC_P256, &key_a);
    if (ret != KSM_SUCCESS) return TEST_FAIL;

    ret = ksm_generate(KSM_TYPE_ECC_P256, &key_b);
    if (ret != KSM_SUCCESS) {
        ksm_destroy(key_a);
        return TEST_FAIL;
    }

    /* Export public keys */
    ret = ksm_export_pubkey(key_a, pub_a, &pub_a_len);
    if (ret != KSM_SUCCESS) goto cleanup;

    ret = ksm_export_pubkey(key_b, pub_b, &pub_b_len);
    if (ret != KSM_SUCCESS) goto cleanup;

    /* Compute shared secrets */
    ret = ksm_ecdh(key_a, pub_b, pub_b_len, secret_a, &secret_a_len);
    if (ret != KSM_SUCCESS) goto cleanup;

    ret = ksm_ecdh(key_b, pub_a, pub_a_len, secret_b, &secret_b_len);
    if (ret != KSM_SUCCESS) goto cleanup;

    /* Shared secrets must match */
    if (secret_a_len != secret_b_len ||
        memcmp(secret_a, secret_b, secret_a_len) != 0) {
        ret = -1;
        goto cleanup;
    }

    ret = KSM_SUCCESS;

cleanup:
    ksm_destroy(key_a);
    ksm_destroy(key_b);
    return (ret == KSM_SUCCESS) ? TEST_PASS : TEST_FAIL;
}

/* ============================================================
 * Test: Wrapped Export/Import
 * ============================================================ */
static int test_wrapped_export_import(void)
{
    ksm_key_id wrap_key, orig_key, imported_key;
    byte wrapped[1024];
    word32 wrapped_len = sizeof(wrapped);
    byte pub_orig[65], pub_imported[65];
    word32 pub_orig_len = sizeof(pub_orig), pub_imported_len = sizeof(pub_imported);
    int ret;

    /* Generate wrapping key (AES-256) */
    ret = ksm_generate(KSM_TYPE_AES_256, &wrap_key);
    if (ret != KSM_SUCCESS) return TEST_FAIL;

    /* Generate key to wrap */
    ret = ksm_generate(KSM_TYPE_ECC_P256, &orig_key);
    if (ret != KSM_SUCCESS) {
        ksm_destroy(wrap_key);
        return TEST_FAIL;
    }

    /* Export public key of original */
    ret = ksm_export_pubkey(orig_key, pub_orig, &pub_orig_len);
    if (ret != KSM_SUCCESS) goto cleanup;

    /* Wrap and export */
    ret = ksm_export_wrapped(orig_key, wrap_key, wrapped, &wrapped_len);
    if (ret != KSM_SUCCESS) goto cleanup;

    /* Destroy original */
    ksm_destroy(orig_key);
    orig_key = KSM_KEY_INVALID;

    /* Import wrapped */
    ret = ksm_import_wrapped(wrapped, wrapped_len, wrap_key,
                             KSM_TYPE_ECC_P256, &imported_key);
    if (ret != KSM_SUCCESS) goto cleanup;

    /* Export public key of imported */
    ret = ksm_export_pubkey(imported_key, pub_imported, &pub_imported_len);
    if (ret != KSM_SUCCESS) {
        ksm_destroy(imported_key);
        goto cleanup;
    }

    /* Public keys must match */
    if (pub_orig_len != pub_imported_len ||
        memcmp(pub_orig, pub_imported, pub_orig_len) != 0) {
        ret = -1;
    }

    ksm_destroy(imported_key);

cleanup:
    if (orig_key != KSM_KEY_INVALID) ksm_destroy(orig_key);
    ksm_destroy(wrap_key);
    return (ret == KSM_SUCCESS) ? TEST_PASS : TEST_FAIL;
}

/* ============================================================
 * Test: Destroy Makes Key Unusable
 * ============================================================ */
static int test_destroy_invalidates(void)
{
    ksm_key_id key_id;
    ksm_key_type type;
    int ret;

    ret = ksm_generate(KSM_TYPE_ECC_P256, &key_id);
    if (ret != KSM_SUCCESS) return TEST_FAIL;

    ret = ksm_destroy(key_id);
    if (ret != KSM_SUCCESS) return TEST_FAIL;

    /* Should fail - key destroyed */
    ret = ksm_get_type(key_id, &type);
    if (ret != KSM_E_INVALID) return TEST_FAIL;

    return TEST_PASS;
}

/* ============================================================
 * Test: RSA Sign
 * ============================================================ */
static int test_rsa_sign(void)
{
    ksm_key_id key_id;
    byte hash[32];
    byte sig[256];
    word32 siglen = sizeof(sig);
    int ret;

    ret = ksm_generate(KSM_TYPE_RSA_2048, &key_id);
    if (ret != KSM_SUCCESS) return TEST_FAIL;

    memset(hash, 0x55, sizeof(hash));

    ret = ksm_sign(key_id, hash, sizeof(hash), sig, &siglen);
    ksm_destroy(key_id);

    if (ret != KSM_SUCCESS) return TEST_FAIL;
    if (siglen != 256) return TEST_FAIL;  /* RSA-2048 signature = 256 bytes */

    return TEST_PASS;
}

/* ============================================================
 * Test: AES Key Generation
 * ============================================================ */
static int test_aes_key(void)
{
    ksm_key_id key_id;
    ksm_key_type type;
    int ret;

    ret = ksm_generate(KSM_TYPE_AES_256, &key_id);
    if (ret != KSM_SUCCESS) return TEST_FAIL;

    ret = ksm_get_type(key_id, &type);
    if (ret != KSM_SUCCESS || type != KSM_TYPE_AES_256) {
        ksm_destroy(key_id);
        return TEST_FAIL;
    }

    /* AES keys should NOT have exportable pubkey */
    byte buf[32];
    word32 buflen = sizeof(buf);
    ret = ksm_export_pubkey(key_id, buf, &buflen);
    if (ret != KSM_E_TYPE_MISMATCH) {
        ksm_destroy(key_id);
        return TEST_FAIL;
    }

    ksm_destroy(key_id);
    return TEST_PASS;
}

/* ============================================================
 * Test: ECC P-384 Key Generation
 * ============================================================ */
static int test_ecc_p384(void)
{
    ksm_key_id key;
    byte pub[97];
    word32 publen = sizeof(pub);

    if (ksm_generate(KSM_TYPE_ECC_P384, &key) != KSM_SUCCESS) return TEST_FAIL;
    if (ksm_export_pubkey(key, pub, &publen) != KSM_SUCCESS) {
        ksm_destroy(key);
        return TEST_FAIL;
    }
    if (publen != 97 || pub[0] != 0x04) {
        ksm_destroy(key);
        return TEST_FAIL;
    }
    ksm_destroy(key);
    return TEST_PASS;
}

/* ============================================================
 * Test: RSA-4096 Sign
 * ============================================================ */
static int test_rsa_4096(void)
{
    ksm_key_id key;
    byte hash[32], sig[512];
    word32 siglen = sizeof(sig);

    memset(hash, 0x55, sizeof(hash));
    if (ksm_generate(KSM_TYPE_RSA_4096, &key) != KSM_SUCCESS) return TEST_FAIL;
    if (ksm_sign(key, hash, sizeof(hash), sig, &siglen) != KSM_SUCCESS) {
        ksm_destroy(key);
        return TEST_FAIL;
    }
    if (siglen != 512) {
        ksm_destroy(key);
        return TEST_FAIL;
    }
    ksm_destroy(key);
    return TEST_PASS;
}

/* ============================================================
 * Test: AES-128 Key Generation
 * ============================================================ */
static int test_aes_128(void)
{
    ksm_key_id key;
    ksm_key_type type;

    if (ksm_generate(KSM_TYPE_AES_128, &key) != KSM_SUCCESS) return TEST_FAIL;
    if (ksm_get_type(key, &type) != KSM_SUCCESS || type != KSM_TYPE_AES_128) {
        ksm_destroy(key);
        return TEST_FAIL;
    }
    ksm_destroy(key);
    return TEST_PASS;
}

/* ============================================================
 * Test: Null Pointer Handling
 * ============================================================ */
static int test_null_pointers(void)
{
    ksm_key_id key;
    byte buf[64];
    word32 len = sizeof(buf);

    if (ksm_generate(KSM_TYPE_ECC_P256, NULL) != KSM_E_INVALID) return TEST_FAIL;

    ksm_generate(KSM_TYPE_ECC_P256, &key);
    if (ksm_get_type(key, NULL) != KSM_E_INVALID) {
        ksm_destroy(key);
        return TEST_FAIL;
    }
    if (ksm_export_pubkey(key, NULL, &len) != KSM_E_INVALID) {
        ksm_destroy(key);
        return TEST_FAIL;
    }
    if (ksm_export_pubkey(key, buf, NULL) != KSM_E_INVALID) {
        ksm_destroy(key);
        return TEST_FAIL;
    }
    ksm_destroy(key);
    return TEST_PASS;
}

/* ============================================================
 * Test: Invalid Handle Handling
 * ============================================================ */
static int test_invalid_handles(void)
{
    ksm_key_type type;

    if (ksm_get_type(0, &type) != KSM_E_INVALID) return TEST_FAIL;
    if (ksm_get_type(KSM_MAX_KEYS + 1, &type) != KSM_E_INVALID) return TEST_FAIL;
    if (ksm_destroy(0) != KSM_E_INVALID) return TEST_FAIL;
    if (ksm_destroy(99) != KSM_E_INVALID) return TEST_FAIL;

    return TEST_PASS;
}

/* ============================================================
 * Test: Type Mismatch Errors
 * ============================================================ */
static int test_type_mismatch(void)
{
    ksm_key_id ecc_key, aes_key;
    byte buf[256];
    word32 len = sizeof(buf);

    ksm_generate(KSM_TYPE_ECC_P256, &ecc_key);
    ksm_generate(KSM_TYPE_AES_256, &aes_key);

    /* Sign with AES key should fail */
    if (ksm_sign(aes_key, buf, 32, buf, &len) != KSM_E_TYPE_MISMATCH) {
        ksm_destroy(ecc_key);
        ksm_destroy(aes_key);
        return TEST_FAIL;
    }

    /* Decrypt with ECC key should fail */
    len = sizeof(buf);
    if (ksm_decrypt(ecc_key, buf, 256, buf, &len) != KSM_E_TYPE_MISMATCH) {
        ksm_destroy(ecc_key);
        ksm_destroy(aes_key);
        return TEST_FAIL;
    }

    /* Export pubkey from AES should fail */
    len = sizeof(buf);
    if (ksm_export_pubkey(aes_key, buf, &len) != KSM_E_TYPE_MISMATCH) {
        ksm_destroy(ecc_key);
        ksm_destroy(aes_key);
        return TEST_FAIL;
    }

    ksm_destroy(ecc_key);
    ksm_destroy(aes_key);
    return TEST_PASS;
}

/* ============================================================
 * Test: Double Destroy
 * ============================================================ */
static int test_double_destroy(void)
{
    ksm_key_id key;

    ksm_generate(KSM_TYPE_ECC_P256, &key);
    if (ksm_destroy(key) != KSM_SUCCESS) return TEST_FAIL;
    if (ksm_destroy(key) != KSM_E_INVALID) return TEST_FAIL;

    return TEST_PASS;
}

/* ============================================================
 * Test: Wrapped Import with Wrong Key
 * ============================================================ */
static int test_wrapped_wrong_key(void)
{
    ksm_key_id wrap1, wrap2, orig, imported;
    byte wrapped[1024];
    word32 len = sizeof(wrapped);

    ksm_generate(KSM_TYPE_AES_256, &wrap1);
    ksm_generate(KSM_TYPE_AES_256, &wrap2);
    ksm_generate(KSM_TYPE_ECC_P256, &orig);

    ksm_export_wrapped(orig, wrap1, wrapped, &len);

    /* Import with wrong key must fail */
    if (ksm_import_wrapped(wrapped, len, wrap2, KSM_TYPE_ECC_P256, &imported) == KSM_SUCCESS) {
        ksm_destroy(imported);
        ksm_destroy(wrap1);
        ksm_destroy(wrap2);
        ksm_destroy(orig);
        return TEST_FAIL;
    }

    ksm_destroy(wrap1);
    ksm_destroy(wrap2);
    ksm_destroy(orig);
    return TEST_PASS;
}

/* ============================================================
 * Test: Wrapped Data Tampered
 * ============================================================ */
static int test_wrapped_tampered(void)
{
    ksm_key_id wrap, orig, imported;
    byte wrapped[1024];
    word32 len = sizeof(wrapped);

    ksm_generate(KSM_TYPE_AES_256, &wrap);
    ksm_generate(KSM_TYPE_ECC_P256, &orig);

    ksm_export_wrapped(orig, wrap, wrapped, &len);

    /* Flip bit in ciphertext */
    wrapped[30] ^= 0x01;
    if (ksm_import_wrapped(wrapped, len, wrap, KSM_TYPE_ECC_P256, &imported) == KSM_SUCCESS) {
        ksm_destroy(imported);
        ksm_destroy(wrap);
        ksm_destroy(orig);
        return TEST_FAIL;
    }
    wrapped[30] ^= 0x01;

    /* Flip bit in tag */
    wrapped[len - 1] ^= 0x01;
    if (ksm_import_wrapped(wrapped, len, wrap, KSM_TYPE_ECC_P256, &imported) == KSM_SUCCESS) {
        ksm_destroy(imported);
        ksm_destroy(wrap);
        ksm_destroy(orig);
        return TEST_FAIL;
    }

    ksm_destroy(wrap);
    ksm_destroy(orig);
    return TEST_PASS;
}

/* ============================================================
 * Test: Wrapped Import Type Mismatch
 * ============================================================ */
static int test_wrapped_type_mismatch(void)
{
    ksm_key_id wrap, ecc, imported;
    byte wrapped[1024];
    word32 len = sizeof(wrapped);

    ksm_generate(KSM_TYPE_AES_256, &wrap);
    ksm_generate(KSM_TYPE_ECC_P256, &ecc);

    ksm_export_wrapped(ecc, wrap, wrapped, &len);

    /* Import as wrong type must fail */
    if (ksm_import_wrapped(wrapped, len, wrap, KSM_TYPE_RSA_2048, &imported) != KSM_E_TYPE_MISMATCH) {
        if (imported != KSM_KEY_INVALID) ksm_destroy(imported);
        ksm_destroy(wrap);
        ksm_destroy(ecc);
        return TEST_FAIL;
    }

    ksm_destroy(wrap);
    ksm_destroy(ecc);
    return TEST_PASS;
}

/* ============================================================
 * Test: Double Init (should be idempotent)
 * ============================================================ */
static int test_double_init(void)
{
    /* Already init'd in main, second init should succeed (idempotent) */
    if (ksm_init() != KSM_SUCCESS) return TEST_FAIL;
    return TEST_PASS;
}

/* ============================================================
 * Test: Slot Exhaustion
 * ============================================================ */
static int test_slot_exhaustion(void)
{
    ksm_key_id keys[KSM_MAX_KEYS + 1];
    int i;

    for (i = 0; i < KSM_MAX_KEYS; i++) {
        if (ksm_generate(KSM_TYPE_AES_128, &keys[i]) != KSM_SUCCESS) {
            while (--i >= 0) ksm_destroy(keys[i]);
            return TEST_FAIL;
        }
    }

    /* 33rd should fail */
    if (ksm_generate(KSM_TYPE_AES_128, &keys[KSM_MAX_KEYS]) != KSM_E_FULL) {
        for (i = 0; i < KSM_MAX_KEYS; i++) ksm_destroy(keys[i]);
        return TEST_FAIL;
    }

    /* Free one, should succeed now */
    ksm_destroy(keys[0]);
    if (ksm_generate(KSM_TYPE_AES_128, &keys[0]) != KSM_SUCCESS) {
        for (i = 1; i < KSM_MAX_KEYS; i++) ksm_destroy(keys[i]);
        return TEST_FAIL;
    }

    for (i = 0; i < KSM_MAX_KEYS; i++) ksm_destroy(keys[i]);
    return TEST_PASS;
}

/* ============================================================
 * Main
 * ============================================================ */
int main(void)
{
    int ret;

    printf("wolfKSM Test Suite\n");
    printf("==================\n\n");

    ret = ksm_init();
    if (ret != KSM_SUCCESS) {
        printf("ERROR: ksm_init() failed with %d\n", ret);
        return 1;
    }

    printf("Running tests:\n");

    /* Original tests */
    RUN_TEST(test_generate_ecc_p256);
    RUN_TEST(test_export_pubkey);
    RUN_TEST(test_sign_verify);
    RUN_TEST(test_ecdh);
    RUN_TEST(test_wrapped_export_import);
    RUN_TEST(test_destroy_invalidates);
    RUN_TEST(test_rsa_sign);
    RUN_TEST(test_aes_key);

    /* Key type tests */
    RUN_TEST(test_ecc_p384);
    RUN_TEST(test_rsa_4096);
    RUN_TEST(test_aes_128);

    /* Error path tests */
    RUN_TEST(test_null_pointers);
    RUN_TEST(test_invalid_handles);
    RUN_TEST(test_type_mismatch);
    RUN_TEST(test_double_destroy);

    /* Security tests */
    RUN_TEST(test_wrapped_wrong_key);
    RUN_TEST(test_wrapped_tampered);
    RUN_TEST(test_wrapped_type_mismatch);

    /* Lifecycle tests */
    RUN_TEST(test_double_init);
    RUN_TEST(test_slot_exhaustion);

    ksm_shutdown();

    printf("\n==================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}

/* ksm.c
 *
 * Copyright (C) 2024-2025 wolfSSL Inc.
 *
 * This file is part of wolfKSM.
 *
 * wolfKSM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfKSM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfKSM.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "ksm_internal.h"
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>

#if defined(__linux__)
#include <sys/prctl.h>
#endif

/* Thread safety macros */
#ifdef KSM_HAVE_PTHREAD
    #define KSM_LOCK()   pthread_mutex_lock(&_ksm.lock)
    #define KSM_UNLOCK() pthread_mutex_unlock(&_ksm.lock)
#elif defined(KSM_HAVE_WIN32_THREADS)
    #define KSM_LOCK()   EnterCriticalSection(&_ksm.lock)
    #define KSM_UNLOCK() LeaveCriticalSection(&_ksm.lock)
#else
    #define KSM_LOCK()
    #define KSM_UNLOCK()
#endif

/* Global state - keys stored here in mlock'd memory */
static ksm_state_t _ksm;

/* ============================================================
 * Lifecycle
 * ============================================================ */

int ksm_init(void)
{
    int ret;

    if (_ksm.initialized) {
        return KSM_SUCCESS;
    }

    /* Zero state first */
    _ksm_zero(&_ksm, sizeof(_ksm));

    /* Initialize free list */
    _ksm_slot_init_freelist(&_ksm);

    /* Initialize mutex */
#ifdef KSM_HAVE_PTHREAD
    pthread_mutex_init(&_ksm.lock, NULL);
#elif defined(KSM_HAVE_WIN32_THREADS)
    InitializeCriticalSection(&_ksm.lock);
#endif

    /* Lock memory to prevent swapping */
    if (_ksm_mlock(&_ksm, sizeof(_ksm)) == 0) {
        _ksm.mem_locked = 1;
    }
    /* Continue even if mlock fails - better than no security */

    /* Disable core dumps on Linux */
#if defined(__linux__)
    prctl(PR_SET_DUMPABLE, 0);
#endif

    /* Initialize RNG */
    ret = wc_InitRng(&_ksm.rng);
    if (ret != 0) {
#ifdef KSM_HAVE_PTHREAD
        pthread_mutex_destroy(&_ksm.lock);
#elif defined(KSM_HAVE_WIN32_THREADS)
        DeleteCriticalSection(&_ksm.lock);
#endif
        _ksm_zero(&_ksm, sizeof(_ksm));
        return KSM_E_RNG;
    }

    _ksm.initialized = 1;
    return KSM_SUCCESS;
}

void ksm_shutdown(void)
{
    if (!_ksm.initialized) {
        return;
    }

    /* Free all active keys */
    _ksm_slot_free_all(&_ksm);

    /* Free RNG */
    wc_FreeRng(&_ksm.rng);

    /* Unlock memory if we locked it */
    if (_ksm.mem_locked) {
        _ksm_munlock(&_ksm, sizeof(_ksm));
    }

    /* Destroy mutex before zeroing */
#ifdef KSM_HAVE_PTHREAD
    pthread_mutex_destroy(&_ksm.lock);
#elif defined(KSM_HAVE_WIN32_THREADS)
    DeleteCriticalSection(&_ksm.lock);
#endif

    /* Secure zero entire state */
    _ksm_zero(&_ksm, sizeof(_ksm));
}

/* ============================================================
 * Key Generation
 * ============================================================ */

int ksm_generate(ksm_key_type type, ksm_key_id* id)
{
    ksm_key_id slot_id;
    ksm_slot_t* slot;
    int ret = 0;

    if (id == NULL) {
        return KSM_E_INVALID;
    }
    *id = KSM_KEY_INVALID;

    if (!_ksm.initialized) {
        return KSM_E_NOT_INIT;
    }

    KSM_LOCK();

    /* Allocate slot */
    slot_id = _ksm_slot_alloc(&_ksm);
    if (slot_id == KSM_KEY_INVALID) {
        KSM_UNLOCK();
        return KSM_E_FULL;
    }

    slot = &_ksm.slots[slot_id - 1];
    slot->type = type;

    /* Generate key based on type */
    switch (type) {
        case KSM_TYPE_ECC_P256:
            ret = wc_ecc_init(&slot->key.ecc);
            if (ret == 0) {
                ret = wc_ecc_make_key(&_ksm.rng, 32, &slot->key.ecc);
                if (ret == 0) {
                    ret = wc_ecc_set_rng(&slot->key.ecc, &_ksm.rng);
                }
            }
            break;

        case KSM_TYPE_ECC_P384:
            ret = wc_ecc_init(&slot->key.ecc);
            if (ret == 0) {
                ret = wc_ecc_make_key(&_ksm.rng, 48, &slot->key.ecc);
                if (ret == 0) {
                    ret = wc_ecc_set_rng(&slot->key.ecc, &_ksm.rng);
                }
            }
            break;

        case KSM_TYPE_RSA_2048:
            ret = wc_InitRsaKey(&slot->key.rsa, NULL);
            if (ret == 0) {
                ret = wc_MakeRsaKey(&slot->key.rsa, 2048, WC_RSA_EXPONENT,
                                    &_ksm.rng);
            }
            break;

        case KSM_TYPE_RSA_4096:
            ret = wc_InitRsaKey(&slot->key.rsa, NULL);
            if (ret == 0) {
                ret = wc_MakeRsaKey(&slot->key.rsa, 4096, WC_RSA_EXPONENT,
                                    &_ksm.rng);
            }
            break;

#ifdef HAVE_ED25519
        case KSM_TYPE_ED25519:
            ret = wc_ed25519_init(&slot->key.ed);
            if (ret == 0) {
                ret = wc_ed25519_make_key(&_ksm.rng, ED25519_KEY_SIZE,
                                          &slot->key.ed);
            }
            break;
#endif

#ifdef HAVE_CURVE25519
        case KSM_TYPE_X25519:
            ret = wc_curve25519_init(&slot->key.x25519);
            if (ret == 0) {
                ret = wc_curve25519_make_key(&_ksm.rng, CURVE25519_KEYSIZE,
                                             &slot->key.x25519);
            }
            break;
#endif

        case KSM_TYPE_AES_128:
            slot->sym_len = 16;
            ret = wc_RNG_GenerateBlock(&_ksm.rng, slot->key.sym, 16);
            break;

        case KSM_TYPE_AES_256:
            slot->sym_len = 32;
            ret = wc_RNG_GenerateBlock(&_ksm.rng, slot->key.sym, 32);
            break;

        default:
            _ksm_slot_free(&_ksm, slot_id);
            KSM_UNLOCK();
            return KSM_E_UNSUPPORTED;
    }

    if (ret != 0) {
        _ksm_slot_free(&_ksm, slot_id);
        KSM_UNLOCK();
        return KSM_E_CRYPTO;
    }

    *id = slot_id;
    KSM_UNLOCK();
    return KSM_SUCCESS;
}

int ksm_destroy(ksm_key_id id)
{
    int result;

    if (!_ksm.initialized) {
        return KSM_E_NOT_INIT;
    }

    KSM_LOCK();

    if (_ksm_slot_get(&_ksm, id) == NULL) {
        KSM_UNLOCK();
        return KSM_E_INVALID;
    }

    _ksm_slot_free(&_ksm, id);
    result = KSM_SUCCESS;

    KSM_UNLOCK();
    return result;
}

int ksm_get_type(ksm_key_id id, ksm_key_type* type)
{
    ksm_slot_t* slot;
    int result;

    if (type == NULL) {
        return KSM_E_INVALID;
    }

    if (!_ksm.initialized) {
        return KSM_E_NOT_INIT;
    }

    KSM_LOCK();

    slot = _ksm_slot_get(&_ksm, id);
    if (slot == NULL) {
        KSM_UNLOCK();
        return KSM_E_INVALID;
    }

    *type = slot->type;
    result = KSM_SUCCESS;

    KSM_UNLOCK();
    return result;
}

/* ============================================================
 * Public Key Export
 * ============================================================ */

int ksm_export_pubkey(ksm_key_id id, byte* out, word32* len)
{
    ksm_slot_t* slot;
    int ret;
    int result;

    if (out == NULL || len == NULL) {
        return KSM_E_INVALID;
    }

    if (!_ksm.initialized) {
        return KSM_E_NOT_INIT;
    }

    KSM_LOCK();

    slot = _ksm_slot_get(&_ksm, id);
    if (slot == NULL) {
        KSM_UNLOCK();
        return KSM_E_INVALID;
    }

    switch (slot->type) {
        case KSM_TYPE_ECC_P256:
        case KSM_TYPE_ECC_P384:
            /* Ensure RNG is set for export (may be needed for blinding) */
            ret = wc_ecc_set_rng(&slot->key.ecc, &_ksm.rng);
            if (ret == 0) {
                ret = wc_ecc_export_x963(&slot->key.ecc, out, len);
            }
            break;

        case KSM_TYPE_RSA_2048:
        case KSM_TYPE_RSA_4096:
            ret = wc_RsaKeyToPublicDer(&slot->key.rsa, out, *len);
            if (ret > 0) {
                *len = (word32)ret;
                ret = 0;
            }
            break;

#ifdef HAVE_ED25519
        case KSM_TYPE_ED25519:
            ret = wc_ed25519_export_public(&slot->key.ed, out, len);
            break;
#endif

#ifdef HAVE_CURVE25519
        case KSM_TYPE_X25519:
            ret = wc_curve25519_export_public_ex(&slot->key.x25519, out, len,
                                                  EC25519_LITTLE_ENDIAN);
            break;
#endif

        case KSM_TYPE_AES_128:
        case KSM_TYPE_AES_256:
            /* Symmetric keys have no public component */
            KSM_UNLOCK();
            return KSM_E_TYPE_MISMATCH;

        default:
            KSM_UNLOCK();
            return KSM_E_UNSUPPORTED;
    }

    result = (ret == 0) ? KSM_SUCCESS : KSM_E_CRYPTO;
    KSM_UNLOCK();
    return result;
}

/* ============================================================
 * Cryptographic Operations
 * ============================================================ */

int ksm_sign(ksm_key_id id, const byte* hash, word32 hashLen,
             byte* sig, word32* sigLen)
{
    ksm_slot_t* slot;
    int ret;
    int result;

    if (hash == NULL || sig == NULL || sigLen == NULL) {
        return KSM_E_INVALID;
    }

    if (!_ksm.initialized) {
        return KSM_E_NOT_INIT;
    }

    KSM_LOCK();

    slot = _ksm_slot_get(&_ksm, id);
    if (slot == NULL) {
        KSM_UNLOCK();
        return KSM_E_INVALID;
    }

    switch (slot->type) {
        case KSM_TYPE_ECC_P256:
        case KSM_TYPE_ECC_P384:
            ret = wc_ecc_sign_hash(hash, hashLen, sig, sigLen,
                                   &_ksm.rng, &slot->key.ecc);
            break;

        case KSM_TYPE_RSA_2048:
        case KSM_TYPE_RSA_4096:
            ret = wc_RsaSSL_Sign(hash, hashLen, sig, *sigLen,
                                 &slot->key.rsa, &_ksm.rng);
            if (ret > 0) {
                *sigLen = (word32)ret;
                ret = 0;
            }
            break;

#ifdef HAVE_ED25519
        case KSM_TYPE_ED25519:
            /* Ed25519 signs message, not hash - but we accept hash for API consistency */
            ret = wc_ed25519_sign_msg(hash, hashLen, sig, sigLen, &slot->key.ed);
            break;
#endif

        default:
            KSM_UNLOCK();
            return KSM_E_TYPE_MISMATCH;
    }

    result = (ret == 0) ? KSM_SUCCESS : KSM_E_CRYPTO;
    KSM_UNLOCK();
    return result;
}

int ksm_decrypt(ksm_key_id id, const byte* in, word32 inLen,
                byte* out, word32* outLen)
{
    ksm_slot_t* slot;
    int ret;
    int result;

    if (in == NULL || out == NULL || outLen == NULL) {
        return KSM_E_INVALID;
    }

    if (!_ksm.initialized) {
        return KSM_E_NOT_INIT;
    }

    KSM_LOCK();

    slot = _ksm_slot_get(&_ksm, id);
    if (slot == NULL) {
        KSM_UNLOCK();
        return KSM_E_INVALID;
    }

    switch (slot->type) {
        case KSM_TYPE_RSA_2048:
        case KSM_TYPE_RSA_4096:
            ret = wc_RsaPrivateDecrypt(in, inLen, out, *outLen, &slot->key.rsa);
            if (ret > 0) {
                *outLen = (word32)ret;
                ret = 0;
            }
            break;

        default:
            KSM_UNLOCK();
            return KSM_E_TYPE_MISMATCH;
    }

    result = (ret == 0) ? KSM_SUCCESS : KSM_E_CRYPTO;
    KSM_UNLOCK();
    return result;
}

/* Simple HKDF-Extract + Expand for ECDH output normalization */
static int _ksm_hkdf_sha256(const byte* ikm, word32 ikmLen,
                            byte* okm, word32 okmLen)
{
    Hmac hmac;
    byte prk[WC_SHA256_DIGEST_SIZE];
    byte info_counter[1];
    int ret;

    /* Extract: PRK = HMAC-SHA256(salt="", IKM) */
    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0) return ret;

    ret = wc_HmacSetKey(&hmac, WC_SHA256, (const byte*)"", 0);
    if (ret != 0) { wc_HmacFree(&hmac); return ret; }

    ret = wc_HmacUpdate(&hmac, ikm, ikmLen);
    if (ret != 0) { wc_HmacFree(&hmac); return ret; }

    ret = wc_HmacFinal(&hmac, prk);
    wc_HmacFree(&hmac);
    if (ret != 0) return ret;

    /* Expand: OKM = HMAC-SHA256(PRK, 0x01) - single block for <=32 bytes */
    if (okmLen > WC_SHA256_DIGEST_SIZE) {
        okmLen = WC_SHA256_DIGEST_SIZE;
    }

    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0) { _ksm_zero(prk, sizeof(prk)); return ret; }

    ret = wc_HmacSetKey(&hmac, WC_SHA256, prk, WC_SHA256_DIGEST_SIZE);
    _ksm_zero(prk, sizeof(prk));
    if (ret != 0) { wc_HmacFree(&hmac); return ret; }

    info_counter[0] = 0x01;
    ret = wc_HmacUpdate(&hmac, info_counter, 1);
    if (ret != 0) { wc_HmacFree(&hmac); return ret; }

    ret = wc_HmacFinal(&hmac, okm);
    wc_HmacFree(&hmac);

    return ret;
}

int ksm_ecdh(ksm_key_id id, const byte* peerPub, word32 peerLen,
             byte* secret, word32* secretLen)
{
    ksm_slot_t* slot;
    int ret;
    int result;

    if (peerPub == NULL || secret == NULL || secretLen == NULL) {
        return KSM_E_INVALID;
    }

    if (!_ksm.initialized) {
        return KSM_E_NOT_INIT;
    }

    KSM_LOCK();

    slot = _ksm_slot_get(&_ksm, id);
    if (slot == NULL) {
        KSM_UNLOCK();
        return KSM_E_INVALID;
    }

    switch (slot->type) {
        case KSM_TYPE_ECC_P256:
        case KSM_TYPE_ECC_P384:
        {
            ecc_key peer;
            byte raw_secret[64];
            word32 raw_len = sizeof(raw_secret);

            ret = wc_ecc_init(&peer);
            if (ret == 0) {
                ret = wc_ecc_import_x963(peerPub, peerLen, &peer);
                if (ret == 0) {
                    /* Set RNG on both keys for side-channel protection */
                    ret = wc_ecc_set_rng(&slot->key.ecc, &_ksm.rng);
                    if (ret == 0) {
                        ret = wc_ecc_set_rng(&peer, &_ksm.rng);
                    }
                    if (ret == 0) {
                        ret = wc_ecc_shared_secret(&slot->key.ecc, &peer,
                                                   raw_secret, &raw_len);
                        if (ret == 0) {
                            /* Return raw secret (for now - TODO: apply HKDF) */
                            if (*secretLen > raw_len) {
                                *secretLen = raw_len;
                            }
                            XMEMCPY(secret, raw_secret, *secretLen);
                        }
                    }
                }
                wc_ecc_free(&peer);
            }
            _ksm_zero(raw_secret, sizeof(raw_secret));
            break;
        }

#ifdef HAVE_CURVE25519
        case KSM_TYPE_X25519:
        {
            curve25519_key peer;
            byte raw_secret[CURVE25519_KEYSIZE];
            word32 raw_len = sizeof(raw_secret);

            ret = wc_curve25519_init(&peer);
            if (ret == 0) {
                ret = wc_curve25519_import_public_ex(peerPub, peerLen, &peer,
                                                     EC25519_LITTLE_ENDIAN);
                if (ret == 0) {
                    ret = wc_curve25519_shared_secret_ex(&slot->key.x25519,
                                                         &peer, raw_secret,
                                                         &raw_len,
                                                         EC25519_LITTLE_ENDIAN);
                    if (ret == 0) {
                        ret = _ksm_hkdf_sha256(raw_secret, raw_len,
                                               secret, *secretLen);
                        if (ret == 0 && *secretLen > WC_SHA256_DIGEST_SIZE) {
                            *secretLen = WC_SHA256_DIGEST_SIZE;
                        }
                    }
                }
                wc_curve25519_free(&peer);
            }
            _ksm_zero(raw_secret, sizeof(raw_secret));
            break;
        }
#endif

        default:
            KSM_UNLOCK();
            return KSM_E_TYPE_MISMATCH;
    }

    result = (ret == 0) ? KSM_SUCCESS : KSM_E_CRYPTO;
    KSM_UNLOCK();
    return result;
}

/* ============================================================
 * Wrapped Export/Import
 * ============================================================ */

/* Wrapped key format:
 * [4 bytes: type] [4 bytes: data_len] [12 bytes: IV] [data] [16 bytes: tag]
 */
#define KSM_WRAP_HEADER_SIZE (4 + 4 + 12)
#define KSM_WRAP_TAG_SIZE    16
#define KSM_WRAP_IV_SIZE     12

int ksm_export_wrapped(ksm_key_id id, ksm_key_id wrap_key_id,
                       byte* out, word32* len)
{
    ksm_slot_t* slot;
    ksm_slot_t* wrap_slot;
    byte key_data[2560];  /* Sized for RSA-4096 DER + margin */
    word32 key_len = sizeof(key_data);
    byte iv[KSM_WRAP_IV_SIZE];
    byte tag[KSM_WRAP_TAG_SIZE];
    Aes aes;
    int ret;
    word32 needed;

    if (out == NULL || len == NULL) {
        return KSM_E_INVALID;
    }

    if (!_ksm.initialized) {
        return KSM_E_NOT_INIT;
    }

    KSM_LOCK();

    slot = _ksm_slot_get(&_ksm, id);
    wrap_slot = _ksm_slot_get(&_ksm, wrap_key_id);

    if (slot == NULL || wrap_slot == NULL) {
        KSM_UNLOCK();
        return KSM_E_INVALID;
    }

    if (wrap_slot->type != KSM_TYPE_AES_128 &&
        wrap_slot->type != KSM_TYPE_AES_256) {
        KSM_UNLOCK();
        return KSM_E_TYPE_MISMATCH;
    }

    /* Serialize key to temp buffer */
    switch (slot->type) {
        case KSM_TYPE_ECC_P256:
        case KSM_TYPE_ECC_P384:
            /* Export full key in DER format (includes public key) */
            ret = wc_EccKeyToDer(&slot->key.ecc, key_data, key_len);
            if (ret > 0) {
                key_len = (word32)ret;
                ret = 0;
            }
            break;

        case KSM_TYPE_RSA_2048:
        case KSM_TYPE_RSA_4096:
            ret = wc_RsaKeyToDer(&slot->key.rsa, key_data, key_len);
            if (ret > 0) {
                key_len = (word32)ret;
                ret = 0;
            }
            break;

#ifdef HAVE_ED25519
        case KSM_TYPE_ED25519:
            key_len = ED25519_KEY_SIZE;
            ret = wc_ed25519_export_private_only(&slot->key.ed, key_data, &key_len);
            break;
#endif

#ifdef HAVE_CURVE25519
        case KSM_TYPE_X25519:
            key_len = CURVE25519_KEYSIZE;
            ret = wc_curve25519_export_private_raw_ex(&slot->key.x25519,
                                                       key_data, &key_len,
                                                       EC25519_LITTLE_ENDIAN);
            break;
#endif

        case KSM_TYPE_AES_128:
        case KSM_TYPE_AES_256:
            key_len = slot->sym_len;
            XMEMCPY(key_data, slot->key.sym, key_len);
            ret = 0;
            break;

        default:
            KSM_UNLOCK();
            return KSM_E_UNSUPPORTED;
    }

    if (ret != 0) {
        _ksm_zero(key_data, sizeof(key_data));
        KSM_UNLOCK();
        return KSM_E_CRYPTO;
    }

    /* Check output buffer size */
    needed = KSM_WRAP_HEADER_SIZE + key_len + KSM_WRAP_TAG_SIZE;
    if (*len < needed) {
        _ksm_zero(key_data, sizeof(key_data));
        *len = needed;
        KSM_UNLOCK();
        return KSM_E_BUFFER;
    }

    /* Generate IV */
    ret = wc_RNG_GenerateBlock(&_ksm.rng, iv, KSM_WRAP_IV_SIZE);
    if (ret != 0) {
        _ksm_zero(key_data, sizeof(key_data));
        KSM_UNLOCK();
        return KSM_E_RNG;
    }

    /* Write header */
    out[0] = (byte)(slot->type >> 24);
    out[1] = (byte)(slot->type >> 16);
    out[2] = (byte)(slot->type >> 8);
    out[3] = (byte)(slot->type);
    out[4] = (byte)(key_len >> 24);
    out[5] = (byte)(key_len >> 16);
    out[6] = (byte)(key_len >> 8);
    out[7] = (byte)(key_len);
    XMEMCPY(out + 8, iv, KSM_WRAP_IV_SIZE);

    /* AES-GCM encrypt */
    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_AesGcmSetKey(&aes, wrap_slot->key.sym, wrap_slot->sym_len);
        if (ret == 0) {
            ret = wc_AesGcmEncrypt(&aes, out + KSM_WRAP_HEADER_SIZE,
                                   key_data, key_len,
                                   iv, KSM_WRAP_IV_SIZE,
                                   tag, KSM_WRAP_TAG_SIZE,
                                   out, KSM_WRAP_HEADER_SIZE);  /* AAD = type + len + IV */
        }
        wc_AesFree(&aes);
    }

    /* Append tag */
    XMEMCPY(out + KSM_WRAP_HEADER_SIZE + key_len, tag, KSM_WRAP_TAG_SIZE);

    /* Secure zero temp buffer */
    _ksm_zero(key_data, sizeof(key_data));

    if (ret != 0) {
        KSM_UNLOCK();
        return KSM_E_WRAP;
    }

    *len = needed;
    KSM_UNLOCK();
    return KSM_SUCCESS;
}

int ksm_import_wrapped(const byte* wrapped, word32 len,
                       ksm_key_id wrap_key_id, ksm_key_type type,
                       ksm_key_id* id)
{
    ksm_slot_t* wrap_slot;
    ksm_slot_t* new_slot;
    ksm_key_id new_id;
    byte key_data[2560];  /* Sized for RSA-4096 DER + margin */
    word32 key_len;
    ksm_key_type stored_type;
    byte iv[KSM_WRAP_IV_SIZE];
    const byte* tag;
    Aes aes;
    int ret;

    if (wrapped == NULL || id == NULL) {
        return KSM_E_INVALID;
    }
    *id = KSM_KEY_INVALID;

    if (!_ksm.initialized) {
        return KSM_E_NOT_INIT;
    }

    if (len < KSM_WRAP_HEADER_SIZE + KSM_WRAP_TAG_SIZE) {
        return KSM_E_INVALID;
    }

    KSM_LOCK();

    wrap_slot = _ksm_slot_get(&_ksm, wrap_key_id);
    if (wrap_slot == NULL) {
        KSM_UNLOCK();
        return KSM_E_INVALID;
    }

    if (wrap_slot->type != KSM_TYPE_AES_128 &&
        wrap_slot->type != KSM_TYPE_AES_256) {
        KSM_UNLOCK();
        return KSM_E_TYPE_MISMATCH;
    }

    /* Parse header */
    stored_type = (ksm_key_type)(
        ((word32)wrapped[0] << 24) |
        ((word32)wrapped[1] << 16) |
        ((word32)wrapped[2] << 8) |
        ((word32)wrapped[3])
    );
    key_len = ((word32)wrapped[4] << 24) |
              ((word32)wrapped[5] << 16) |
              ((word32)wrapped[6] << 8) |
              ((word32)wrapped[7]);

    if (stored_type != type) {
        KSM_UNLOCK();
        return KSM_E_TYPE_MISMATCH;
    }

    if (len != KSM_WRAP_HEADER_SIZE + key_len + KSM_WRAP_TAG_SIZE) {
        KSM_UNLOCK();
        return KSM_E_INVALID;
    }

    if (key_len > sizeof(key_data)) {
        KSM_UNLOCK();
        return KSM_E_BUFFER;
    }

    XMEMCPY(iv, wrapped + 8, KSM_WRAP_IV_SIZE);
    tag = wrapped + KSM_WRAP_HEADER_SIZE + key_len;

    /* AES-GCM decrypt */
    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_AesGcmSetKey(&aes, wrap_slot->key.sym, wrap_slot->sym_len);
        if (ret == 0) {
            ret = wc_AesGcmDecrypt(&aes, key_data,
                                   wrapped + KSM_WRAP_HEADER_SIZE, key_len,
                                   iv, KSM_WRAP_IV_SIZE,
                                   tag, KSM_WRAP_TAG_SIZE,
                                   wrapped, KSM_WRAP_HEADER_SIZE);  /* AAD = type + len + IV */
        }
        wc_AesFree(&aes);
    }

    if (ret != 0) {
        _ksm_zero(key_data, sizeof(key_data));
        KSM_UNLOCK();
        return KSM_E_WRAP;
    }

    /* Allocate new slot and import */
    new_id = _ksm_slot_alloc(&_ksm);
    if (new_id == KSM_KEY_INVALID) {
        _ksm_zero(key_data, sizeof(key_data));
        KSM_UNLOCK();
        return KSM_E_FULL;
    }

    new_slot = &_ksm.slots[new_id - 1];
    new_slot->type = type;

    switch (type) {
        case KSM_TYPE_ECC_P256:
        case KSM_TYPE_ECC_P384:
            ret = wc_ecc_init(&new_slot->key.ecc);
            if (ret == 0) {
                word32 idx = 0;
                ret = wc_EccPrivateKeyDecode(key_data, &idx, &new_slot->key.ecc, key_len);
                if (ret == 0) {
                    /* Set RNG for future operations */
                    ret = wc_ecc_set_rng(&new_slot->key.ecc, &_ksm.rng);
                }
            }
            break;

        case KSM_TYPE_RSA_2048:
        case KSM_TYPE_RSA_4096:
            ret = wc_InitRsaKey(&new_slot->key.rsa, NULL);
            if (ret == 0) {
                word32 idx = 0;
                ret = wc_RsaPrivateKeyDecode(key_data, &idx,
                                             &new_slot->key.rsa, key_len);
            }
            break;

#ifdef HAVE_ED25519
        case KSM_TYPE_ED25519:
            ret = wc_ed25519_init(&new_slot->key.ed);
            if (ret == 0) {
                ret = wc_ed25519_import_private_only(key_data, key_len,
                                                     &new_slot->key.ed);
            }
            break;
#endif

#ifdef HAVE_CURVE25519
        case KSM_TYPE_X25519:
            ret = wc_curve25519_init(&new_slot->key.x25519);
            if (ret == 0) {
                ret = wc_curve25519_import_private_ex(key_data, key_len,
                                                      &new_slot->key.x25519,
                                                      EC25519_LITTLE_ENDIAN);
            }
            break;
#endif

        case KSM_TYPE_AES_128:
            if (key_len != 16) ret = -1;
            else {
                XMEMCPY(new_slot->key.sym, key_data, 16);
                new_slot->sym_len = 16;
                ret = 0;
            }
            break;

        case KSM_TYPE_AES_256:
            if (key_len != 32) ret = -1;
            else {
                XMEMCPY(new_slot->key.sym, key_data, 32);
                new_slot->sym_len = 32;
                ret = 0;
            }
            break;

        default:
            ret = -1;
    }

    _ksm_zero(key_data, sizeof(key_data));

    if (ret != 0) {
        _ksm_slot_free(&_ksm, new_id);
        KSM_UNLOCK();
        return KSM_E_CRYPTO;
    }

    *id = new_id;
    KSM_UNLOCK();
    return KSM_SUCCESS;
}

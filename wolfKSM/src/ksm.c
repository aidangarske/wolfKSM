/* ksm.c
 *
 * wolfKSM - Lightweight Key Store Manager
 * Core Implementation
 *
 * Copyright (C) 2024
 * License: GPLv2+
 */

#include "ksm_internal.h"
#include <wolfssl/wolfcrypt/aes.h>

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

    /* Lock memory to prevent swapping */
    if (_ksm_mlock(&_ksm, sizeof(_ksm)) == 0) {
        _ksm.mem_locked = 1;
    }
    /* Continue even if mlock fails - better than no security */

    /* Initialize RNG */
    ret = wc_InitRng(&_ksm.rng);
    if (ret != 0) {
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

    /* Allocate slot */
    slot_id = _ksm_slot_alloc(&_ksm);
    if (slot_id == KSM_KEY_INVALID) {
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
            }
            break;

        case KSM_TYPE_ECC_P384:
            ret = wc_ecc_init(&slot->key.ecc);
            if (ret == 0) {
                ret = wc_ecc_make_key(&_ksm.rng, 48, &slot->key.ecc);
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
            return KSM_E_UNSUPPORTED;
    }

    if (ret != 0) {
        _ksm_slot_free(&_ksm, slot_id);
        return KSM_E_CRYPTO;
    }

    *id = slot_id;
    return KSM_SUCCESS;
}

int ksm_destroy(ksm_key_id id)
{
    if (!_ksm.initialized) {
        return KSM_E_NOT_INIT;
    }

    if (_ksm_slot_get(&_ksm, id) == NULL) {
        return KSM_E_INVALID;
    }

    _ksm_slot_free(&_ksm, id);
    return KSM_SUCCESS;
}

int ksm_get_type(ksm_key_id id, ksm_key_type* type)
{
    ksm_slot_t* slot;

    if (type == NULL) {
        return KSM_E_INVALID;
    }

    if (!_ksm.initialized) {
        return KSM_E_NOT_INIT;
    }

    slot = _ksm_slot_get(&_ksm, id);
    if (slot == NULL) {
        return KSM_E_INVALID;
    }

    *type = slot->type;
    return KSM_SUCCESS;
}

/* ============================================================
 * Public Key Export
 * ============================================================ */

int ksm_export_pubkey(ksm_key_id id, byte* out, word32* len)
{
    ksm_slot_t* slot;
    int ret;

    if (out == NULL || len == NULL) {
        return KSM_E_INVALID;
    }

    if (!_ksm.initialized) {
        return KSM_E_NOT_INIT;
    }

    slot = _ksm_slot_get(&_ksm, id);
    if (slot == NULL) {
        return KSM_E_INVALID;
    }

    switch (slot->type) {
        case KSM_TYPE_ECC_P256:
        case KSM_TYPE_ECC_P384:
            ret = wc_ecc_export_x963(&slot->key.ecc, out, len);
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
            return KSM_E_TYPE_MISMATCH;

        default:
            return KSM_E_UNSUPPORTED;
    }

    return (ret == 0) ? KSM_SUCCESS : KSM_E_CRYPTO;
}

/* ============================================================
 * Cryptographic Operations
 * ============================================================ */

int ksm_sign(ksm_key_id id, const byte* hash, word32 hashLen,
             byte* sig, word32* sigLen)
{
    ksm_slot_t* slot;
    int ret;

    if (hash == NULL || sig == NULL || sigLen == NULL) {
        return KSM_E_INVALID;
    }

    if (!_ksm.initialized) {
        return KSM_E_NOT_INIT;
    }

    slot = _ksm_slot_get(&_ksm, id);
    if (slot == NULL) {
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
            return KSM_E_TYPE_MISMATCH;
    }

    return (ret == 0) ? KSM_SUCCESS : KSM_E_CRYPTO;
}

int ksm_decrypt(ksm_key_id id, const byte* in, word32 inLen,
                byte* out, word32* outLen)
{
    ksm_slot_t* slot;
    int ret;

    if (in == NULL || out == NULL || outLen == NULL) {
        return KSM_E_INVALID;
    }

    if (!_ksm.initialized) {
        return KSM_E_NOT_INIT;
    }

    slot = _ksm_slot_get(&_ksm, id);
    if (slot == NULL) {
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
            return KSM_E_TYPE_MISMATCH;
    }

    return (ret == 0) ? KSM_SUCCESS : KSM_E_CRYPTO;
}

int ksm_ecdh(ksm_key_id id, const byte* peerPub, word32 peerLen,
             byte* secret, word32* secretLen)
{
    ksm_slot_t* slot;
    int ret;

    if (peerPub == NULL || secret == NULL || secretLen == NULL) {
        return KSM_E_INVALID;
    }

    if (!_ksm.initialized) {
        return KSM_E_NOT_INIT;
    }

    slot = _ksm_slot_get(&_ksm, id);
    if (slot == NULL) {
        return KSM_E_INVALID;
    }

    switch (slot->type) {
        case KSM_TYPE_ECC_P256:
        case KSM_TYPE_ECC_P384:
        {
            ecc_key peer;
            ret = wc_ecc_init(&peer);
            if (ret == 0) {
                ret = wc_ecc_import_x963(peerPub, peerLen, &peer);
                if (ret == 0) {
                    ret = wc_ecc_shared_secret(&slot->key.ecc, &peer,
                                               secret, secretLen);
                }
                wc_ecc_free(&peer);
            }
            break;
        }

#ifdef HAVE_CURVE25519
        case KSM_TYPE_X25519:
        {
            curve25519_key peer;
            ret = wc_curve25519_init(&peer);
            if (ret == 0) {
                ret = wc_curve25519_import_public_ex(peerPub, peerLen, &peer,
                                                     EC25519_LITTLE_ENDIAN);
                if (ret == 0) {
                    ret = wc_curve25519_shared_secret_ex(&slot->key.x25519,
                                                         &peer, secret,
                                                         secretLen,
                                                         EC25519_LITTLE_ENDIAN);
                }
                wc_curve25519_free(&peer);
            }
            break;
        }
#endif

        default:
            return KSM_E_TYPE_MISMATCH;
    }

    return (ret == 0) ? KSM_SUCCESS : KSM_E_CRYPTO;
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
    byte key_data[512];  /* Temp buffer for serialized key */
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

    slot = _ksm_slot_get(&_ksm, id);
    wrap_slot = _ksm_slot_get(&_ksm, wrap_key_id);

    if (slot == NULL || wrap_slot == NULL) {
        return KSM_E_INVALID;
    }

    if (wrap_slot->type != KSM_TYPE_AES_128 &&
        wrap_slot->type != KSM_TYPE_AES_256) {
        return KSM_E_TYPE_MISMATCH;
    }

    /* Serialize key to temp buffer */
    switch (slot->type) {
        case KSM_TYPE_ECC_P256:
        case KSM_TYPE_ECC_P384:
            ret = wc_ecc_export_private_only(&slot->key.ecc, key_data, &key_len);
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
            return KSM_E_UNSUPPORTED;
    }

    if (ret != 0) {
        _ksm_zero(key_data, sizeof(key_data));
        return KSM_E_CRYPTO;
    }

    /* Check output buffer size */
    needed = KSM_WRAP_HEADER_SIZE + key_len + KSM_WRAP_TAG_SIZE;
    if (*len < needed) {
        _ksm_zero(key_data, sizeof(key_data));
        *len = needed;
        return KSM_E_BUFFER;
    }

    /* Generate IV */
    ret = wc_RNG_GenerateBlock(&_ksm.rng, iv, KSM_WRAP_IV_SIZE);
    if (ret != 0) {
        _ksm_zero(key_data, sizeof(key_data));
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
                                   out, 8);  /* AAD = type + len */
        }
        wc_AesFree(&aes);
    }

    /* Append tag */
    XMEMCPY(out + KSM_WRAP_HEADER_SIZE + key_len, tag, KSM_WRAP_TAG_SIZE);

    /* Secure zero temp buffer */
    _ksm_zero(key_data, sizeof(key_data));

    if (ret != 0) {
        return KSM_E_WRAP;
    }

    *len = needed;
    return KSM_SUCCESS;
}

int ksm_import_wrapped(const byte* wrapped, word32 len,
                       ksm_key_id wrap_key_id, ksm_key_type type,
                       ksm_key_id* id)
{
    ksm_slot_t* wrap_slot;
    ksm_slot_t* new_slot;
    ksm_key_id new_id;
    byte key_data[512];
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

    wrap_slot = _ksm_slot_get(&_ksm, wrap_key_id);
    if (wrap_slot == NULL) {
        return KSM_E_INVALID;
    }

    if (wrap_slot->type != KSM_TYPE_AES_128 &&
        wrap_slot->type != KSM_TYPE_AES_256) {
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
        return KSM_E_TYPE_MISMATCH;
    }

    if (len != KSM_WRAP_HEADER_SIZE + key_len + KSM_WRAP_TAG_SIZE) {
        return KSM_E_INVALID;
    }

    if (key_len > sizeof(key_data)) {
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
                                   wrapped, 8);  /* AAD = type + len */
        }
        wc_AesFree(&aes);
    }

    if (ret != 0) {
        _ksm_zero(key_data, sizeof(key_data));
        return KSM_E_WRAP;
    }

    /* Allocate new slot and import */
    new_id = _ksm_slot_alloc(&_ksm);
    if (new_id == KSM_KEY_INVALID) {
        _ksm_zero(key_data, sizeof(key_data));
        return KSM_E_FULL;
    }

    new_slot = &_ksm.slots[new_id - 1];
    new_slot->type = type;

    switch (type) {
        case KSM_TYPE_ECC_P256:
        case KSM_TYPE_ECC_P384:
            ret = wc_ecc_init(&new_slot->key.ecc);
            if (ret == 0) {
                ret = wc_ecc_import_private_key(key_data, key_len,
                                                 NULL, 0, &new_slot->key.ecc);
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
        return KSM_E_CRYPTO;
    }

    *id = new_id;
    return KSM_SUCCESS;
}

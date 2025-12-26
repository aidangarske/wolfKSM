/* ksm.h
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

#ifndef WOLFKSM_H
#define WOLFKSM_H

#include <wolfssl/wolfcrypt/types.h>
#include <wolfksm/ksm_error.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * Types
 * ============================================================ */

/* Opaque key handle - actual key bytes never exposed */
typedef word32 ksm_key_id;
#define KSM_KEY_INVALID 0

/* Supported key types */
typedef enum {
    KSM_TYPE_ECC_P256,      /* ECDSA/ECDH secp256r1 */
    KSM_TYPE_ECC_P384,      /* ECDSA/ECDH secp384r1 */
    KSM_TYPE_RSA_2048,      /* RSA 2048-bit */
    KSM_TYPE_RSA_4096,      /* RSA 4096-bit */
    KSM_TYPE_ED25519,       /* EdDSA signing */
    KSM_TYPE_X25519,        /* X25519 key exchange */
    KSM_TYPE_AES_128,       /* AES-128 symmetric (for wrapping) */
    KSM_TYPE_AES_256        /* AES-256 symmetric (for wrapping) */
} ksm_key_type;

/* ============================================================
 * Lifecycle
 * ============================================================ */

/**
 * Initialize wolfKSM.
 * Must be called before any other KSM function.
 * Locks key storage memory to prevent swapping.
 *
 * @return KSM_SUCCESS or error code
 */
int ksm_init(void);

/**
 * Shutdown wolfKSM.
 * Securely zeros all keys and releases resources.
 */
void ksm_shutdown(void);

/**
 * Generate a new key on-site.
 * Key is born inside KSM and never leaves.
 *
 * @param type   Key type to generate
 * @param id     [out] Receives opaque key handle
 * @return KSM_SUCCESS or error code
 */
int ksm_generate(ksm_key_type type, ksm_key_id* id);

/**
 * Destroy a key.
 * Securely zeros key material.
 *
 * @param id     Key handle
 * @return KSM_SUCCESS or error code
 */
int ksm_destroy(ksm_key_id id);

/**
 * Get key type for a handle.
 *
 * @param id     Key handle
 * @param type   [out] Receives key type
 * @return KSM_SUCCESS or error code
 */
int ksm_get_type(ksm_key_id id, ksm_key_type* type);

/* ============================================================
 * Public Key Export (safe - not private material)
 * ============================================================ */

/**
 * Export public key.
 * For asymmetric keys only. Does not expose private key.
 *
 * @param id     Key handle
 * @param out    [out] Buffer for public key (X9.63 for ECC, DER for RSA)
 * @param len    [in/out] Buffer size, receives actual size
 * @return KSM_SUCCESS or error code
 */
int ksm_export_pubkey(ksm_key_id id, byte* out, word32* len);

/* ============================================================
 * Cryptographic Operations
 * Private key used internally, never exposed
 * ============================================================ */

/**
 * Sign a hash.
 * Supports ECC, RSA, Ed25519 keys.
 *
 * @param id       Key handle
 * @param hash     Hash to sign
 * @param hashLen  Hash length
 * @param sig      [out] Signature buffer
 * @param sigLen   [in/out] Buffer size, receives signature size
 * @return KSM_SUCCESS or error code
 */
int ksm_sign(ksm_key_id id, const byte* hash, word32 hashLen,
             byte* sig, word32* sigLen);

/**
 * Decrypt data (RSA only).
 *
 * @param id       Key handle (RSA)
 * @param in       Ciphertext
 * @param inLen    Ciphertext length
 * @param out      [out] Plaintext buffer
 * @param outLen   [in/out] Buffer size, receives plaintext size
 * @return KSM_SUCCESS or error code
 */
int ksm_decrypt(ksm_key_id id, const byte* in, word32 inLen,
                byte* out, word32* outLen);

/**
 * Perform ECDH key agreement.
 * Supports ECC and X25519 keys.
 *
 * @param id           Key handle (our private key)
 * @param peerPub      Peer's public key (X9.63 or raw)
 * @param peerLen      Peer public key length
 * @param secret       [out] Shared secret buffer
 * @param secretLen    [in/out] Buffer size, receives secret size
 * @return KSM_SUCCESS or error code
 */
int ksm_ecdh(ksm_key_id id, const byte* peerPub, word32 peerLen,
             byte* secret, word32* secretLen);

/* ============================================================
 * Wrapped Export/Import (for backup/migration)
 * Private key encrypted with wrapping key
 * ============================================================ */

/**
 * Export key wrapped (encrypted) with another key.
 * Allows secure backup. Wrapping key must be AES.
 *
 * @param id         Key to export
 * @param wrap_key   Wrapping key handle (AES)
 * @param out        [out] Wrapped key buffer
 * @param len        [in/out] Buffer size, receives wrapped size
 * @return KSM_SUCCESS or error code
 */
int ksm_export_wrapped(ksm_key_id id, ksm_key_id wrap_key,
                       byte* out, word32* len);

/**
 * Import a wrapped key.
 *
 * @param wrapped    Wrapped key data
 * @param len        Wrapped key length
 * @param wrap_key   Wrapping key handle (AES)
 * @param type       Expected key type
 * @param id         [out] Receives new key handle
 * @return KSM_SUCCESS or error code
 */
int ksm_import_wrapped(const byte* wrapped, word32 len,
                       ksm_key_id wrap_key, ksm_key_type type,
                       ksm_key_id* id);

#ifdef __cplusplus
}
#endif

#endif /* WOLFKSM_H */

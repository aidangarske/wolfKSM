/* ksm_internal.h
 *
 * wolfKSM - Internal definitions
 * Not part of public API
 */

#ifndef WOLFKSM_INTERNAL_H
#define WOLFKSM_INTERNAL_H

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/aes.h>

#ifdef HAVE_ED25519
#include <wolfssl/wolfcrypt/ed25519.h>
#endif
#ifdef HAVE_CURVE25519
#include <wolfssl/wolfcrypt/curve25519.h>
#endif

#include <wolfksm/ksm.h>

/* Maximum concurrent keys */
#ifndef KSM_MAX_KEYS
#define KSM_MAX_KEYS 32
#endif

/* Key slot structure */
typedef struct {
    ksm_key_type type;
    byte         active;
    byte         _pad[2];
    union {
        ecc_key    ecc;
        RsaKey     rsa;
#ifdef HAVE_ED25519
        ed25519_key ed;
#endif
#ifdef HAVE_CURVE25519
        curve25519_key x25519;
#endif
        byte       sym[32];  /* AES key material */
    } key;
    word32       sym_len;    /* For symmetric keys */
} ksm_slot_t;

/* Global KSM state */
typedef struct {
    ksm_slot_t  slots[KSM_MAX_KEYS];
    WC_RNG      rng;
    byte        initialized;
    byte        mem_locked;
    byte        _pad[2];
} ksm_state_t;

/* ============================================================
 * Secure Memory (ksm_mem.c)
 * ============================================================ */

/**
 * Lock memory region to prevent swapping.
 * @return 0 on success, -1 on failure (non-fatal)
 */
int _ksm_mlock(void* ptr, size_t len);

/**
 * Unlock memory region.
 */
void _ksm_munlock(void* ptr, size_t len);

/**
 * Secure zero - cannot be optimized away.
 */
void _ksm_zero(void* ptr, size_t len);

/* ============================================================
 * Slot Management (ksm_slot.c)
 * ============================================================ */

/**
 * Allocate a free slot.
 * @return slot index (1-based) or KSM_KEY_INVALID
 */
ksm_key_id _ksm_slot_alloc(ksm_state_t* state);

/**
 * Get slot by ID, validate active.
 * @return pointer to slot or NULL if invalid
 */
ksm_slot_t* _ksm_slot_get(ksm_state_t* state, ksm_key_id id);

/**
 * Free a slot, secure zero contents.
 */
void _ksm_slot_free(ksm_state_t* state, ksm_key_id id);

/**
 * Free all slots.
 */
void _ksm_slot_free_all(ksm_state_t* state);

#endif /* WOLFKSM_INTERNAL_H */

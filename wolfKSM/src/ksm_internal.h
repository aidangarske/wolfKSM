/* ksm_internal.h
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

#ifndef WOLFKSM_INTERNAL_H
#define WOLFKSM_INTERNAL_H

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#ifdef HAVE_ED25519
#include <wolfssl/wolfcrypt/ed25519.h>
#endif
#ifdef HAVE_CURVE25519
#include <wolfssl/wolfcrypt/curve25519.h>
#endif

/* Threading support */
#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
    #include <pthread.h>
    #define KSM_HAVE_PTHREAD
#elif defined(_WIN32)
    #include <windows.h>
    #define KSM_HAVE_WIN32_THREADS
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
    int          next_free;  /* Index of next free slot when inactive */
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
    int         free_head;    /* Index of first free slot, -1 if full */
    byte        initialized;
    byte        mem_locked;
    byte        _pad[2];
#ifdef KSM_HAVE_PTHREAD
    pthread_mutex_t lock;
#elif defined(KSM_HAVE_WIN32_THREADS)
    CRITICAL_SECTION lock;
#endif
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
 * Initialize free list - call during ksm_init.
 */
void _ksm_slot_init_freelist(ksm_state_t* state);

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

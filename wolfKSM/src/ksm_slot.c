/* ksm_slot.c
 *
 * wolfKSM - Slot Management
 *
 * Copyright (C) 2024
 * License: GPLv2+
 */

#include "ksm_internal.h"

ksm_key_id _ksm_slot_alloc(ksm_state_t* state)
{
    int i;

    if (state == NULL) {
        return KSM_KEY_INVALID;
    }

    for (i = 0; i < KSM_MAX_KEYS; i++) {
        if (!state->slots[i].active) {
            state->slots[i].active = 1;
            /* Return 1-based ID (0 is KSM_KEY_INVALID) */
            return (ksm_key_id)(i + 1);
        }
    }

    return KSM_KEY_INVALID;
}

ksm_slot_t* _ksm_slot_get(ksm_state_t* state, ksm_key_id id)
{
    ksm_slot_t* slot;

    if (state == NULL || id == KSM_KEY_INVALID || id > KSM_MAX_KEYS) {
        return NULL;
    }

    slot = &state->slots[id - 1];

    if (!slot->active) {
        return NULL;
    }

    return slot;
}

void _ksm_slot_free(ksm_state_t* state, ksm_key_id id)
{
    ksm_slot_t* slot;

    if (state == NULL || id == KSM_KEY_INVALID || id > KSM_MAX_KEYS) {
        return;
    }

    slot = &state->slots[id - 1];

    if (!slot->active) {
        return;
    }

    /* Free wolfCrypt key structures */
    switch (slot->type) {
        case KSM_TYPE_ECC_P256:
        case KSM_TYPE_ECC_P384:
            wc_ecc_free(&slot->key.ecc);
            break;

        case KSM_TYPE_RSA_2048:
        case KSM_TYPE_RSA_4096:
            wc_FreeRsaKey(&slot->key.rsa);
            break;

#ifdef HAVE_ED25519
        case KSM_TYPE_ED25519:
            wc_ed25519_free(&slot->key.ed);
            break;
#endif

#ifdef HAVE_CURVE25519
        case KSM_TYPE_X25519:
            wc_curve25519_free(&slot->key.x25519);
            break;
#endif

        case KSM_TYPE_AES_128:
        case KSM_TYPE_AES_256:
            /* Symmetric keys are just byte arrays, handled by zero below */
            break;

        default:
            break;
    }

    /* Secure zero entire slot */
    _ksm_zero(slot, sizeof(ksm_slot_t));
    slot->active = 0;
}

void _ksm_slot_free_all(ksm_state_t* state)
{
    int i;

    if (state == NULL) {
        return;
    }

    for (i = 0; i < KSM_MAX_KEYS; i++) {
        if (state->slots[i].active) {
            _ksm_slot_free(state, (ksm_key_id)(i + 1));
        }
    }
}

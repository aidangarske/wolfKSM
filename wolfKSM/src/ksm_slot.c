/* ksm_slot.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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
 * along with wolfKSM. If not, see <http://www.gnu.org/licenses/>.
 */

#include "ksm_internal.h"

/* Initialize free list - call during ksm_init */
void _ksm_slot_init_freelist(ksm_state_t* state)
{
    int i;
    for (i = 0; i < KSM_MAX_KEYS - 1; i++) {
        state->slots[i].next_free = i + 1;
    }
    state->slots[KSM_MAX_KEYS - 1].next_free = -1;
    state->free_head = 0;
}

ksm_key_id _ksm_slot_alloc(ksm_state_t* state)
{
    int idx;

    if (state == NULL || state->free_head < 0) {
        return KSM_KEY_INVALID;
    }

    idx = state->free_head;
    state->free_head = state->slots[idx].next_free;
    state->slots[idx].active = 1;
    state->slots[idx].next_free = -1;

    return (ksm_key_id)(idx + 1);
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
    int idx;

    if (state == NULL || id == KSM_KEY_INVALID || id > KSM_MAX_KEYS) {
        return;
    }

    idx = id - 1;
    slot = &state->slots[idx];

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
            break;

        default:
            break;
    }

    /* Secure zero entire slot */
    _ksm_zero(slot, sizeof(ksm_slot_t));

    /* Add to free list */
    slot->active = 0;
    slot->next_free = state->free_head;
    state->free_head = idx;
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

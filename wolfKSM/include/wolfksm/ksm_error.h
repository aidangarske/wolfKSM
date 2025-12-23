/* ksm_error.h
 *
 * wolfKSM - Lightweight Key Store Manager
 * Error codes
 *
 * Copyright (C) 2024
 * License: GPLv2+
 */

#ifndef WOLFKSM_ERROR_H
#define WOLFKSM_ERROR_H

#define KSM_SUCCESS          0
#define KSM_E_INVALID       -1    /* Invalid key handle */
#define KSM_E_FULL          -2    /* No free slots */
#define KSM_E_UNSUPPORTED   -3    /* Key type not supported */
#define KSM_E_MEMORY        -4    /* Memory allocation failed */
#define KSM_E_RNG           -5    /* RNG failure */
#define KSM_E_CRYPTO        -6    /* Underlying crypto failure */
#define KSM_E_BUFFER        -7    /* Output buffer too small */
#define KSM_E_NOT_INIT      -8    /* KSM not initialized */
#define KSM_E_TYPE_MISMATCH -9    /* Key type mismatch for operation */
#define KSM_E_WRAP          -10   /* Key wrap/unwrap failed */

#endif /* WOLFKSM_ERROR_H */

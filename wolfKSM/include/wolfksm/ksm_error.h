/* ksm_error.h
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

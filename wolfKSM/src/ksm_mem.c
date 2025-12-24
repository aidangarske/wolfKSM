/* ksm_mem.c
 *
 * wolfKSM - Secure Memory Operations
 *
 * Copyright (C) 2024
 * License: GPLv2+
 */

#include "ksm_internal.h"
#include <string.h>

/* Use explicit_bzero if available (C11+) */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
    #if defined(__GLIBC__) && __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 25
        #define KSM_HAVE_EXPLICIT_BZERO
        #include <string.h>
    #endif
#endif

/* Platform-specific memory locking */
#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
    #define KSM_HAVE_MLOCK
    #include <sys/mman.h>
#elif defined(_WIN32)
    #define KSM_HAVE_VIRTUALLOCK
    #include <windows.h>
#endif

int _ksm_mlock(void* ptr, size_t len)
{
    if (ptr == NULL || len == 0) {
        return -1;
    }

#if defined(KSM_HAVE_MLOCK)
    if (mlock(ptr, len) == 0) {
        return 0;
    }
    /* mlock failed - continue without, but caller should note */
    return -1;

#elif defined(KSM_HAVE_VIRTUALLOCK)
    if (VirtualLock(ptr, len)) {
        return 0;
    }
    return -1;

#else
    /* No memory locking available */
    (void)ptr;
    (void)len;
    return -1;
#endif
}

void _ksm_munlock(void* ptr, size_t len)
{
    if (ptr == NULL || len == 0) {
        return;
    }

#if defined(KSM_HAVE_MLOCK)
    munlock(ptr, len);

#elif defined(KSM_HAVE_VIRTUALLOCK)
    VirtualUnlock(ptr, len);

#else
    (void)ptr;
    (void)len;
#endif
}

void _ksm_zero(void* ptr, size_t len)
{
    volatile byte* bp;
    volatile word64* wp;
    size_t pre, words, rem;

    if (ptr == NULL || len == 0) {
        return;
    }

    bp = (volatile byte*)ptr;

    /* Align to 8-byte boundary */
    pre = (8 - ((size_t)bp & 7)) & 7;
    if (pre > len) {
        pre = len;
    }
    while (pre--) {
        *bp++ = 0;
        len--;
    }

    /* Zero 64-bit words */
    wp = (volatile word64*)bp;
    words = len >> 3;
    while (words--) {
        *wp++ = 0;
    }

    /* Zero remaining bytes */
    bp = (volatile byte*)wp;
    rem = len & 7;
    while (rem--) {
        *bp++ = 0;
    }

    /* Memory barrier - single barrier at end */
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif
}

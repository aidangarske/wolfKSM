/* ksm_mem.c
 *
 * wolfKSM - Secure Memory Operations
 *
 * Copyright (C) 2024
 * License: GPLv2+
 */

#include "ksm_internal.h"
#include <string.h>

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
    if (ptr == NULL || len == 0) {
        return;
    }

    /* Volatile pointer prevents compiler from optimizing away the zeroing */
    volatile byte* vp = (volatile byte*)ptr;

    while (len--) {
        *vp++ = 0;
    }

    /* Memory barrier to ensure writes complete before function returns.
     * Prevents reordering that could leak key material. */
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif
}

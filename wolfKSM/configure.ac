dnl configure.ac
dnl
dnl wolfKSM - Lightweight Key Store Manager
dnl

AC_PREREQ([2.69])
AC_INIT([wolfKSM], [0.1.0], [https://github.com/wolfSSL/wolfKSM/issues])
AC_CONFIG_SRCDIR([src/ksm.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign subdir-objects -Wall -Werror])
LT_INIT

dnl Checks for programs
AC_PROG_CC
AC_PROG_CC_C99

dnl Checks for header files
AC_CHECK_HEADERS([sys/mman.h])

dnl ======================================
dnl wolfSSL (required)
dnl ======================================
AC_ARG_WITH([wolfssl],
    [AS_HELP_STRING([--with-wolfssl=PATH],
        [Path to wolfSSL installation (required)])],
    [WOLFSSL_DIR="$withval"],
    [WOLFSSL_DIR=""])

if test -z "$WOLFSSL_DIR"; then
    dnl Try pkg-config
    PKG_CHECK_MODULES([WOLFSSL], [wolfssl], [
        CFLAGS="$CFLAGS $WOLFSSL_CFLAGS"
        LIBS="$LIBS $WOLFSSL_LIBS"
    ], [
        AC_MSG_ERROR([wolfSSL not found. Use --with-wolfssl=PATH])
    ])
else
    CFLAGS="$CFLAGS -I$WOLFSSL_DIR/include"
    LDFLAGS="$LDFLAGS -L$WOLFSSL_DIR/lib"
    LIBS="$LIBS -lwolfssl"
fi

dnl Verify wolfSSL is usable
AC_MSG_CHECKING([for wolfSSL])
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM(
        [[#include <wolfssl/wolfcrypt/random.h>]],
        [[WC_RNG rng; wc_InitRng(&rng);]])],
    [AC_MSG_RESULT([yes])],
    [AC_MSG_ERROR([wolfSSL not usable. Check --with-wolfssl path.])])

dnl ======================================
dnl Optional: wolfTPM
dnl ======================================
AC_ARG_ENABLE([tpm],
    [AS_HELP_STRING([--enable-tpm],
        [Enable TPM 2.0 backend via wolfTPM])],
    [enable_tpm=$enableval],
    [enable_tpm=no])

AC_ARG_WITH([wolftpm],
    [AS_HELP_STRING([--with-wolftpm=PATH],
        [Path to wolfTPM installation])],
    [WOLFTPM_DIR="$withval"],
    [WOLFTPM_DIR=""])

if test "x$enable_tpm" = "xyes"; then
    if test -n "$WOLFTPM_DIR"; then
        CFLAGS="$CFLAGS -I$WOLFTPM_DIR/include"
        LDFLAGS="$LDFLAGS -L$WOLFTPM_DIR/lib"
    fi
    LIBS="$LIBS -lwolftpm"
    AC_DEFINE([WOLFKSM_TPM], [1], [Enable TPM backend])
fi
AM_CONDITIONAL([ENABLE_TPM], [test "x$enable_tpm" = "xyes"])

dnl ======================================
dnl Optional: wolfHSM
dnl ======================================
AC_ARG_ENABLE([hsm],
    [AS_HELP_STRING([--enable-hsm],
        [Enable HSM backend via wolfHSM])],
    [enable_hsm=$enableval],
    [enable_hsm=no])

AC_ARG_WITH([wolfhsm],
    [AS_HELP_STRING([--with-wolfhsm=PATH],
        [Path to wolfHSM installation])],
    [WOLFHSM_DIR="$withval"],
    [WOLFHSM_DIR=""])

if test "x$enable_hsm" = "xyes"; then
    if test -n "$WOLFHSM_DIR"; then
        CFLAGS="$CFLAGS -I$WOLFHSM_DIR/include"
        LDFLAGS="$LDFLAGS -L$WOLFHSM_DIR/lib"
    fi
    LIBS="$LIBS -lwolfhsm"
    AC_DEFINE([WOLFKSM_HSM], [1], [Enable HSM backend])
fi
AM_CONDITIONAL([ENABLE_HSM], [test "x$enable_hsm" = "xyes"])

dnl ======================================
dnl Optional: Encrypted vault persistence
dnl ======================================
AC_ARG_ENABLE([vault],
    [AS_HELP_STRING([--enable-vault],
        [Enable encrypted key vault persistence])],
    [enable_vault=$enableval],
    [enable_vault=no])

if test "x$enable_vault" = "xyes"; then
    AC_DEFINE([WOLFKSM_VAULT], [1], [Enable encrypted vault])
fi
AM_CONDITIONAL([ENABLE_VAULT], [test "x$enable_vault" = "xyes"])

dnl ======================================
dnl Max keys configuration
dnl ======================================
AC_ARG_WITH([max-keys],
    [AS_HELP_STRING([--with-max-keys=N],
        [Maximum concurrent keys (default: 32)])],
    [max_keys="$withval"],
    [max_keys=32])

AC_DEFINE_UNQUOTED([KSM_MAX_KEYS], [$max_keys], [Maximum concurrent keys])

dnl ======================================
dnl Static Analysis Tools
dnl ======================================
AC_ARG_ENABLE([static-analysis],
    [AS_HELP_STRING([--enable-static-analysis],
        [Enable static analysis targets (format, lint, cppcheck)])],
    [enable_static_analysis=$enableval],
    [enable_static_analysis=no])

if test "x$enable_static_analysis" = "xyes"; then
    AC_CHECK_PROG([CLANG_FORMAT], [clang-format], [clang-format], [no])
    AC_CHECK_PROG([CLANG_TIDY], [clang-tidy], [clang-tidy], [no])
    AC_CHECK_PROG([CPPCHECK], [cppcheck], [cppcheck], [no])

    if test "x$CLANG_FORMAT" = "xno"; then
        AC_MSG_WARN([clang-format not found, format targets disabled])
    fi
    if test "x$CPPCHECK" = "xno"; then
        AC_MSG_WARN([cppcheck not found, cppcheck target disabled])
    fi
fi
AM_CONDITIONAL([ENABLE_STATIC_ANALYSIS], [test "x$enable_static_analysis" = "xyes"])
AM_CONDITIONAL([HAVE_CLANG_FORMAT], [test "x$CLANG_FORMAT" != "xno"])
AM_CONDITIONAL([HAVE_CLANG_TIDY], [test "x$CLANG_TIDY" != "xno"])
AM_CONDITIONAL([HAVE_CPPCHECK], [test "x$CPPCHECK" != "xno"])

dnl ======================================
dnl Sanitizers (for development/testing)
dnl ======================================
AC_ARG_ENABLE([sanitizers],
    [AS_HELP_STRING([--enable-sanitizers],
        [Enable AddressSanitizer and UndefinedBehaviorSanitizer])],
    [enable_sanitizers=$enableval],
    [enable_sanitizers=no])

if test "x$enable_sanitizers" = "xyes"; then
    CFLAGS="$CFLAGS -fsanitize=address,undefined -fno-omit-frame-pointer"
    LDFLAGS="$LDFLAGS -fsanitize=address,undefined"
fi

dnl ======================================
dnl Compiler flags
dnl ======================================
CFLAGS="$CFLAGS -Wall -Wextra -Wno-unused-parameter"
CFLAGS="$CFLAGS -Wformat -Wformat-security"
CFLAGS="$CFLAGS -fstack-protector-strong"

dnl ======================================
dnl Output
dnl ======================================
AC_CONFIG_FILES([
    Makefile
    src/Makefile
    include/Makefile
    tests/Makefile
])

AC_OUTPUT

echo ""
echo "wolfKSM configuration:"
echo "  Version:         $PACKAGE_VERSION"
echo "  wolfSSL:         ${WOLFSSL_DIR:-system}"
echo "  TPM backend:     $enable_tpm"
echo "  HSM backend:     $enable_hsm"
echo "  Vault:           $enable_vault"
echo "  Max keys:        $max_keys"
echo ""
echo "Development options:"
echo "  Static analysis: $enable_static_analysis"
echo "  Sanitizers:      $enable_sanitizers"
echo ""

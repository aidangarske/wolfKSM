# src/Makefile.am

lib_LTLIBRARIES = libwolfksm.la

libwolfksm_la_SOURCES = \
    ksm.c \
    ksm_mem.c \
    ksm_slot.c

libwolfksm_la_CPPFLAGS = \
    -I$(top_srcdir)/include \
    -I$(top_srcdir)/src

libwolfksm_la_LDFLAGS = -version-info 0:1:0

# Internal header (not installed)
noinst_HEADERS = ksm_internal.h

# Makefile.am
#
# wolfKSM - Lightweight Key Store Manager
#

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src include tests

EXTRA_DIST = \
    README.md \
    LICENSE \
    .clang-format \
    .clang-tidy \
    cppcheck-suppressions.txt

# pkg-config file
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = wolfksm.pc

# ======================================
# Static Analysis Targets
# ======================================

.PHONY: format format-check lint cppcheck analyze

# Format all C source files
format:
	@echo "Formatting source files..."
	@find $(top_srcdir)/src $(top_srcdir)/include -name '*.c' -o -name '*.h' | \
		xargs clang-format -i -style=file

# Check formatting (dry-run, for CI)
format-check:
	@echo "Checking code formatting..."
	@find $(top_srcdir)/src $(top_srcdir)/include -name '*.c' -o -name '*.h' | \
		xargs clang-format --dry-run -Werror -style=file

# Run clang-tidy (requires compile_commands.json)
lint:
	@echo "Running clang-tidy..."
	@if [ -f compile_commands.json ]; then \
		clang-tidy $(top_srcdir)/src/*.c -- -I$(top_srcdir)/include $(CFLAGS); \
	else \
		echo "No compile_commands.json found. Generate with: bear -- make"; \
		clang-tidy $(top_srcdir)/src/*.c -- -I$(top_srcdir)/include; \
	fi

# Run cppcheck static analyzer
cppcheck:
	@echo "Running cppcheck..."
	cppcheck --enable=all --inconclusive --std=c11 \
		--suppressions-list=$(top_srcdir)/cppcheck-suppressions.txt \
		--error-exitcode=1 \
		-I$(top_srcdir)/include \
		$(top_srcdir)/src/

# Run all static analysis
analyze: format-check cppcheck
	@echo "All static analysis checks passed"

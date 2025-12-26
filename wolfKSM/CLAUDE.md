# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Tool Approval Policy

Claude can execute the following without user approval:
- **All Bash commands** EXCEPT:
  - Git commands (git add, git commit, git push, git pull, git merge, etc.)
  - Any commands that modify git state
- **Read operations**: All file reads, greps, globs, searches
- **Build operations**: make, cmake, configure, compilation
- **Test execution**: make check, running test binaries
- **Analysis tools**: nm, objdump, ldd, file, wc, stat
- **WebFetch/WebSearch**: Documentation lookups

Claude MUST request approval for:
- **Code modifications**: Edit, Write, NotebookEdit tools
- **Git operations**: Any git command (status, diff, log, commit, push, etc.)
- **Commits and pushes**: Creating commits or pushing to remote
- **Destructive operations**: rm -rf, format, dangerous system commands

## Project Overview

wolfKSM is a lightweight key store manager wrapping wolfCrypt. The core security invariant: **private key bytes NEVER cross the API boundary**. Only opaque handles (`ksm_key_id`), public keys, signatures, and cryptographic results leave the library.

## Architecture

```
ksm.h (public API) → ksm.c (dispatch) → ksm_slot.c (slot management)
                                      → ksm_mem.c (mlock/secure zero)
                                      → wolfCrypt (crypto operations)
```

**Key files:**
- `include/wolfksm/ksm.h` - Public API (lifecycle, generate, sign, export)
- `include/wolfksm/ksm_error.h` - Error codes (`KSM_E_*`)
- `src/ksm.c` - Core operations, wrapped export/import
- `src/ksm_slot.c` - Slot allocation, free list management
- `src/ksm_mem.c` - Memory locking (`_ksm_mlock`), secure zeroing (`_ksm_zero`)
- `src/ksm_internal.h` - Internal slot structure, global state

**Memory protection:**
- Keys stored in `mmap(MAP_LOCKED)` memory to prevent swapping
- Volatile writes + asm barrier prevent compiler-optimized zeroing
- PR_SET_DUMPABLE prevents core dump exposure

## Build System

### Standard Build
```bash
./configure --with-wolfssl=/path/to/wolfssl
make && make check
```

### With Static Analysis
```bash
./configure --enable-static-analysis --with-wolfssl=/path/to/wolfssl
make analyze  # runs format-check + cppcheck
```

### With Sanitizers (Development)
```bash
./configure --enable-sanitizers --with-wolfssl=/path/to/wolfssl
make check
```

### Build Options
- `--with-wolfssl=PATH` - Required: wolfSSL installation location
- `--enable-tpm` / `--with-wolftpm=PATH` - TPM 2.0 backend support
- `--enable-hsm` / `--with-wolfhsm=PATH` - HSM backend support
- `--enable-vault` - Encrypted persistence layer
- `--with-max-keys=N` - Max concurrent keys (default: 32)
- `--enable-static-analysis` - Enable format/lint/cppcheck targets
- `--enable-sanitizers` - ASan + UBSan for development

## Development Commands

### Code Quality
```bash
make format       # Auto-format all C files with clang-format
make format-check # CI: verify formatting (dry-run, fails on changes)
make cppcheck     # Static analysis (security, buffer safety)
make lint         # clang-tidy (requires compile_commands.json)
make analyze      # Run format-check + cppcheck
```

Generate `compile_commands.json` for clang-tidy:
```bash
bear -- make
```

### Testing
```bash
make check        # Run full test suite (tests/test_ksm)
```

Tests cover: key generation, sign/verify, ECDH, wrapped export/import, handle invalidation.

## Coding Conventions

**Style:**
- 4-space indent, 80-column limit, Linux kernel braces
- Functions: `lower_case`, internal helpers: `_ksm_*` prefix
- Constants: `UPPER_CASE`, types: `*_t` suffix
- wolfCrypt types: `byte`, `word32`

**Error codes:**
- All in `ksm_error.h` with `KSM_E_*` prefix
- Return `int` (0 = success, negative = error)
- See `docs/ERROR_HANDLING.md` for patterns

**Security checks enforced by clang-tidy:**
- `cert-*` - CERT-C compliance
- `clang-analyzer-security.*` - Buffer/null pointer safety
- `bugprone-*` - Common bug patterns

## wolfCrypt Integration

wolfKSM uses **only wolfCrypt** (no TLS/SSL). Required wolfSSL build options:
```bash
./configure --enable-keygen --enable-aesgcm --enable-hkdf \
            --enable-curve25519 --enable-ed25519
```

**Key API mappings:**
- ECC: `wc_ecc_make_key`, `wc_ecc_sign_hash`, `wc_ecc_shared_secret`
- RSA: `wc_MakeRsaKey`, `wc_RsaSSL_Sign`, `wc_RsaPrivateDecrypt`
- AES-GCM: `wc_AesGcmEncrypt/Decrypt` (for key wrapping)
- Ed25519: `wc_ed25519_make_key`, `wc_ed25519_sign_msg`
- X25519: `wc_curve25519_make_key`, `wc_curve25519_shared_secret_ex`

See `docs/WOLFCRYPT_INTEGRATION.md` for complete API mapping.

## Extension Points

1. **New key type:**
   - Add to `ksm_key_type` enum in `ksm.h`
   - Handle in `ksm_generate()`, `ksm_sign()`, `ksm_export_pubkey()`, etc.
   - Update slot union in `ksm_internal.h`

2. **TPM backend:**
   - Build with `--enable-tpm`
   - Implement in `src/backend_tpm.c` (currently planned)
   - Wrap wolfTPM APIs

3. **Vault persistence:**
   - Build with `--enable-vault`
   - Implement in `src/ksm_vault.c` (currently planned)
   - Encrypt key slots with master key

## Security Model

**Assets protected:**
- Private/symmetric key bytes (HIGH) - never exposed
- Public keys (NONE) - freely exportable
- Key handles (LOW) - sequential, enumerable

**In-scope threats:**
- Unprivileged process memory reads → mlock prevents swap
- Crash dumps → PR_SET_DUMPABLE recommended
- Network observation → keys never transmitted
- Malicious library calls → opaque handles only

**Out-of-scope:**
- Root/kernel access (full memory visibility)
- Physical attacks (cold boot, DMA)
- Hardware attacks (fault injection, EM)

See `docs/THREAT_MODEL.md` for complete analysis.

## Common Patterns

**Basic usage:**
```c
ksm_init();
ksm_key_id key;
ksm_generate(KSM_TYPE_ECC_P256, &key);
ksm_sign(key, hash, 32, sig, &siglen);
ksm_destroy(key);
ksm_shutdown();
```

**Error handling:**
```c
int ret = ksm_generate(KSM_TYPE_ECC_P256, &key);
if (ret != KSM_SUCCESS) {
    /* Handle error (see ksm_error.h) */
}
```

**Wrapped export/import (encrypted backup):**
```c
ksm_key_id wrap_key, data_key;
ksm_generate(KSM_TYPE_AES_256, &wrap_key);
ksm_generate(KSM_TYPE_ECC_P256, &data_key);

byte wrapped[256];
word32 wrapped_len = sizeof(wrapped);
ksm_export_wrapped(data_key, wrap_key, wrapped, &wrapped_len);

ksm_key_id restored;
ksm_import_wrapped(wrapped, wrapped_len, wrap_key, &restored);
```

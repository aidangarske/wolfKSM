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

wolfKSM is a **fully transparent** key store manager that provides cryptographic operations WITHOUT exposing private keys to applications. The ultimate goal: applications never see, touch, or manage key material - they just request operations and wolfKSM handles everything internally.

### Core Security Invariant
**Private key bytes NEVER cross the API boundary.** Applications cannot:
- See private key bytes
- Export private keys (except encrypted via wrapped export)
- Pass key handles between processes
- Accidentally leak keys through memory dumps or crashes

### Vision: Fully Implicit Key Management

Applications use **standard wolfCrypt APIs** without modification. wolfKSM intercepts operations transparently via the crypto callback framework:

```c
// Application perspective: Just normal wolfCrypt calls
wc_ecc_sign_hash(hash, hashLen, sig, &sigLen, NULL);  // No key visible!
wc_ecc_shared_secret(NULL, peerKey, secret, &secretLen);

// Behind the scenes: wolfKSM handles EVERYTHING
// - Selects appropriate key based on algorithm/curve
// - Performs operation in secure storage
// - Returns only the cryptographic result
// - Private key NEVER exposed
```

**No key handles. No key management. Just secure crypto.**

## Architecture

### Standalone wolfKSM Library
```
ksm.h (public API) → ksm.c (dispatch) → ksm_slot.c (slot management)
                                      → ksm_mem.c (mlock/secure zero)
                                      → wolfCrypt (crypto operations)
```

### wolfSSL Integration (Primary Use Case)
```
Application (wolfSSH, TLS server, etc.)
    ↓
wolfCrypt API (wc_ecc_sign_hash, wc_RsaSSL_Sign)
    ↓
#ifdef HAVE_WOLFKSM
    if (devId == WOLFKSM_DEVID)  ← Already in wolfCrypt!
        ↓
    wc_CryptoCb_* (crypto callback framework)
        ↓
    wolfKSM_CryptoDevCb (in wolfssl/wolfcrypt/src/ksm_cryptocb.c)
        ↓
    ksm_sign() / ksm_ecdh() / ksm_decrypt()
        ↓
    Private keys NEVER leave wolfKSM
#endif
```

**Key Point**: Applications use unmodified wolfCrypt APIs. wolfKSM integration is transparent via crypto callbacks.

**Key files:**
- `include/wolfksm/ksm.h` - Public API (lifecycle, generate, sign, export)
- `include/wolfksm/ksm_error.h` - Error codes (`KSM_E_*`)
- `src/ksm.c` - Core operations, wrapped export/import
- `src/ksm_slot.c` - Slot allocation, free list management
- `src/ksm_mem.c` - Memory locking (`_ksm_mlock`), secure zeroing (`_ksm_zero`)
- `src/ksm_internal.h` - Internal slot structure, global state

**Supported Algorithms:**

Core Library (via `libwolfksm`):
- ECC: P-256, P-384 (ECDSA sign + ECDH)
- RSA: 2048-bit, 4096-bit (sign + decrypt)
- Ed25519: EdDSA signing
- X25519: ECDH key exchange
- AES: 128-bit, 256-bit (for key wrapping)

wolfSSL Integration (via crypto callback, when built with `--enable-ksm`):
- ✅ ECC P-256/P-384 via `wolfKSM_EccSignHash()`, `wolfKSM_EccDhAgree()`
- ✅ RSA 2048/4096 via `wolfKSM_RsaSign()`, `wolfKSM_RsaDecrypt()`
- ✅ Ed25519 via `wolfKSM_Ed25519Sign()`
- ✅ X25519 via `wolfKSM_X25519SharedSecret()`

See `ALGORITHM_EXAMPLES_PLAN.md` for expansion roadmap.

**Memory protection:**
- Keys stored in `mmap(MAP_LOCKED)` memory to prevent swapping
- Volatile writes + asm barrier prevent compiler-optimized zeroing
- PR_SET_DUMPABLE prevents core dump exposure

## Build System

### Bootstrap Build (First Time Only)

Due to circular dependency (wolfSSL --enable-ksm needs wolfKSM, wolfKSM needs wolfSSL), use this build sequence:

**Step 1: Build wolfSSL WITHOUT --enable-ksm**
```bash
cd /path/to/wolfssl
./autogen.sh  # if from git
./configure \
    --enable-keygen \
    --enable-aesgcm \
    --enable-hkdf \
    --enable-curve25519 \
    --enable-ed25519 \
    --enable-cryptocb
make
sudo make install
sudo ldconfig
```

**Step 2: Build and install wolfKSM**
```bash
cd /path/to/wolfKSM
./autogen.sh  # if from git
./configure
make
make check
sudo make install
sudo ldconfig
```

**Step 3: Rebuild wolfSSL WITH --enable-ksm**
```bash
cd /path/to/wolfssl
make clean
./configure \
    --enable-keygen \
    --enable-aesgcm \
    --enable-hkdf \
    --enable-curve25519 \
    --enable-ed25519 \
    --enable-cryptocb \
    --enable-ksm
make
sudo make install
sudo ldconfig
```

**Step 4: Test**
```bash
cd /path/to/wolfssl
./examples/ksm/ksm_implicit_example
```

### After Bootstrap (Normal Development)

Once both libraries are installed, rebuild either one normally:

**Rebuild wolfSSL:**
```bash
cd /path/to/wolfssl
make clean
./configure \
    --enable-keygen --enable-aesgcm --enable-hkdf \
    --enable-curve25519 --enable-ed25519 \
    --enable-cryptocb --enable-ksm
make
sudo make install
sudo ldconfig
```

**Rebuild wolfKSM:**
```bash
cd /path/to/wolfKSM
make clean
./configure
make
make check
sudo make install
sudo ldconfig
```

### With Static Analysis
```bash
./configure --enable-static-analysis
make analyze  # runs format-check + cppcheck
```

### With Sanitizers (Development)
```bash
./configure --enable-sanitizers
make check
```

### Build Options
- `--with-wolfssl=PATH` - Optional: wolfSSL installation location (default: /usr/local)
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

## wolfSSL Integration

### Building wolfKSM for wolfSSL Integration

See the **Bootstrap Build** section above for complete build instructions.

**Required wolfSSL configure options:**
```bash
./configure \
    --enable-keygen        # wc_MakeRsaKey, wc_ecc_make_key
    --enable-aesgcm        # AES-GCM for key wrapping
    --enable-hkdf          # Key derivation
    --enable-curve25519    # X25519 support
    --enable-ed25519       # Ed25519 support
    --enable-cryptocb      # Crypto callback framework (required)
    --enable-ksm           # wolfKSM integration (final build only)
```

**wolfKSM configure:**
```bash
./configure  # Auto-detects wolfSSL at /usr/local
```

### Using wolfKSM in Applications

**Current Approach** (works now, but requires explicit key management):
```c
#include <wolfssl/wolfcrypt/ksm_cryptocb.h>

int devId;
wolfKSM_SetCryptoDevCb(&devId);  // Register callback

// Generate key in KSM
ksm_key_id ksmId;
ecc_key myKey;
wolfKSM_MakeEccKey(&myKey, NULL, 32, ECC_SECP256R1, &ksmId);

// Use normal wolfCrypt API
wc_ecc_sign_hash(hash, hashLen, sig, &sigLen, &myKey);
// ↑ Automatically routed to KSM via crypto callback!

wolfKSM_ClearCryptoDevCb(devId);
```

**Future Approach** (fully implicit - GOAL):
```c
#include <wolfssl/wolfcrypt/ksm_cryptocb.h>

wolfKSM_SetDefaultPolicy(WC_ALGO_TYPE_PK, ECC_SECP256R1, WOLFKSM_ENABLED);

// Application just uses wolfCrypt - NO key management!
wc_ecc_sign_hash_ex(hash, hashLen, sig, &sigLen, NULL, ECC_SECP256R1);
// ↑ NULL key - wolfKSM automatically selects and uses internal key
```

### How wolfSSL Integration Works

1. **Application calls normal wolfCrypt API**: `wc_ecc_sign_hash()`
2. **wolfCrypt checks devId**: If key has `devId == WOLFKSM_DEVID`...
3. **Routes to crypto callback**: Calls `wc_CryptoCb_EccSign()`
4. **Dispatches to wolfKSM**: `wolfKSM_CryptoDevCb()` handles the request
5. **KSM performs operation**: Calls `ksm_sign()` with internal key
6. **Returns result**: Application gets signature, private key never exposed

**Zero changes to wolfCrypt core!** The crypto callback hooks already exist.

## wolfCrypt API Reference

wolfKSM uses **only wolfCrypt** (no TLS/SSL). Key API mappings:

- ECC: `wc_ecc_make_key`, `wc_ecc_sign_hash`, `wc_ecc_shared_secret`
- RSA: `wc_MakeRsaKey`, `wc_RsaSSL_Sign`, `wc_RsaPrivateDecrypt`
- AES-GCM: `wc_AesGcmEncrypt/Decrypt` (for key wrapping)
- Ed25519: `wc_ed25519_make_key`, `wc_ed25519_sign_msg`
- X25519: `wc_curve25519_make_key`, `wc_curve25519_shared_secret_ex`

## Development Roadmap

### Phase 1: Core wolfKSM Library ✅ COMPLETE
- [x] Key generation (ECC P-256/P-384, RSA 2048/4096)
- [x] Cryptographic operations (sign, ECDH, decrypt)
- [x] Wrapped export/import for secure backup
- [x] Memory protection (mlock, secure zeroing)
- [x] Comprehensive test suite (20/20 tests passing)
- [x] GPL v3 licensing with wolfSSL dual-license structure

### Phase 2: wolfSSL Integration via CryptoCb ✅ IN PROGRESS
- [x] Add `--enable-ksm` flag to wolfSSL configure.ac
- [x] Create `ksm_cryptocb.c` following wolfTPM pattern
- [x] Implement `wolfKSM_CryptoDevCb()` callback
- [x] Auto-enable cryptocb when `--enable-ksm` is used
- [x] Implement Ed25519 crypto callback support (`wolfKSM_Ed25519Sign()`)
- [x] Implement X25519 crypto callback support (`wolfKSM_X25519SharedSecret()`)
- [x] Example program demonstrating all supported algorithms (ECC, RSA, AES, Ed25519, X25519)
- [ ] **TODO: Fully implicit key management** ← Next priority!
  - [ ] Policy-based key selection (no explicit handles in apps)
  - [ ] Context-aware key routing (TLS server key, client key, etc.)
  - [ ] Automatic key lifecycle management
- [ ] Integration testing with wolfSSH
- [ ] Integration testing with TLS server/client

### Phase 3: Advanced Features (Future)
- [ ] **TPM backend** (`--enable-tpm`):
  - Hardware-backed key storage via wolfTPM
  - Persistent keys across reboots
- [ ] **Vault persistence** (`--enable-vault`):
  - Encrypted key storage on disk
  - Master key derivation from passphrase
- [ ] **Named key slots**:
  - Application-defined key identifiers
  - Multi-tenant key isolation
- [ ] **Remote key server**:
  - Networked key management
  - Centralized policy enforcement

### Current Focus: Fully Implicit Integration

**Goal**: Make key management completely transparent. Applications should NEVER see key handles.

**Current State**: Applications still manage `ecc_key`/`RsaKey` structures with `devId` markers.

**Target State**:
```c
// Setup once per application
wolfKSM_SetDefaultPolicy(WC_ALGO_TYPE_PK, ECC_SECP256R1, WOLFKSM_ENABLED);

// Application uses standard wolfCrypt - NO key management!
wc_ecc_sign_hash_ex(hash, hashLen, sig, &sigLen, NULL, ECC_SECP256R1);
// ↑ NULL key pointer! wolfKSM handles everything internally
```

**Implementation Strategy**:
1. Extend crypto callback to handle NULL key pointers
2. Add policy engine to select appropriate KSM key based on algorithm/curve
3. Implement context-aware routing (TLS role, key usage, etc.)
4. Update wolfKSM API to support named contexts/slots

## Extension Points

1. **New key type:**
   - Add to `ksm_key_type` enum in `ksm.h`
   - Handle in `ksm_generate()`, `ksm_sign()`, `ksm_export_pubkey()`, etc.
   - Update slot union in `ksm_internal.h`

2. **New crypto callback operation:**
   - Add case to `wolfKSM_CryptoDevCb()` in `ksm_cryptocb.c`
   - Map to appropriate `ksm_*()` function
   - Update error handling

3. **Backend integration:**
   - Implement in `src/backend_*.c`
   - Follow dispatch pattern in `ksm.c`
   - Maintain API compatibility

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

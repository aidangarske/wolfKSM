# wolfKSM

Lightweight key store manager wrapping wolfCrypt. Keys never leave.

## Architecture

```
ksm.h (public) → ksm.c (dispatch) → ksm_slot.c (storage) → wolfCrypt
                                  → ksm_mem.c (mlock/zero)
```

## Core Invariant

Private key bytes NEVER cross API boundary. Only:
- `ksm_key_id` (word32 handle)
- Public keys
- Signatures, shared secrets, plaintext

## Key Files

| File | Purpose |
|------|---------|
| `include/wolfksm/ksm.h` | Public API |
| `src/ksm.c` | Core ops, wrapped export |
| `src/ksm_slot.c` | Slot alloc/free |
| `src/ksm_mem.c` | `_ksm_mlock`, `_ksm_zero` |
| `src/ksm_internal.h` | Slot struct, state |

## Conventions

- Internal helpers: `_ksm_*` prefix
- Error codes: `KSM_E_*` in `ksm_error.h`
- wolfCrypt types: `byte`, `word32`

## Build

```bash
# Standard build
./configure --with-wolfssl=/path/to/wolfssl
make && make check

# With static analysis
./configure --enable-static-analysis --with-wolfssl=/path/to/wolfssl
make analyze  # format-check + cppcheck

# With sanitizers (debug)
./configure --enable-sanitizers --with-wolfssl=/path/to/wolfssl
make check
```

## Code Quality

```bash
make format       # Auto-format all C files
make format-check # CI: verify formatting
make cppcheck     # Static analysis
make lint         # clang-tidy (needs compile_commands.json)
make analyze      # All checks
```

Config files: `.clang-format`, `.clang-tidy`, `cppcheck-suppressions.txt`

### Coding Style
- 4-space indent, 80-col limit, Linux braces
- Functions: `lower_case`, internal: `_prefix`
- Constants: `UPPER_CASE`, types: `*_t`

### Security Checks (enforced by clang-tidy)
- `cert-*`: CERT-C compliance
- `clang-analyzer-security.*`: Buffer/null safety
- `bugprone-*`: Common bug patterns

## Extension Points

1. **New key type**: Add to `ksm_key_type` enum, handle in `ksm_generate`, `ksm_sign`, etc.
2. **TPM backend**: `--enable-tpm`, implement in `src/backend_tpm.c`
3. **Vault persistence**: `--enable-vault`, add `ksm_vault.c`

## Testing

```bash
make check  # runs tests/test_ksm
```

Tests: generate, sign/verify, ECDH, wrapped export/import, destroy invalidates.

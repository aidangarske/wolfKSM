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
./configure --with-wolfssl=/path/to/wolfssl
make && make check
```

## Extension Points

1. **New key type**: Add to `ksm_key_type` enum, handle in `ksm_generate`, `ksm_sign`, etc.
2. **TPM backend**: `--enable-tpm`, implement in `src/backend_tpm.c`
3. **Vault persistence**: `--enable-vault`, add `ksm_vault.c`

## Testing

```bash
make check  # runs tests/test_ksm
```

Tests: generate, sign/verify, ECDH, wrapped export/import, destroy invalidates.

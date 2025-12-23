# wolfKSM

Lightweight Key Store Manager for wolfCrypt. Private keys never leave.

## What It Does

```
App calls: ksm_sign(handle, hash) → signature
           ksm_ecdh(handle, peer) → shared_secret

What crosses boundary: handles, public keys, results
What stays inside: private key bytes, crypto operations
```

## Quick Start

```bash
# Build (requires wolfSSL)
./configure --with-wolfssl=/usr/local
make && make check

# Use
ksm_key_id key;
ksm_generate(KSM_TYPE_ECC_P256, &key);  // key born inside
ksm_sign(key, hash, 32, sig, &siglen);  // private key never exposed
ksm_destroy(key);                        // secure zero
```

## API

| Function | Purpose |
|----------|---------|
| `ksm_init/shutdown` | Lifecycle, mlock memory |
| `ksm_generate(type, &id)` | Create key on-site |
| `ksm_destroy(id)` | Secure zero |
| `ksm_sign(id, hash, sig)` | Sign (ECC/RSA/Ed25519) |
| `ksm_decrypt(id, in, out)` | RSA decrypt |
| `ksm_ecdh(id, peer, secret)` | Key agreement |
| `ksm_export_pubkey(id, buf)` | Get public key (safe) |
| `ksm_export_wrapped(id, wrap, buf)` | Encrypted backup |
| `ksm_import_wrapped(buf, wrap, &id)` | Restore from backup |

## Key Types

- `KSM_TYPE_ECC_P256/P384` - ECDSA + ECDH
- `KSM_TYPE_RSA_2048/4096` - Sign + Decrypt
- `KSM_TYPE_ED25519` - EdDSA signing
- `KSM_TYPE_X25519` - Key exchange
- `KSM_TYPE_AES_128/256` - Wrapping keys

## Security

| Threat | Mitigation |
|--------|------------|
| Key in swap | `mmap(MAP_LOCKED)` |
| Core dump exposure | mlock prevents |
| Compiler elides memset | Volatile + asm barrier |
| API returns key bytes | Handle-only, callback pattern |
| Weak entropy | wolfCrypt RNG |

## Build Options

```bash
--with-wolfssl=PATH    # Required: wolfSSL location
--enable-tpm           # TPM 2.0 backend (wolfTPM)
--enable-hsm           # HSM backend (wolfHSM)
--enable-vault         # Encrypted persistence
--with-max-keys=N      # Max concurrent keys (default: 32)
```

## Dependencies

- wolfSSL with: `--enable-keygen --enable-aesgcm --enable-hkdf`
- Optional: wolfTPM, wolfHSM

## License

GPLv2+

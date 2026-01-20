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

### Bootstrap Build (First Time Only)

Due to circular dependency, build in this order:

**Step 1: Build wolfSSL without --enable-ksm**
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

**Step 3: Rebuild wolfSSL with --enable-ksm**
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

### Usage

```c
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

## Supported Algorithms

### Core Library (Full Support)
All operations available via standalone `libwolfksm`:

| Algorithm | Key Types | Operations | Status |
|-----------|-----------|------------|--------|
| **ECC** | P-256, P-384 | ECDSA sign, ECDH | ✅ Full |
| **RSA** | 2048-bit, 4096-bit | Sign, Decrypt | ✅ Full |
| **Ed25519** | EdDSA | Sign | ✅ Full |
| **X25519** | Curve25519 | ECDH | ✅ Full |
| **AES** | 128-bit, 256-bit | Wrapping | ✅ Full |

### wolfSSL Integration (via Crypto Callback)
Transparent integration when using `--enable-ksm`:

| Algorithm | Operations | Implicit API | Status |
|-----------|------------|--------------|--------|
| **ECC** P-256/P-384 | Sign, ECDH | `wolfKSM_EccSignHash()`, `wolfKSM_EccDhAgree()` | ✅ Available |
| **RSA** 2048/4096 | Sign, Decrypt | `wolfKSM_RsaSign()`, `wolfKSM_RsaDecrypt()` | ✅ Available |
| **Ed25519** | Sign | `wolfKSM_Ed25519Sign()` | ✅ Available |
| **X25519** | ECDH | `wolfKSM_X25519SharedSecret()` | ✅ Available |

### Future Expansion (Planned)
- Additional ECC curves: P-192, P-224, P-521, secp256k1 (Bitcoin)
- Additional RSA sizes: 1024, 3072 bits
- Post-quantum: Falcon, Dilithium, SPHINCS+
- Classic: DH, DSA
- Curve448, Ed448

**Design Goal:** Eventually support ALL wolfSSL/wolfCrypt algorithms transparently.

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

**Required:**
- wolfSSL with: `--enable-keygen --enable-aesgcm --enable-hkdf --enable-curve25519 --enable-ed25519 --enable-cryptocb`

**Optional:**
- wolfTPM (for `--enable-tpm`)
- wolfHSM (for `--enable-hsm`)

## License

GPLv2+

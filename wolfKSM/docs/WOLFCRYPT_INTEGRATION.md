# wolfCrypt Integration Overview

wolfKSM uses **wolfCrypt only** (the crypto engine inside wolfSSL). No TLS/SSL functionality is used.

## Headers Required

```c
#include <wolfssl/wolfcrypt/settings.h>   // Build configuration
#include <wolfssl/wolfcrypt/types.h>      // byte, word32
#include <wolfssl/wolfcrypt/random.h>     // WC_RNG
#include <wolfssl/wolfcrypt/ecc.h>        // ecc_key, ECDSA, ECDH
#include <wolfssl/wolfcrypt/rsa.h>        // RsaKey
#include <wolfssl/wolfcrypt/aes.h>        // Aes (GCM for key wrapping)
#include <wolfssl/wolfcrypt/ed25519.h>    // ed25519_key (optional)
#include <wolfssl/wolfcrypt/curve25519.h> // curve25519_key (optional)
```

## API Usage by Category

### Random Number Generation

| API | Purpose | Location |
|-----|---------|----------|
| `wc_InitRng(&rng)` | Initialize RNG | `ksm_init()` |
| `wc_FreeRng(&rng)` | Free RNG | `ksm_shutdown()` |
| `wc_RNG_GenerateBlock(&rng, buf, len)` | Generate random bytes | Key gen, IV gen |

### ECC (P-256, P-384)

| API | Purpose | Location |
|-----|---------|----------|
| `wc_ecc_init(&key)` | Initialize key struct | `ksm_generate()` |
| `wc_ecc_make_key(&rng, size, &key)` | Generate keypair | `ksm_generate()` |
| `wc_ecc_free(&key)` | Free key | `ksm_destroy()` |
| `wc_ecc_sign_hash(hash, len, sig, &siglen, &rng, &key)` | ECDSA sign | `ksm_sign()` |
| `wc_ecc_shared_secret(&priv, &peer, out, &len)` | ECDH | `ksm_ecdh()` |
| `wc_ecc_export_x963(&key, out, &len)` | Export pubkey | `ksm_export_pubkey()` |
| `wc_ecc_import_x963(buf, len, &key)` | Import pubkey | `ksm_ecdh()` |
| `wc_ecc_export_private_only(&key, buf, &len)` | Export privkey | `ksm_export_wrapped()` |
| `wc_ecc_import_private_key(priv, len, NULL, 0, &key)` | Import privkey | `ksm_import_wrapped()` |

### RSA (2048, 4096)

| API | Purpose | Location |
|-----|---------|----------|
| `wc_InitRsaKey(&key, NULL)` | Initialize key struct | `ksm_generate()` |
| `wc_MakeRsaKey(&key, bits, exp, &rng)` | Generate keypair | `ksm_generate()` |
| `wc_FreeRsaKey(&key)` | Free key | `ksm_destroy()` |
| `wc_RsaSSL_Sign(hash, len, sig, siglen, &key, &rng)` | RSA sign | `ksm_sign()` |
| `wc_RsaPrivateDecrypt(in, len, out, outlen, &key)` | RSA decrypt | `ksm_decrypt()` |
| `wc_RsaKeyToPublicDer(&key, buf, len)` | Export pubkey | `ksm_export_pubkey()` |
| `wc_RsaKeyToDer(&key, buf, len)` | Export privkey | `ksm_export_wrapped()` |
| `wc_RsaPrivateKeyDecode(buf, &idx, &key, len)` | Import privkey | `ksm_import_wrapped()` |

### AES-GCM (Key Wrapping)

| API | Purpose | Location |
|-----|---------|----------|
| `wc_AesInit(&aes, NULL, INVALID_DEVID)` | Initialize AES ctx | `ksm_export/import_wrapped()` |
| `wc_AesGcmSetKey(&aes, key, len)` | Set wrap key | `ksm_export/import_wrapped()` |
| `wc_AesGcmEncrypt(&aes, out, in, len, iv, ivlen, tag, taglen, aad, aadlen)` | Encrypt | `ksm_export_wrapped()` |
| `wc_AesGcmDecrypt(&aes, out, in, len, iv, ivlen, tag, taglen, aad, aadlen)` | Decrypt | `ksm_import_wrapped()` |
| `wc_AesFree(&aes)` | Free AES ctx | `ksm_export/import_wrapped()` |

### Ed25519 (Optional)

| API | Purpose | Location |
|-----|---------|----------|
| `wc_ed25519_init(&key)` | Initialize | `ksm_generate()` |
| `wc_ed25519_make_key(&rng, size, &key)` | Generate | `ksm_generate()` |
| `wc_ed25519_free(&key)` | Free | `ksm_destroy()` |
| `wc_ed25519_sign_msg(msg, len, sig, &siglen, &key)` | Sign | `ksm_sign()` |
| `wc_ed25519_export_public(&key, buf, &len)` | Export pubkey | `ksm_export_pubkey()` |
| `wc_ed25519_export_private_only(&key, buf, &len)` | Export privkey | `ksm_export_wrapped()` |
| `wc_ed25519_import_private_only(buf, len, &key)` | Import privkey | `ksm_import_wrapped()` |

### Curve25519/X25519 (Optional)

| API | Purpose | Location |
|-----|---------|----------|
| `wc_curve25519_init(&key)` | Initialize | `ksm_generate()` |
| `wc_curve25519_make_key(&rng, size, &key)` | Generate | `ksm_generate()` |
| `wc_curve25519_free(&key)` | Free | `ksm_destroy()` |
| `wc_curve25519_shared_secret_ex(&priv, &peer, out, &len, endian)` | ECDH | `ksm_ecdh()` |
| `wc_curve25519_export_public_ex(&key, buf, &len, endian)` | Export pubkey | `ksm_export_pubkey()` |
| `wc_curve25519_import_public_ex(buf, len, &key, endian)` | Import pubkey | `ksm_ecdh()` |
| `wc_curve25519_export_private_raw_ex(&key, buf, &len, endian)` | Export privkey | `ksm_export_wrapped()` |
| `wc_curve25519_import_private_ex(buf, len, &key, endian)` | Import privkey | `ksm_import_wrapped()` |

## Required wolfSSL Build Options

```bash
./configure \
    --enable-keygen        # wc_MakeRsaKey, wc_ecc_make_key
    --enable-aesgcm        # AES-GCM for key wrapping
    --enable-aesctr        # AES modes
    --enable-hkdf          # Key derivation (future)
    --enable-curve25519    # X25519 support
    --enable-ed25519       # Ed25519 support
```

## API Call Flow

```
ksm_generate(ECC_P256)
    └─> wc_ecc_init()
    └─> wc_ecc_make_key()      ← key born here
    └─> store in mlock'd slot

ksm_sign(id, hash)
    └─> lookup slot
    └─> wc_ecc_sign_hash()     ← key used internally
    └─> return signature only

ksm_export_wrapped(id, wrap_key)
    └─> wc_ecc_export_private_only()  ← to temp buffer
    └─> wc_AesGcmEncrypt()            ← encrypt temp
    └─> _ksm_zero(temp)               ← secure erase
    └─> return ciphertext
```

## Constants Used

| Constant | Source | Value |
|----------|--------|-------|
| `WC_RSA_EXPONENT` | wolfcrypt/rsa.h | 65537 |
| `INVALID_DEVID` | wolfcrypt/types.h | -2 |
| `ED25519_KEY_SIZE` | wolfcrypt/ed25519.h | 32 |
| `CURVE25519_KEYSIZE` | wolfcrypt/curve25519.h | 32 |
| `EC25519_LITTLE_ENDIAN` | wolfcrypt/curve25519.h | 1 |

## Types Used

| Type | Source | Purpose |
|------|--------|---------|
| `byte` | wolfcrypt/types.h | unsigned char |
| `word32` | wolfcrypt/types.h | uint32_t |
| `WC_RNG` | wolfcrypt/random.h | RNG state |
| `ecc_key` | wolfcrypt/ecc.h | ECC keypair |
| `RsaKey` | wolfcrypt/rsa.h | RSA keypair |
| `Aes` | wolfcrypt/aes.h | AES context |
| `ed25519_key` | wolfcrypt/ed25519.h | Ed25519 keypair |
| `curve25519_key` | wolfcrypt/curve25519.h | X25519 keypair |

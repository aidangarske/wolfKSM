# wolfKSM Algorithm Examples - Implementation Plan

## Current State

### Supported by wolfKSM Core Library
From `include/wolfksm/ksm.h`:
- ✅ `KSM_TYPE_ECC_P256` - ECDSA sign + ECDH
- ✅ `KSM_TYPE_ECC_P384` - ECDSA sign + ECDH
- ✅ `KSM_TYPE_RSA_2048` - RSA sign + decrypt
- ✅ `KSM_TYPE_RSA_4096` - RSA sign + decrypt
- ✅ `KSM_TYPE_ED25519` - EdDSA signing
- ✅ `KSM_TYPE_X25519` - X25519 key exchange
- ✅ `KSM_TYPE_AES_128` - Symmetric (for wrapping)
- ✅ `KSM_TYPE_AES_256` - Symmetric (for wrapping)

### Supported by wolfSSL Integration (Crypto Callback)
From `wolfssl/wolfcrypt/ksm_cryptocb.h`:
- ✅ `wolfKSM_EccSignHash()` - ECC signing (P-256, P-384)
- ✅ `wolfKSM_EccDhAgree()` - ECDH (P-256, P-384)
- ✅ `wolfKSM_RsaSign()` - RSA signing (2048, 4096)
- ✅ `wolfKSM_RsaDecrypt()` - RSA decryption (2048, 4096)
- ❌ Ed25519 - **NOT YET EXPOSED** (needs crypto callback implementation)
- ❌ X25519 - **NOT YET EXPOSED** (needs crypto callback implementation)

### Current Example Coverage
From `examples/ksm/ksm_implicit_example.c`:
- ✅ ECC P-256 sign
- ✅ ECC P-256 ECDH
- ✅ ECC P-384 sign (via policy)
- ❌ RSA sign/decrypt
- ❌ Ed25519
- ❌ X25519
- ❌ AES wrapping demo

---

## Proposed Architecture: Multi-Algorithm Example

### Option A: Single Binary with Subcommands (RECOMMENDED)

**Structure:**
```
examples/ksm/ksm_implicit_example [all|ecc|rsa|ed25519|x25519|aes]
```

**Implementation:**
```c
// examples/ksm/ksm_implicit_example.c

int test_ecc_operations(void);
int test_rsa_operations(void);
int test_ed25519_operations(void);
int test_x25519_operations(void);
int test_aes_wrapping(void);

int main(int argc, char** argv)
{
    const char* test = (argc > 1) ? argv[1] : "all";

    wolfSSL_Debugging_ON();
    wolfKSM_SetCryptoDevCb(NULL);

    if (strcmp(test, "all") == 0 || strcmp(test, "ecc") == 0) {
        test_ecc_operations();
    }
    if (strcmp(test, "all") == 0 || strcmp(test, "rsa") == 0) {
        test_rsa_operations();
    }
    // ... etc

    wolfKSM_ClearCryptoDevCb(WOLFKSM_DEVID);
}
```

**Pros:**
- Single binary, easy to build
- Can run all tests or specific ones
- Matches your suggestion
- Easy to extend

**Cons:**
- Single file could get large (solved with good function organization)

### Option B: Separate Binaries

**Structure:**
```
examples/ksm/ksm_ecc_example
examples/ksm/ksm_rsa_example
examples/ksm/ksm_ed25519_example
examples/ksm/ksm_x25519_example
examples/ksm/ksm_aes_example
```

**Pros:**
- Each example is focused and simple
- Easy to read individual examples
- Clear separation

**Cons:**
- More Makefile complexity
- More executables to maintain
- Duplicate boilerplate code

---

## Recommended Implementation Plan

### Phase 1: Enhance Current Example (Short Term)

**Goal:** Add RSA, Ed25519, X25519 tests to `ksm_implicit_example.c`

**Step 1.1: Add RSA operations**
```c
int test_rsa_operations(void)
{
    int rc;
    byte hash[32];
    byte sig[512];
    word32 sigLen = sizeof(sig);
    byte plaintext[] = "Secret message";
    byte ciphertext[512];
    byte decrypted[512];
    word32 cipherLen = sizeof(ciphertext);
    word32 decryptLen = sizeof(decrypted);

    printf("=== RSA 2048 Operations ===\n");

    // Test implicit RSA sign
    XMEMSET(hash, 0x42, sizeof(hash));
    rc = wolfKSM_RsaSign(hash, sizeof(hash), sig, &sigLen, 2048);
    if (rc < 0) {
        printf("ERROR: RSA sign failed: %d\n", rc);
        return rc;
    }
    printf("✓ RSA-2048 signature: %u bytes\n", sigLen);

    // Test implicit RSA decrypt
    // First, we need to encrypt with the public key
    // (This would use wolfKSM_MakeRsaKey + wc_RsaPublicEncrypt)

    return 0;
}
```

**Step 1.2: Add Ed25519 operations** ⚠️ BLOCKED
- Need to implement `wolfKSM_Ed25519Sign()` in ksm_cryptocb.c first
- Or use explicit API: `wolfKSM_MakeEd25519Key()` (if it exists)

**Step 1.3: Add X25519 operations** ⚠️ BLOCKED
- Need to implement `wolfKSM_X25519SharedSecret()` in ksm_cryptocb.c first
- Or use explicit API: `wolfKSM_MakeX25519Key()` (if it exists)

**Step 1.4: Add AES wrapping demo**
```c
int test_aes_wrapping(void)
{
    int rc;
    ksm_key_id wrapKey, dataKey, restoredKey;
    byte wrapped[256];
    word32 wrappedLen = sizeof(wrapped);

    printf("=== AES Key Wrapping ===\n");

    // Generate AES wrapping key in KSM
    rc = wolfKSM_GenerateAesKey(&wrapKey, 256);

    // Generate ECC key to wrap
    rc = wolfKSM_MakeEccKey(..., &dataKey);

    // Export wrapped
    rc = ksm_export_wrapped(dataKey, wrapKey, wrapped, &wrappedLen);
    printf("✓ Key wrapped: %u bytes\n", wrappedLen);

    // Import wrapped
    rc = ksm_import_wrapped(wrapped, wrappedLen, wrapKey,
                            KSM_TYPE_ECC_P256, &restoredKey);
    printf("✓ Key restored from wrapped backup\n");

    return 0;
}
```

**Step 1.5: Update main() to support subcommands**
```c
int main(int argc, char** argv)
{
    int rc = 0;
    const char* test = (argc > 1) ? argv[1] : "all";

    printf("=================================================\n");
    printf("wolfKSM Algorithm Examples\n");
    printf("Usage: %s [all|ecc|rsa|ed25519|x25519|aes]\n", argv[0]);
    printf("=================================================\n\n");

    wolfSSL_Debugging_ON();
    rc = wolfKSM_SetCryptoDevCb(NULL);
    if (rc != 0) return rc;

    if (strcmp(test, "all") == 0 || strcmp(test, "ecc") == 0) {
        rc = test_ecc_operations();
        if (rc != 0) goto cleanup;
    }

    if (strcmp(test, "all") == 0 || strcmp(test, "rsa") == 0) {
        rc = test_rsa_operations();
        if (rc != 0) goto cleanup;
    }

    // ... more tests

cleanup:
    wolfKSM_ClearCryptoDevCb(WOLFKSM_DEVID);
    return rc;
}
```

### Phase 2: Add Missing Crypto Callback Support (Medium Term)

**Blocked algorithms that need crypto callback implementation:**

**2.1: Add Ed25519 support to ksm_cryptocb.c**
```c
// In wolfssl/wolfcrypt/src/ksm_cryptocb.c

#ifndef NO_ED25519
WOLFSSL_API int wolfKSM_Ed25519Sign(const byte* msg, word32 msgLen,
                                     byte* sig, word32* sigLen)
{
    int rc;
    ksm_key_id kid;

    // Get or generate Ed25519 key from policy
    rc = _wolfKSM_GetPolicyKey(KSM_TYPE_ED25519, &kid);
    if (rc != 0) return rc;

    // Sign using KSM
    rc = ksm_sign(kid, msg, msgLen, sig, sigLen);
    return ksm_to_wc_error(rc);
}
#endif
```

**2.2: Add X25519 support to ksm_cryptocb.c**
```c
#ifdef HAVE_CURVE25519
WOLFSSL_API int wolfKSM_X25519SharedSecret(const byte* peerPub, word32 peerLen,
                                            byte* secret, word32* secretLen)
{
    int rc;
    ksm_key_id kid;

    // Get or generate X25519 key from policy
    rc = _wolfKSM_GetPolicyKey(KSM_TYPE_X25519, &kid);
    if (rc != 0) return rc;

    // Perform ECDH using KSM
    rc = ksm_ecdh(kid, peerPub, peerLen, secret, secretLen);
    return ksm_to_wc_error(rc);
}
#endif
```

**2.3: Update crypto callback dispatcher**
```c
// In wolfKSM_CryptoDevCb(), add cases:

#ifndef NO_ED25519
case WC_ALGO_TYPE_PK:
    if (info->pk.type == WC_PK_TYPE_ED25519_SIGN) {
        // Route to KSM Ed25519 signing
    }
    break;
#endif

#ifdef HAVE_CURVE25519
case WC_ALGO_TYPE_PK:
    if (info->pk.type == WC_PK_TYPE_CURVE25519) {
        // Route to KSM X25519
    }
    break;
#endif
```

### Phase 3: Full Algorithm Support (Long Term)

**Goal:** Support ALL wolfSSL algorithms via KSM

**Algorithms to add:**
- ✅ ECC curves: P-192, P-224, P-521, secp256k1 (Bitcoin)
- ✅ RSA: 1024, 3072 bit keys
- ✅ DSA keys
- ✅ DH (Diffie-Hellman)
- ✅ Curve448 / Ed448
- ✅ Falcon (post-quantum)
- ✅ Dilithium (post-quantum)
- ✅ SPHINCS+ (post-quantum)

**Implementation approach:**
1. Extend `ksm_key_type` enum in `ksm.h`
2. Add key generation logic in `ksm_generate()`
3. Update slot structure in `ksm_internal.h`
4. Add crypto operations in `ksm.c`
5. Expose via crypto callback in `ksm_cryptocb.c`
6. Add example tests

---

## File Organization

```
examples/ksm/
├── include.am                    # Build system
├── ksm_implicit_example.c        # Main multi-algorithm example
└── README.md                     # Usage guide
```

---

## Testing Matrix

### Current Coverage (✅ = tested, ❌ = not tested)

| Algorithm | Core KSM | Crypto CB | Example | Notes |
|-----------|----------|-----------|---------|-------|
| ECC P-256 Sign | ✅ | ✅ | ✅ | Fully working |
| ECC P-256 ECDH | ✅ | ✅ | ✅ | Fully working |
| ECC P-384 Sign | ✅ | ✅ | ✅ | Fully working |
| ECC P-384 ECDH | ✅ | ✅ | ❌ | Should add |
| RSA 2048 Sign | ✅ | ✅ | ❌ | **PRIORITY** |
| RSA 2048 Decrypt | ✅ | ✅ | ❌ | **PRIORITY** |
| RSA 4096 Sign | ✅ | ✅ | ❌ | Should add |
| RSA 4096 Decrypt | ✅ | ✅ | ❌ | Should add |
| Ed25519 Sign | ✅ | ❌ | ❌ | **BLOCKED** - needs crypto CB |
| X25519 ECDH | ✅ | ❌ | ❌ | **BLOCKED** - needs crypto CB |
| AES Wrapping | ✅ | N/A | ❌ | Should add demo |

---

## Documentation Updates Needed

### 1. Update README.md
Add "Supported Algorithms" section:
```markdown
## Supported Algorithms

### Current Support (via Crypto Callback)
- **ECC:** P-256, P-384 (ECDSA sign + ECDH)
- **RSA:** 2048-bit, 4096-bit (sign + decrypt)

### Core Library Only (not yet in crypto callback)
- **Ed25519:** EdDSA signing
- **X25519:** ECDH key exchange
- **AES:** 128-bit, 256-bit (for key wrapping)

### Future Support (Planned)
- Additional ECC curves: P-192, P-224, P-521, secp256k1
- Additional RSA sizes: 1024, 3072
- Post-quantum: Falcon, Dilithium, SPHINCS+
- DH, DSA, Curve448, Ed448
```

### 2. Update CLAUDE.md
Add algorithm support matrix in the "Key Types" section.

### 3. Update example header comment
Document available subcommands:
```c
/*!
    Run:
        ./examples/ksm/ksm_implicit_example         # Run all tests
        ./examples/ksm/ksm_implicit_example ecc     # ECC only
        ./examples/ksm/ksm_implicit_example rsa     # RSA only
        ./examples/ksm/ksm_implicit_example ed25519 # Ed25519 only
        ./examples/ksm/ksm_implicit_example x25519  # X25519 only
        ./examples/ksm/ksm_implicit_example aes     # AES wrapping only
*/
```

---

## Implementation Priority

### Immediate (Can do now):
1. ✅ Add RSA sign/decrypt tests to example
2. ✅ Add AES wrapping demo to example
3. ✅ Add command-line argument parsing
4. ✅ Update documentation with algorithm support matrix

### Short-term (Needs crypto callback work):
1. ❌ Implement `wolfKSM_Ed25519Sign()` in ksm_cryptocb.c
2. ❌ Implement `wolfKSM_X25519SharedSecret()` in ksm_cryptocb.c
3. ❌ Add Ed25519/X25519 to crypto callback dispatcher
4. ❌ Add Ed25519/X25519 tests to example

### Long-term (Future expansion):
1. ❌ Add more ECC curves
2. ❌ Add post-quantum algorithms
3. ❌ Add DH, DSA support

---

## Success Criteria

**Phase 1 Complete when:**
- [ ] Example can be run with `./ksm_implicit_example all`
- [ ] Example supports `ecc`, `rsa`, `aes` subcommands
- [ ] RSA sign and decrypt are demonstrated
- [ ] AES key wrapping is demonstrated
- [ ] Documentation is updated with algorithm support matrix

**Phase 2 Complete when:**
- [ ] Ed25519 and X25519 are exposed via crypto callback
- [ ] Example supports `ed25519` and `x25519` subcommands
- [ ] All 8 wolfKSM key types have example coverage

**Phase 3 Complete when:**
- [ ] wolfKSM supports all major wolfSSL algorithms
- [ ] Examples cover all supported algorithms
- [ ] Performance benchmarks are available

# Error Handling Guide

## Error Codes

| Code | Value | Meaning | Common Cause | Remediation |
|------|-------|---------|--------------|-------------|
| KSM_SUCCESS | 0 | Operation succeeded | - | - |
| KSM_E_INVALID | -1 | Invalid parameter | NULL pointer, bad handle | Check inputs |
| KSM_E_FULL | -2 | No free key slots | 32 keys allocated | Destroy unused keys |
| KSM_E_UNSUPPORTED | -3 | Key type not supported | Build config | Rebuild with feature |
| KSM_E_MEMORY | -4 | Memory allocation failed | System OOM | Free memory |
| KSM_E_RNG | -5 | RNG failure | Entropy exhausted | Check /dev/random |
| KSM_E_CRYPTO | -6 | Crypto operation failed | wolfCrypt error | Check wolfSSL logs |
| KSM_E_BUFFER | -7 | Buffer too small | Undersized output | Increase buffer |
| KSM_E_NOT_INIT | -8 | KSM not initialized | Missing ksm_init() | Call ksm_init() |
| KSM_E_TYPE_MISMATCH | -9 | Wrong key type | Sign with AES key | Use correct key |
| KSM_E_WRAP | -10 | Wrap/unwrap failed | Wrong key, corrupted | Verify wrap key |

## Error Handling Patterns

### Basic Pattern
```c
int ret = ksm_generate(KSM_TYPE_ECC_P256, &key);
if (ret != KSM_SUCCESS) {
    fprintf(stderr, "Key generation failed: %d\n", ret);
    return ret;
}
```

### Buffer Sizing Pattern
```c
byte buf[256];
word32 len = sizeof(buf);

int ret = ksm_export_pubkey(key, buf, &len);
if (ret == KSM_E_BUFFER) {
    /* len now contains required size */
    byte* larger = malloc(len);
    ret = ksm_export_pubkey(key, larger, &len);
}
```

### Cleanup on Error
```c
ksm_key_id key1 = KSM_KEY_INVALID, key2 = KSM_KEY_INVALID;

if (ksm_generate(KSM_TYPE_ECC_P256, &key1) != KSM_SUCCESS) goto cleanup;
if (ksm_generate(KSM_TYPE_AES_256, &key2) != KSM_SUCCESS) goto cleanup;
/* ... use keys ... */

cleanup:
    if (key1 != KSM_KEY_INVALID) ksm_destroy(key1);
    if (key2 != KSM_KEY_INVALID) ksm_destroy(key2);
```

## Debugging Tips

1. **KSM_E_NOT_INIT**: Ensure `ksm_init()` called before any operation
2. **KSM_E_FULL**: Check if old keys need cleanup, or increase KSM_MAX_KEYS
3. **KSM_E_WRAP**: Verify same wrapping key used for export/import
4. **KSM_E_CRYPTO**: Enable wolfSSL debug logging

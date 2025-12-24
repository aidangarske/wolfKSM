# Wire Format Specification

## Wrapped Key Format v1

Used by `ksm_export_wrapped()` and `ksm_import_wrapped()`.

### Structure

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | type | ksm_key_type enum (big-endian) |
| 4 | 4 | data_len | Encrypted data length (big-endian) |
| 8 | 12 | iv | AES-GCM initialization vector |
| 20 | data_len | ciphertext | AES-GCM encrypted key material |
| 20+data_len | 16 | tag | AES-GCM authentication tag |

**Total size**: 36 + data_len bytes

### Encryption

- **Algorithm**: AES-GCM
- **Key**: 128-bit or 256-bit (from wrapping key)
- **IV**: 96-bit random (never reused)
- **Tag**: 128-bit authentication tag
- **AAD**: type + data_len (first 8 bytes)

### Key Material Encoding

| Key Type | Format | Typical Size |
|----------|--------|--------------|
| ECC_P256 | Raw scalar | 32 bytes |
| ECC_P384 | Raw scalar | 48 bytes |
| RSA_2048 | DER PKCS#1 | ~1190 bytes |
| RSA_4096 | DER PKCS#1 | ~2373 bytes |
| ED25519 | Raw private | 32 bytes |
| X25519 | Raw private | 32 bytes |
| AES_128 | Raw key | 16 bytes |
| AES_256 | Raw key | 32 bytes |

### Example

```
Wrapped ECC P-256 key (68 bytes total):
00 00 00 00  - type: KSM_TYPE_ECC_P256 (0)
00 00 00 20  - data_len: 32 bytes
XX XX XX XX XX XX XX XX XX XX XX XX  - 12-byte IV
[32 bytes encrypted scalar]
[16 bytes GCM tag]
```

### Security Notes

1. IV is random per export, never reused with same key
2. Type is authenticated via AAD
3. Tampering detected via GCM tag verification
4. Same key exports differently each time (random IV)

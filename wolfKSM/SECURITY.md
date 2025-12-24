# Security Policy

## Reporting Vulnerabilities

**Email**: security@wolfssl.com
**Response Time**: 48 hours for acknowledgment, 90 days for fix

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✓         |

## Security Model

wolfKSM protects private keys from:
- Memory inspection by unprivileged processes
- Swap file extraction (via mlock)
- Accidental exposure through API

wolfKSM does NOT protect against:
- Root/administrator access
- Physical memory attacks (cold boot, DMA)
- Side-channel attacks beyond wolfCrypt's mitigations
- Debugger attachment by privileged users

## Hardening Checklist

- [ ] Verify mlock succeeded (check _ksm.mem_locked after init)
- [ ] Set RLIMIT_MEMLOCK appropriately: `ulimit -l unlimited`
- [ ] Disable core dumps: `ulimit -c 0`
- [ ] Run as non-root user with minimal privileges
- [ ] Build wolfSSL with `--enable-fortress`
- [ ] Enable stack protector: `-fstack-protector-strong`
- [ ] Test wrapped key import/export integrity

## Thread Safety

**WARNING**: wolfKSM 0.1.x requires external synchronization for multi-threaded use.
All public API functions access shared global state without internal locking.

## Known Limitations

1. Maximum 32 concurrent keys (KSM_MAX_KEYS)
2. No key usage attributes or permissions
3. Sequential handle enumeration (1-32)
4. Wrapped key format not versioned

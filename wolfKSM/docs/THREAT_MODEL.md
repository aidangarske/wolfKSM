# Threat Model

## Assets Protected

| Asset | Protection Level | Notes |
|-------|------------------|-------|
| Private key bytes | HIGH | Never cross API boundary |
| Symmetric key bytes | HIGH | Never cross API boundary |
| Public keys | NONE | Freely exportable |
| Key handles | LOW | Sequential, enumerable |

## Threat Actors

### In Scope

| Actor | Capability | Mitigation |
|-------|------------|------------|
| Unprivileged process | Read /proc/pid/mem | mlock prevents swap, no direct exposure |
| Crash dump analyzer | Read core files | prctl(PR_SET_DUMPABLE, 0) recommended |
| Network attacker | Observe encrypted traffic | Keys never transmitted, only results |
| Malicious library | Call KSM APIs | Opaque handles, no raw key access |

### Out of Scope

| Actor | Why Out of Scope |
|-------|------------------|
| Root user | Can ptrace, read memory directly |
| Kernel compromise | Full memory access |
| Physical attacker | Cold boot, DMA attacks |
| Hardware attacks | Fault injection, EM analysis |

## Attack Surface

### API Attacks
- **Handle enumeration**: Handles 1-32 predictable (accepted risk)
- **Slot exhaustion**: 32 max keys, DoS possible (mitigate externally)
- **Type confusion**: Validated at every operation

### Memory Attacks
- **Swap extraction**: Mitigated by mlock (if successful)
- **Core dump**: Mitigated by PR_SET_DUMPABLE
- **Heap spray**: Static allocation, no heap for keys

### Cryptographic Attacks
- **Timing attacks**: Delegated to wolfCrypt
- **Weak RNG**: Uses wolfCrypt WC_RNG (OS entropy)
- **Key reuse**: Each key independent

## Security Properties

### Guaranteed
1. Private keys never returned by any API function
2. Destroyed keys are securely zeroed
3. Wrapped keys are authenticated (AES-GCM)
4. Invalid handles rejected before crypto operations

### Best Effort
1. Memory locking (may fail due to ulimits)
2. Core dump prevention (requires privileges)
3. Compiler-safe zeroing (tested on GCC/Clang/MSVC)

### Not Provided
1. Access control between callers
2. Key usage restrictions
3. Audit logging
4. Hardware-backed storage

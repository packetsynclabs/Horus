# Horus Security Posture

**Project**: Horus 64-bit Capability Microkernel  
**Status**: Research kernel. Boots reliably into 64-bit long mode with a functional capability-based kernel shell. Not suitable for production use.

## Security Model

Horus is designed around a strict capability model:

- All resource access is mediated by capabilities. There is no ambient authority.
- The three core invariants are enforced in the design:
  1. No code path may bypass `cap_lookup`.
  2. All authentication must go through `verify_user_password`.
  3. Any change to the user database must update the integrity tag via `users_persist()`.
- Storage uses per-block authenticated encryption (encrypt-then-MAC) with unique nonces.
- User authentication employs a strong KDF with per-user salts and a kernel pepper.
- Safety-critical policy decisions (demand paging, copy-on-write, certain FS and IPC operations) are implemented in Rust.

## Current Security Posture

The kernel has received multiple iterative security reviews during its development. The following areas have received particular attention:

- Capability minting, revocation, and cross-task scanning.
- Per-user rate limiting and lockout to resist brute-force attacks.
- Secure key derivation and zeroisation for file encryption keys.
- Audit logging of privileged operations.

## Known Limitations and Risks

The following limitations are material and should be understood by anyone reviewing or extending the kernel:

- The 64-bit port is incomplete. Large parts of the scheduler, paging, and interrupt handling retain 32-bit assumptions or are bypassed in the current long-mode path.
- There is no full per-task 4-level paging. Early tasks share an identity-mapped address space.
- Interrupt handling in long mode is rudimentary. A full 64-bit IDT with IST stacks and safe return paths is not yet implemented.
- Userspace tasks do not yet execute in ring 3 with proper isolation in the 64-bit build.
- Canonical address validation and robust user/kernel memory copying helpers are not present.
- The storage layer provides confidentiality and integrity but does not provide durability or crash consistency.
- Hardware cryptographic acceleration (AES-NI) is detected but not yet used in the primary code paths.

These gaps mean that the kernel should be treated as a research and educational artefact rather than a secure foundation for real workloads.

## Attack Surface Summary

| Area                              | Current Assessment      | Notes |
|-----------------------------------|-------------------------|-------|
| Early bootstrap (long mode)       | Strong                  | Historic triple-fault issues resolved |
| Capability system                 | Strong (design)         | Full cross-task revocation implemented |
| Kernel shell & console            | Moderate                | Runs in kernel mode |
| Storage encryption                | Strong (design)         | AEAD in place; durability missing |
| Interrupt & exception handling (64-bit) | Weak             | Minimal IDT; no IST |
| Userspace isolation               | Not yet present         | No reliable ring-3 execution in 64-bit path |

## Recommendations for Production Use

Do not use Horus in production or on untrusted hardware. Anyone considering using this code as the basis for a more secure system should first complete the remaining 64-bit porting work listed above, particularly proper per-task paging, a robust interrupt model, and comprehensive canonical address checking.

Further independent security review is strongly recommended before any sensitive use.
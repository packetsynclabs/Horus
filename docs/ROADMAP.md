# Horus Development Roadmap

This document outlines the intended direction for Horus. It is deliberately ambitious and honest about the current state of the project.

## Guiding Principles

- Security and correctness over features.
- Small, auditable codebase.
- Capability model as the primary (and ideally only) authorisation mechanism.
- Rust used for complex, safety-critical policy decisions.
- British English in all documentation and comments.

## Current State (as of late 2026)

Horus boots reliably into 64-bit long mode and provides a rich kernel shell that exercises many of the core subsystems (capabilities, storage with AEAD, user authentication, etc.).

However, the 64-bit port remains incomplete in several critical areas (see LIMITATIONS.md for details).

## Priority 1: Foundation Hardening (Current Focus)

These items are required before the kernel can be considered a solid base for further development.

### 1.1 Complete 64-bit Interrupt and Exception Subsystem (In Progress)
- Full 64-bit IDT with 16-byte gates.
- Proper IST allocation for critical exceptions (#DF, #PF, #GP, #MC, etc.).
- Two-path return (kernel vs user) in the ISR stubs.
- Safe page fault handling in long mode.
- Enable the PIT timer and basic preemption.

### 1.2 Proper Per-Task 4-Level Paging
- High-half kernel mapping.
- Per-task PML4 + recursive mapping or alternative.
- Proper `create_user_pagedir` / `switch_cr3` for 64-bit tasks.
- Guard pages and W^X enforcement.

### 1.3 Robust User Memory Access
- Canonical address validation.
- `copy_from_user` / `copy_to_user` helpers with proper bounds checking.
- Integration into all syscall paths.

## Priority 2: Userspace Execution

- Reliable ring-3 execution for 64-bit tasks (or clean IA-32e compat support).
- Basic `exec` / process creation from userspace.
- System call interface from long mode (SYSCALL/SYSRET or stable `int 0x80`).
- Simple libc or freestanding runtime for userspace programs.

## Priority 3: Capability System Maturity

- Capability sealing and object capabilities.
- Improved confinement (e.g., capability attenuation on transfer).
- Revocation handles as first-class capabilities.
- Better auditing of capability operations.

## Priority 4: Storage and Persistence

- Real journaling or write-ahead log for crash consistency.
- Proper `fsync` / durability semantics on the AEAD layer.
- Userspace filesystem server using `CAP_BLOCK_DEV` and `SYS_REGISTER_STORAGE_BACKEND`.
- Support for multiple mounted volumes.

## Priority 5: Advanced Features

- Symmetric multiprocessing (SMP) bring-up and per-CPU data.
- Hardware AES-NI acceleration in the crypto paths.
- Demand paging of executables from disk.
- Shared memory via `CAP_MEMORY_OBJECT`.
- Thread support within tasks.

## Non-Goals (At Least for the Foreseeable Future)

- POSIX compatibility layer.
- Networking stack.
- Graphics / framebuffer support.
- Filesystem formats compatible with existing operating systems.
- Support for languages that require a heavy runtime (beyond basic freestanding C/Rust).

## How to Read This Document

Items in **Priority 1** are blocking further serious work. Contributions that advance these items (especially 1.1–1.3) are the most valuable at this stage.

See `ARCHITECTURE.md` for the high-level design philosophy and `LIMITATIONS.md` for a brutally honest assessment of what currently does *not* work.
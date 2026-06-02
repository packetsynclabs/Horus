# Horus Architecture Overview

This document describes the high-level design of Horus.

## Core Philosophy

Horus follows a "capabilities or nothing" approach:

- If a task wants to do something (read a file, send a message, create another task, audit the system), it must hold a capability with the appropriate rights.
- Ambient authority is considered a design failure.
- Revocation must be reliable and reasonably efficient.

## Major Subsystems

### Capability System (`capability.c`)
- Capabilities are 128-bit values containing type, rights, object reference, and a badge.
- Cnodes are arrays of capabilities.
- Minting, attenuation, and transfer are the primary operations.
- Revocation uses a simple derivation tracking mechanism (with known scalability limits).

### Task and Scheduling Model (`scheduler.c`)
- A `tcb_t` represents a protection domain (address space + cspace + credentials).
- Scheduling is currently cooperative / round-robin in the kernel shell.
- Preemption via PIT timer is planned but not yet reliable in 64-bit mode.

### Memory Management (`paging.c`)
- Early boot uses a simple identity-mapped 4-level page table (first 1 GiB).
- Demand paging and copy-on-write infrastructure exists in skeleton form.
- Full per-task 4-level paging with high-half kernel is a major outstanding piece of work.

### Storage Stack (`storage.c`, `crypto.c`, `ata.c`)
- Block devices are abstracted behind `block_device`.
- All data is encrypted and authenticated at the 4 KiB block level using AES-128-CTR + MAC.
- Nonces are derived deterministically from inode + block index + generation.
- The on-disk format includes superblocks, inodes (with direct + indirect blocks), and directory entries.

### User Authentication
- Passwords are stored as salted hashes using a strong KDF.
- Authentication always flows through `verify_user_password`.
- Successful authentication can mint additional capabilities (e.g. via `sudo`).
- All user database mutations must go through `users_persist()` to maintain integrity tags.

### Policy Layer (Rust)
- Certain complex decisions are delegated to Rust code compiled as a `no_std` static library.
- Current users: demand paging / COW policy, some FS and IPC validation.
- C fallbacks exist when Rust is disabled.

## 64-bit Transition Strategy

Horus was originally developed with 32-bit assumptions. The ongoing 64-bit port follows these principles:

1. The kernel itself must be native 64-bit (long mode, 64-bit GDT, proper ISTs).
2. Existing 32-bit userspace binaries continue to work via IA-32e compatibility mode where possible.
3. All address fields in core structures (`tcb_t`, capability objects, etc.) now use `addr_t`.
4. Legacy 32-bit paging and IDT code is gradually being replaced rather than deleted wholesale.

## Boot Process (High Level)

1. Multiboot 2 header (32-bit entry).
2. 32-bit trampoline sets up minimal 4-level paging and jumps to long mode.
3. Early 64-bit environment (GDT with L-bit, basic exception handling).
4. `kernel_main` (64-bit) initialises subsystems and enters the kernel shell.
5. (Future) Transition to proper per-task paging and ring-3 execution.

## Known Design Tensions

- The desire for a very small TCB conflicts with the desire for rich functionality (storage server, FS, networking, etc.).
- Revocation is currently global and relatively expensive.
- The current storage encryption scheme trades some flexibility for simplicity and security.

## Further Reading

- `ROADMAP.md` — What we intend to build next.
- `LIMITATIONS.md` — What is deliberately not working or not implemented yet.
- `SECURITY.md` — Detailed security posture and remaining risks.
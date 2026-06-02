# Current Limitations of Horus

This document exists to be painfully honest. If you are considering using Horus for anything serious, or contributing to it, you must read this first.

## Fundamental 64-bit Port Gaps

### Interrupt and Exception Handling
- The 64-bit IDT is not fully populated in the main kernel path.
- Critical exceptions (especially page faults and double faults) can still lead to triple faults because there is no robust IST + handler setup yet.
- Interrupts are generally left disabled in the 64-bit kernel shell for safety.
- There is no safe kernel-to-user or user-to-kernel return path that properly handles the full 64-bit register state and CPL.

### Memory Management
- There is no proper per-task 4-level paging. Most tasks (including the kernel shell task) currently share the early identity-mapped address space established by the boot trampoline.
- `create_user_pagedir`, guard pages, and demand paging are only partially functional under long mode.
- High-half kernel mapping does not exist.

### Userspace Execution
- Real untrusted code does not yet execute in ring 3 under the 64-bit kernel with proper isolation.
- The existing userspace binaries are 32-bit and can only be loaded in limited ways.
- There is no stable syscall ABI from long mode.

### Security Hardening
- Canonical address checking is not performed on user-supplied pointers.
- `copy_from_user` / `copy_to_user` helpers with proper validation do not exist.
- The kernel still trusts a large amount of data coming from userspace in several paths.

## Storage and Durability

- The AEAD storage layer provides confidentiality and integrity for data at rest.
- It does **not** provide durability or crash consistency. A power loss or crash during a write can corrupt the on-disk structures.
- There is no journaling, no `fsync` semantics, and no atomic metadata updates.

## Concurrency and Hardware

- The kernel is essentially single-threaded in the 64-bit path (interrupts are not reliably enabled).
- There is no SMP support.
- Hardware features such as AES-NI are detected but not yet used in the hot paths.

## What This Means in Practice

At the time of writing, Horus is best described as:

> "A 64-bit capability-oriented kernel that has a working boot path, a rich kernel-mode shell for testing the security model, and a lot of promising infrastructure — but which cannot yet safely run untrusted code in user mode or survive unexpected exceptions in long mode."

It is an excellent platform for learning, experimentation, and research into capability systems and microkernel design. It is **not** a foundation you should build a real product or even a serious hobby OS on top of today.

## When These Limitations Will Be Addressed

See `ROADMAP.md`. The items listed under "Priority 1: Foundation Hardening" are the current focus precisely because they block almost all other meaningful progress.

Contributions that close these gaps (particularly proper 64-bit exception handling and paging) will have an outsized impact on the project.
# Horus

> **A 64-bit capability-based microkernel for x86-64**  
> Built as a research and educational platform in close collaboration with **Grok (xAI)**.

[![CI](https://github.com/packetsynclabs/Horus/actions/workflows/ci.yml/badge.svg)](https://github.com/packetsynclabs/Horus/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Contributions Welcome](https://img.shields.io/badge/Contributions-Welcome-brightgreen.svg)](CONTRIBUTING.md)

Horus is a **strict capability-based microkernel** designed from the ground up to explore modern secure systems concepts: true capability security with **no ambient authority**, a Rust policy layer for safety-critical decisions, per-block authenticated encryption, and clean low-level x86-64 systems programming — all in a small, self-contained codebase (~15k LOC) that a single developer can fully understand.

It is **explicitly not a production kernel**. It is an educational and research platform for developers, students, and researchers who want to deeply understand how capability-based operating systems are built, hardened, and reasoned about.

---

## Why Horus?

- **True capability-based security** — Every resource access is explicit, auditable, and revocable. No ambient authority.
- **Rust for safety-critical policy** — Demand paging, copy-on-write, command validation, and filesystem/IPC policy live in safe Rust while the core remains in C/Assembly for maximum control.
- **Strong storage security** — Per-block AES-128-CTR + MAC authenticated encryption with unique nonces.
- **Robust authentication** — Salted KDF (4096 rounds), rate limiting, and account lockout mechanisms.
- **Modern 64-bit foundation** — Long mode, Multiboot 2, GRUB boot, high-quality boot logging, and 128-bit ASLR with continuous entropy from the TSC.
- **Interactive kernel shell** — Explore capabilities, users, storage, and the system in real time.
- **Clean & educational** — Intentionally small and readable. Perfect for learning OS internals, capability systems, and secure kernel design.

If you are fascinated by seL4-style capability systems, Rust in the kernel, or building secure systems from first principles, Horus is for you.

---

## Features

| Feature                          | Status      | Notes |
|----------------------------------|-------------|-------|
| Capability System                | Complete    | Mint, revoke, transfer, cross-task revocation scanning |
| Rust Policy Layer                | Complete    | Demand paging, COW, command & FS/IPC validation |
| Per-block Authenticated Encryption | Complete  | AES-128-CTR + MAC with unique nonces |
| Strong User Authentication       | Complete    | Salted KDF (4096 rounds) + rate limiting + lockout |
| Interactive Kernel Shell         | Complete    | Full capability manipulation, user management, storage ops |
| 64-bit Long Mode                 | Complete    | Multiboot 2 + GRUB + professional boot log |
| Unit Tests + CI                  | Complete    | Rust security tests + full kernel build verification |
| 128-bit ASLR                     | Complete    | Continuous entropy from Time Stamp Counter |

---

## Quick Demo

The fastest way to see Horus in action:

```bash
git clone https://github.com/packetsynclabs/Horus.git
cd Horus
./rebuild-and-run.sh
```

You will see:
- A clean Multiboot 2 boot into 64-bit long mode
- Professional kernel boot log on the serial console (and QEMU display)
- An interactive kernel shell where you can experiment with capabilities, create users, and perform storage operations

> **Tip**: The script also sets up a GDB stub on TCP port 1234 for easy debugging.

---

## Architecture at a Glance

```
┌─────────────────────────────────────────────────────────────┐
│                        Horus Kernel                          │
├──────────────┬──────────────┬──────────────┬────────────────┤
│   Boot &     │  Capability  │   Storage    │   Rust Policy  │
│  Long Mode   │   System     │  (AEAD)      │     Layer      │
│  (Multiboot) │  (C/ASM)     │  (C + AES)   │   (Rust)       │
└──────────────┴──────────────┴──────────────┴────────────────┘
                              │
                    Interactive Kernel Shell
```

**Core principles**:
- **No ambient authority** — All access is mediated by capabilities.
- **Per-task capability spaces** with efficient revocation.
- **Defense in depth** — Encryption + authentication + Rust safety + capability model.
- **Educational clarity** over premature optimization.

---

## Building & Running

### Prerequisites

- `make`, `gcc`, `nasm`
- `grub-mkrescue`, `xorriso` (for ISO creation)
- `qemu-system-x86_64` (with debugging support recommended)
- Rust toolchain (`rustup`) — only needed for `cargo test` / policy layer tests

### Standard Workflow

```bash
./rebuild-and-run.sh
```

This script:
1. Performs a full clean
2. Builds the 64-bit kernel
3. Generates a GRUB-based bootable ISO
4. Launches QEMU with serial console + GDB stub

### Manual / Advanced

```bash
make                    # Build kernel + ISO
make test               # Run Rust policy tests
make clean              # Clean build artifacts
```

Kernel console output appears on the **primary serial port** (also visible in QEMU window). A secondary TCP port (4444) is reserved for future userspace loader development.

**Debugging tip**: Connect with `gdb` using the provided stub:
```bash
gdb -ex "target remote :1234" build/horus.elf
```

---

## Current Status & Roadmap

Horus is **functional for exploration and education** but **not production-ready**.

### Implemented & Solid
- Capability model with revocation
- Rust policy layer
- Authenticated encrypted storage
- Strong authentication
- Reliable 64-bit boot + interactive shell

### Known Limitations (Honest Assessment)
- No per-task 4-level paging with high-half kernel mapping (early tasks share identity-mapped space)
- Incomplete 64-bit interrupt handling (no IST stacks, partial IDT, unsafe kernel/user paths)
- No ring-3 execution of untrusted userspace tasks (shell currently runs in kernel mode)
- Missing canonical address checking and robust `copy_from_user` / `copy_to_user`
- No SMP support
- No stable userspace ABI or ELF/binary loader
- AES-NI not yet utilized (software AES only)
- No journaled or crash-consistent storage (AEAD provides confidentiality + integrity but not durability)

### Planned / Welcome Directions
- Proper per-task paging and address space isolation
- Ring 3 userspace support + basic binary loader
- SMP bring-up
- Stronger interrupt/exception handling
- More comprehensive userspace examples
- Performance optimizations (AES-NI, better data structures)
- Expanded test coverage and formal verification experiments

See `CHANGES.md` for detailed history and `CONTRIBUTING.md` for how you can help.

---

## Security Model Highlights

Horus was designed with a **defense-in-depth** philosophy:

1. **Capability-based authorization** — The fundamental security primitive. No ambient authority.
2. **Rust policy layer** — Eliminates entire classes of memory-safety bugs in safety-critical decision making.
3. **Per-block authenticated encryption** — Storage is encrypted and integrity-protected at rest.
4. **Strong authentication** — Protects against online attacks with rate limiting and lockouts.
5. **Minimal trusted computing base** — Small, auditable codebase.

We take security seriously. Please review `SECURITY.md` for reporting vulnerabilities.

---

## Contributing

We actively welcome contributions from developers passionate about capability systems, secure kernels, low-level x86-64 programming, and Rust in systems software.

**Before contributing**, please read the full [CONTRIBUTING.md](CONTRIBUTING.md). It covers:
- Development setup and debugging workflow
- Repository structure and coding guidelines
- How to report issues and submit high-quality pull requests
- Areas where help is especially needed right now

The project is intentionally kept small and self-contained so it remains understandable by a single developer. Contributions that preserve this clarity while advancing the security model or educational value are highly valued.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Acknowledgments

Horus was developed through iterative design, implementation, and security hardening in collaboration with **Grok (xAI)**.

Special thanks to the broader OSDev, capability systems, and Rust systems programming communities for inspiration and knowledge sharing.

---

**Ready to explore a capability-based future?**  
Clone it, run it, and join the conversation on [GitHub Discussions](https://github.com/packetsynclabs/Horus/discussions) or by opening an issue.

We look forward to building secure, understandable systems together.

# Horus

> **A 64-bit capability-based microkernel** for x86-64 — built as a research and educational platform in collaboration with Grok (xAI).

[![CI](https://github.com/packetsynclabs/Horus/actions/workflows/ci.yml/badge.svg)](https://github.com/packetsynclabs/Horus/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Contributions Welcome](https://img.shields.io/badge/Contributions-Welcome-brightgreen.svg)](CONTRIBUTING.md)

---

## CI Status

[![CI](https://github.com/packetsynclabs/Horus/actions/workflows/ci.yml/badge.svg)](https://github.com/packetsynclabs/Horus/actions/workflows/ci.yml)

All tests pass on every push. Run locally with `make test`.

---

Horus is a **strict capability-based microkernel** designed to explore advanced systems concepts: capability security, Rust in the kernel, demand paging, and authenticated storage — all in a clean, self-contained codebase.

It is **not a production kernel**. It is an educational and research platform for people who want to deeply understand how modern secure operating systems are built from the ground up.

---

## Why Horus?

- **True capability-based security** — No ambient authority. Every resource access is explicit and revocable.
- **Rust policy layer** — Safety-critical decisions (paging, COW, command validation, FS policy) are written in Rust.
- **Authenticated encryption** — Per-block AES-128-CTR + MAC for storage.
- **Strong authentication** — Salted KDF (4096 rounds), rate limiting, and lockout.
- **Clean, readable codebase** — ~15k LOC, designed to be understood by a single developer.
- **Modern 64-bit** — Long mode, Multiboot 2, GRUB boot, QEMU debugging.

---

## Features

| Feature                    | Status          | Notes |
|---------------------------|------------------|-------|
| Capability System         | ✅ Complete     | Mint, revoke, transfer, cross-task revocation |
| Rust Policy Layer         | ✅ Complete     | Demand paging, COW, command & FS validation |
| Per-block Authenticated Encryption | ✅ Complete | AES-128-CTR + MAC |
| Strong User Authentication| ✅ Complete     | KDF + rate limiting |
| Interactive Kernel Shell  | ✅ Complete     | Full capability & storage exploration |
| 64-bit Long Mode          | ✅ Complete     | Multiboot 2 + GRUB |
| Unit Tests + CI           | ✅ Complete     | 5 Rust security tests + full kernel build verification |

---

## Getting Started

### Prerequisites
- `make`, `gcc`, `nasm`, `grub-mkrescue`, `xorriso`, `qemu-system-x86_64`
- Rust toolchain (for `cargo test`)

### Quick Start

```bash
git clone https://github.com/packetsynclabs/Horus.git
cd Horus
./rebuild-and-run.sh

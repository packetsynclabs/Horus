# Horus

Horus is a 64-bit capability-based microkernel for the x86-64 architecture. It was developed from the ground up as a research project, with substantial iterative design, implementation, and security hardening performed in collaboration with Grok (xAI).

The kernel implements a strict capability model for all resource access, per-block authenticated encryption for storage, strong per-user authentication, and a Rust-based policy layer for safety-critical decisions. It boots via Multiboot 2 into long mode and provides a rich interactive kernel shell for exploration and testing.

Horus is not a production kernel. It is an educational and research platform intended for developers interested in capability systems, microkernel design, and low-level x86-64 systems programming.

## Key Features

- Strict capability-based authorisation with no ambient authority.
- Per-task capability spaces, minting, revocation, and cross-task revocation scanning.
- Per-block authenticated encryption (AES-128-CTR + MAC) for all storage, using unique nonces.
- Strong user authentication with salted KDF (4096 rounds), rate limiting, and lockout.
- Rust policy layer for demand paging, copy-on-write, and FS/IPC validation decisions.
- 128-bit ASLR with continuous entropy from the TSC.
- Rich interactive kernel shell supporting capability manipulation, user management, and storage operations.

## What Horus Currently Does

- Boots reliably on QEMU into 64-bit long mode via a Multiboot 2 header and 32-bit trampoline.
- Provides a stable 80x50 text-mode console with a professional boot log.
- Runs a fully functional kernel shell that exercises the capability system, storage stack, and user authentication.
- Supports basic block device abstraction (ATA PIO + in-memory virtual disk) with transparent encryption.
- Enforces the core security invariants around capability lookup and user database integrity.

## What Horus Does Not Do (Important Limitations)

Horus is a research kernel and is **not** suitable for production use. The following are deliberately not implemented or are only partially functional:

- Full per-task 4-level paging with high-half kernel mapping (the kernel currently shares an identity-mapped address space for early tasks).
- Proper 64-bit interrupt handling with IST stacks, complete IDT population, and safe kernel/user return paths.
- Execution of untrusted userspace tasks in ring 3 with proper isolation (the rich shell runs in kernel mode).
- Canonical address checking and robust `copy_from_user`/`copy_to_user` helpers.
- Symmetric multiprocessing (SMP) or advanced platform features beyond basic detection.
- A stable userspace ABI or loader capable of running arbitrary 64-bit binaries.
- Hardware-accelerated cryptography (AES-NI is detected but not yet used in the main paths).
- Journalled or crash-consistent storage (the AEAD layer provides confidentiality and integrity but not durability across crashes).

These limitations are documented honestly so that developers can understand exactly where the current boundaries lie.

## Building and Running

The recommended way to build and run Horus is:

```bash
./rebuild-and-run.sh
```

This script performs a full clean, builds the 64-bit kernel and a GRUB-based ISO, cleans up any stale network ports, and launches QEMU with appropriate debugging flags.

The kernel console appears on the primary serial port. A secondary TCP port (4444) is available for the userspace loader if required.

## Contributing

Horus remains a research project. The codebase is intentionally small and self-contained so that the entire system can be understood by a single developer. Contributions that improve the 64-bit port, add proper per-task paging, or strengthen the capability model are particularly welcome.

Please review the limitations section above before submitting changes.

## Licence

See the LICENSE file for details.
## Unit Testing & CI (NEW)
Complete setup added with `make test`, GitHub Actions CI, and `tests/` directory.
All security invariants (capability rights, isolation, COW, command validation) are now continuously tested.

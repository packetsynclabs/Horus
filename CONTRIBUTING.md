# Contributing to Horus

Thank you for your interest in Horus!  

We welcome contributions from developers who are passionate about **capability-based security**, **microkernel design**, **low-level x86-64 systems programming**, **Rust in the kernel**, and building secure systems that prioritize clarity and auditability.

Horus is intentionally kept **small and self-contained** (~15k LOC) so that a single motivated developer can fully understand the entire codebase. We value contributions that respect this philosophy while advancing the project's security model, educational value, or implementation quality.

---

## Code of Conduct

Be respectful, constructive, and inclusive. We follow the spirit of the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct) and expect everyone to help maintain a welcoming environment for learning and collaboration.

Harassment or toxic behavior will not be tolerated.

---

## Development Environment Setup

### Prerequisites

You will need:

- **Build tools**: `make`, `gcc` (cross-compiler friendly), `nasm`
- **Bootloader tools**: `grub-mkrescue`, `xorriso`
- **Emulator**: `qemu-system-x86_64` (with GDB stub support strongly recommended)
- **Rust toolchain**: `rustup` (stable) — required only for running the policy layer tests (`cargo test`)
- **Debugger** (optional but highly recommended): `gdb` or `gdb-multiarch`

On Debian/Ubuntu:

```bash
sudo apt update
sudo apt install build-essential nasm grub-common xorriso qemu-system-x86 gdb
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

On macOS (with Homebrew):

```bash
brew install nasm grub xorriso qemu gdb
```

### Quick Verification

After cloning:

```bash
git clone https://github.com/packetsynclabs/Horus.git
cd Horus
./rebuild-and-run.sh
```

You should see the kernel boot in QEMU and drop into the interactive shell.

### Debugging Workflow (Recommended)

The `rebuild-and-run.sh` script already launches QEMU with a GDB stub on port **1234**.

Connect from another terminal:

```bash
gdb -ex "target remote :1234" -ex "symbol-file build/horus.elf"
```

Useful GDB commands:
- `break kmain`
- `continue`
- `info registers`
- `x/10i $rip` (disassemble)

Kernel messages appear on the **serial console** (visible in QEMU and via `-serial` if you customize the script).

---

## Repository Structure

```
Horus/
├── include/          # C header files (architecture, capability, storage, etc.)
├── src/              # Core kernel implementation (C + Assembly)
│   ├── boot/         # Multiboot 2 entry, long-mode transition, early setup
│   ├── cap/          # Capability system implementation
│   ├── storage/      # Block device, ATA PIO, encryption layer
│   ├── shell/        # Interactive kernel shell
│   └── ...
├── rust/             # Rust policy layer (compiled to staticlib and linked)
│   ├── src/          # Rust crates for paging policy, COW, validation, etc.
│   └── Cargo.toml
├── userspace/        # Placeholder for future userspace components & examples
├── tools/            # Build scripts, generators, or analysis tools
├── linker.ld         # 32-bit linker script (early boot)
├── linker64.ld       # Primary 64-bit linker script
├── grub.cfg          # GRUB configuration for the bootable ISO
├── Makefile          # Main build orchestration
├── rebuild-and-run.sh# One-command clean → build → QEMU launch
├── README.md
├── CONTRIBUTING.md
├── SECURITY.md
├── CHANGES.md
└── LICENSE
```

**Key insight**: The Rust policy layer is deliberately small and focused. Most of the kernel remains in C/Assembly for fine-grained control and to keep the trusted computing base understandable.

---

## Coding Guidelines & Style

### General Principles

- **Clarity over cleverness**. Code should be readable by someone new to the project in a reasonable time.
- **Security first**. Every change must preserve (or strengthen) the capability model and security invariants.
- **Small, focused changes**. Prefer many small, reviewable PRs over large monolithic ones.
- **Document intent**. Especially around security decisions, capability handling, and unsafe Rust blocks.

### Language-Specific

**C / Assembly**
- Follow existing style in `src/` and `include/`.
- Use clear naming (`cap_` prefix for capability functions, etc.).
- Minimize global state.
- Comment non-obvious assembly sequences and why certain instructions are used.
- Avoid undefined behavior — be explicit about memory ordering and volatile access where needed.

**Rust (policy layer)**
- Idiomatic Rust where possible.
- Use `unsafe` only when absolutely necessary and document the safety invariants clearly.
- Prefer `Result`/`Option` for fallible operations.
- Keep the Rust surface small — it is a *policy* layer, not a full kernel rewrite.

**Commit Messages**
- Use conventional style: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`
- Example: `feat(cap): implement cross-task revocation scanning`
- Reference issues when relevant: `Closes #42`

---

## How to Contribute

### 1. Reporting Bugs or Security Issues

- Use **GitHub Issues** for bugs.
- For **security vulnerabilities**, follow the process in `SECURITY.md` (do **not** open a public issue).
- Include:
  - Steps to reproduce
  - Expected vs actual behavior
  - QEMU version, host OS, and any relevant logs
  - If possible, a minimal patch or test case

### 2. Suggesting Features or Improvements

We are especially interested in contributions that align with the project's educational and security goals.

Good areas right now (see also the Roadmap in README):
- Proper per-task 4-level paging and high-half kernel mapping
- Ring-3 userspace task support + basic ELF loader
- SMP initialization and per-CPU data structures
- Improved interrupt/exception handling (IST stacks, proper IDT)
- Robust `copy_from_user` / `copy_to_user` helpers + canonical address checking
- AES-NI acceleration for the encryption layer
- Journaling or crash-consistency for storage
- Expanded userspace examples and test programs
- Better documentation, diagrams, or educational materials
- Additional unit/integration tests for the capability system and policy layer

Before starting large work, please open an issue or start a **GitHub Discussion** so we can align on design.

### 3. Pull Request Process

1. Fork the repository and create a feature branch from `main`.
2. Make focused, atomic commits.
3. Ensure `make` and `make test` still pass.
4. Update documentation (README, code comments, or new docs) if behavior or interfaces change.
5. Open a Pull Request with a clear description:
   - What problem it solves
   - How it was tested
   - Any trade-offs or future work
6. Be responsive to review feedback. We aim for constructive, timely reviews.

We may ask for changes to keep the codebase clean and the security model consistent. This is normal and helps maintain the project's high standards.

---

## Testing

- Run the full test suite: `make test` (runs Rust policy tests + build verification)
- Manually test in QEMU after significant changes (especially capability handling, shell commands, and storage).
- Consider adding new tests when you add functionality to the Rust policy layer or core invariants.

CI runs on every push — keep it green.

---

## Communication & Getting Help

- **GitHub Discussions** — Best place for design questions, ideas, and general chat.
- **GitHub Issues** — Bug reports and concrete feature requests.
- We are a small project. Response times may vary, but we genuinely appreciate thoughtful contributions.

---

## Recognition

All contributors will be acknowledged in `CHANGES.md` (or a future `AUTHORS` file). Significant contributions may also be highlighted in release notes or blog posts.

Even small improvements — better comments, documentation fixes, or test cases — are valuable and welcomed.

---

## Final Notes

Horus exists to help people **understand** secure system design, not to compete with production kernels like seL4. We prioritize:

- Educational clarity
- Strong, auditable security invariants
- A codebase that remains approachable

If your contribution helps more people learn about capability systems, Rust policy layers, or low-level kernel construction while keeping these principles intact, it will be enthusiastically received.

Thank you for helping build Horus. We look forward to your ideas and code!

— The Horus maintainers

---

**Questions?** Open a Discussion or Issue. We're here to help you contribute successfully.

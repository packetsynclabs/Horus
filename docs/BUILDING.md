# Building and Running Horus

## Prerequisites

- GCC targeting x86-64
- GNU Make
- QEMU (`qemu-system-x86_64`)
- GRUB tools (`grub-mkrescue`, `xorriso` or equivalent)
- `netcat` (optional, for the userspace loader)

## Quick Start

```bash
./rebuild-and-run.sh
```

This script will:
1. Clean all build artefacts (including Rust).
2. Build the 64-bit kernel.
3. Create a GRUB bootable ISO.
4. Kill any process holding the loader port (4444).
5. Launch QEMU with sensible debugging flags.

## Manual Build

```bash
make clean
make BITS=64
make boot.iso
```

To run without the helper script:

```bash
qemu-system-x86_64 -m 512M -cpu qemu64,+aes \
    -cdrom boot.iso \
    -nographic \
    -chardev stdio,id=char0,signal=off \
    -serial chardev:char0 \
    -serial tcp:localhost:4444,server,nowait,nodelay \
    -monitor none \
    -net none
```

## 32-bit vs 64-bit Builds

- `make BITS=64` (default): 64-bit kernel (recommended).
- `make BITS=32`: Legacy 32-bit build (mostly for comparison and transition testing).

## Rust Policy Layer

The kernel can be built with or without the Rust components:

```bash
make RUST_ENABLED=1 BITS=64     # With Rust (default in most workflows)
make RUST_ENABLED=0 BITS=64     # Pure C fallbacks only
```

When Rust is enabled, certain policy decisions (demand paging, COW, some validation) are made by the Rust code in `rust/src/lib.rs`.

## Debugging

The kernel is usually run with `-d int,cpu_reset,guest_errors` during development. Serial output is the primary console.

For more invasive debugging, GDB can be attached using QEMU's `-s -S` flags.

## Common Issues

- "grub-mkrescue not found": Install `grub-pc-bin` (Debian/Ubuntu) or the equivalent `grub2` package on your distribution.
- Port 4444 already in use: The `rebuild-and-run.sh` script attempts to kill stale listeners, but you may need to run `fuser -k -n tcp 4444` manually.
- Triple faults on boot: This almost always indicates a problem in the early long-mode environment (GDT, paging, or IDT). Check the serial output for the last successful marker before the fault.
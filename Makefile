CC     = gcc
LD     = ld
AS     = gcc

# ===================== 64-bit x86-64 is now the primary target =====================
# The kernel has transitioned to full 64-bit.
# To force 32-bit (legacy): make BITS=32
BITS ?= 64

ifeq ($(BITS),32)
    # Legacy 32-bit i386 (only for transition/testing)
    CFLAGS = -m32 -ffreestanding -fno-pic -fno-pie -fno-stack-protector \
             -Wall -Wextra -Werror -Wformat -Wformat-security -O2 -pipe \
             -I src/include -std=gnu99 -fno-builtin

    ASFLAGS = -m32 -ffreestanding -fno-pic -fno-pie -x assembler-with-cpp -c

    LDFLAGS = -T linker.ld -m elf_i386 -nostdlib -static
    RUST_TARGET ?= i686-unknown-linux-gnu
else
    # 64-bit x86-64 (default, long mode)
    CFLAGS = -m64 -ffreestanding -fno-pic -fno-pie -fno-stack-protector \
             -Wall -Wextra -Werror -Wformat -Wformat-security -O2 -pipe \
             -I src/include -std=gnu99 -fno-builtin -mcmodel=kernel

    ASFLAGS = -m64 -ffreestanding -fno-pic -fno-pie -x assembler-with-cpp -c

    LDFLAGS = -T linker64.ld -m elf_x86_64 -nostdlib -static
    RUST_TARGET ?= x86_64-unknown-none
endif
# ============================================================================

OBJS = src/boot/multiboot.o \
       src/kernel/terminal.o \
       src/kernel/main.o \
       src/kernel/gdt.o \
       src/kernel/idt.o \
       src/kernel/paging.o \
       src/kernel/capability.o \
       src/kernel/scheduler.o \
       src/kernel/syscall.o \
       src/kernel/ramfs.o \
       src/kernel/storage.o \
       src/kernel/crypto.o \
       src/kernel/ata.o

# 64-bit support
ifeq ($(BITS),64)
    OBJS += src/boot/entry64.o
    OBJS += src/kernel/lowlevel64.o
else
    OBJS += src/kernel/lowlevel.o
endif

all: kernel.elf

RUST_ENABLED ?= 1  # Rust is now the standard for safety-critical paths
# RUST_TARGET is set dynamically above based on BITS
RUST_LIB    := rust/target/$(RUST_TARGET)/release/libhorus_shell.a

.PHONY: rust
rust:
	cargo build --manifest-path rust/Cargo.toml --release --target $(RUST_TARGET)

with-rust:
	$(MAKE) RUST_ENABLED=1

ifeq ($(RUST_ENABLED),1)
  RUST_EXTRA_OBJS := src/kernel/rust_memory_stubs.o
else
  RUST_EXTRA_OBJS := src/kernel/rust_shims.o
endif

ifeq ($(RUST_ENABLED),1)
  LINK_LIST = $(RUST_LIB) $(OBJS)
else
  LINK_LIST = $(OBJS) $(RUST_EXTRA_OBJS)
endif

ifeq ($(RUST_ENABLED),1)
kernel.elf: $(RUST_LIB) $(OBJS) $(RUST_EXTRA_OBJS)
else
kernel.elf: $(OBJS) $(RUST_EXTRA_OBJS)
endif
ifeq ($(RUST_ENABLED),1)
	$(LD) $(LDFLAGS) -o $@ --whole-archive $(RUST_LIB) --no-whole-archive $(OBJS) $(RUST_EXTRA_OBJS)
else
	$(LD) $(LDFLAGS) -o $@ $(LINK_LIST)
endif

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(AS) $(ASFLAGS) $< -o $@

src/kernel/rust_shims.o: src/kernel/rust_shims.c
	$(CC) $(CFLAGS) -c $< -o $@

src/kernel/rust_stubs.o: src/kernel/rust_stubs.c
	$(CC) $(CFLAGS) -c $< -o $@

src/kernel/rust_memory_stubs.o: src/kernel/rust_memory_stubs.c
	$(CC) $(CFLAGS) -c $< -o $@

src/kernel/storage.o: src/kernel/storage.c
	$(CC) $(CFLAGS) -c $< -o $@

src/kernel/crypto.o: src/kernel/crypto.c
	$(CC) $(CFLAGS) -msse2 -maes -c $< -o $@

src/kernel/ata.o: src/kernel/ata.c
	$(CC) $(CFLAGS) -c $< -o $@

ifeq ($(RUST_ENABLED),1)
$(RUST_LIB): rust/src/lib.rs rust/Cargo.toml
	@cargo build --manifest-path rust/Cargo.toml --release --target $(RUST_TARGET)
	@test -f $(RUST_LIB) || (echo "ERROR: $(RUST_LIB) not found"; exit 1)
endif

# --------------------------------------------------------------------
# Run target - now properly handles 32-bit vs 64-bit
# For 64-bit we boot via GRUB (required by modern QEMU for direct 64-bit ELFs)
# --------------------------------------------------------------------

run: kernel.elf
	@echo "Horus: main shell on this terminal; loader on :4444 (second term only)"
	@echo "  cat userspace/shell.bin | nc localhost 4444   (or cd userspace; cat shell.bin | nc ...)"
ifeq ($(BITS),64)
	@echo "  (64-bit kernel - booting via GRUB)"
	@echo "  (HEAVY DEBUG: -d int,cpu_reset,guest_errors,unimp -no-reboot -no-shutdown)"
	@$(MAKE) --no-print-directory boot.iso
	qemu-system-x86_64 -m 512M \
		-cpu qemu64,+aes \
		-nographic \
		-chardev stdio,id=char0,signal=off \
		-serial chardev:char0 \
		-serial tcp:localhost:4444,server,nowait,nodelay \
		-monitor none \
		-device isa-debug-exit,iobase=0x604,iosize=0x04 \
		-net none \
		-d int,cpu_reset,guest_errors,unimp \
		-no-reboot -no-shutdown \
		-cdrom boot.iso
else
	qemu-system-i386 -kernel kernel.elf -m 512M \
		-cpu qemu64,+aes \
		-nographic \
		-chardev stdio,id=char0,signal=off \
		-serial chardev:char0 \
		-serial tcp:localhost:4444,server,nowait,nodelay \
		-monitor none \
		-device isa-debug-exit,iobase=0x604,iosize=0x04 \
		-no-reboot \
		-net none
endif

# Create a GRUB-bootable ISO for 64-bit (Multiboot2)
boot.iso: kernel.elf grub.cfg
	@echo "Creating GRUB bootable ISO (64-bit)..."
	@rm -rf isofiles
	@mkdir -p isofiles/boot/grub
	@cp kernel.elf isofiles/boot/kernel.elf
	@cp kernel.elf isofiles/kernel.elf          # also at ISO root as fallback
	@cp grub.cfg isofiles/boot/grub/grub.cfg
	@grub-mkrescue -o $@ isofiles 2>&1 || \
		( echo "ERROR: grub-mkrescue failed to create ISO." && \
		  echo "Please install the required tools:" && \
		  echo "  Debian/Ubuntu: sudo apt install grub-pc-bin xorriso" && \
		  echo "  Fedora:         sudo dnf install grub2-pc-modules xorriso" && \
		  exit 1 )
	@rm -rf isofiles
	@echo "Created boot.iso successfully"

clean: userspace-clean
	rm -f kernel.elf
	rm -f src/boot/*.o src/kernel/*.o
	rm -f src/kernel/rust_shims.o
	rm -f src/kernel/rust_stubs.o
	rm -f src/kernel/rust_memory_stubs.o
	rm -rf rust/target

clean-rust:
	rm -rf rust/target
	@echo "Rust build cache cleaned."

iso: kernel.elf
	mkdir -p iso/boot/grub
	cp kernel.elf iso/boot/
	cp grub.cfg iso/boot/grub/grub.cfg
	grub-mkrescue -o horus.iso iso 2>/dev/null || echo "grub-mkrescue not found, ISO skipped"

USERSPACE_CFLAGS = -m32 -ffreestanding -fno-pic -fno-pie -fno-stack-protector \
                   -Wall -Wextra -O2 -I include -std=gnu99 -fno-builtin

userspace/%.o: userspace/%.c
	$(CC) $(USERSPACE_CFLAGS) -c $< -o $@

userspace/%.elf: userspace/%.o
	$(LD) -m elf_i386 -Ttext=0x400000 -o $@ $<

# Produce a true flat binary (raw code+data, no ELF headers or metadata).
# The loader expects the payload to be directly executable starting at the
# load base, with hdr.entry as the byte offset into the payload.
userspace/%.raw: userspace/%.elf
	objcopy -O binary $< $@

tools/mkheadered: tools/mkheadered.c
	$(CC) -o $@ $<

userspace/%.bin: userspace/%.raw tools/mkheadered
	@name="$$(basename $@ .bin)"; \
	./tools/mkheadered $< $@ "$$name"

userspace: userspace/shell.bin userspace/hello.bin userspace/fs_server.bin
	@echo "Userspace ready. From root: cat userspace/shell.bin | nc localhost 4444"

userspace-clean:
	rm -f userspace/*.o userspace/*.elf userspace/*.raw userspace/*.bin tools/mkheadered
	rm -f userspace/*.o userspace/*.elf userspace/*.raw userspace/*.bin

#!/usr/bin/env bash
#
# Horus Rebuild & Run Script
# ==========================
#
# This script performs a complete clean + rebuild + run cycle for the Horus kernel.
# It is the recommended way to iterate while developing.
#
# Usage:
#   ./rebuild-and-run.sh
#
# It will:
#   1. Clean Rust build cache
#   2. Full clean (C objects + kernel.elf + userspace)
#   3. Build the kernel (with Rust enabled by default)
#   4. Build userspace programs
#   5. Kill any stale process on the loader port (4444), then launch QEMU via "make run"
#
# The loader port cleanup makes repeated runs much more pleasant.
#
# Stop with Ctrl+C (QEMU will exit cleanly because we use chardev stdio + signal=off)

set -euo pipefail

# Colors for nice output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Horus Full Rebuild & Run ===${NC}"
echo

# Ensure we're in the project root
if [[ ! -f "Makefile" ]]; then
    echo -e "${RED}Error: Makefile not found. Please run this script from the Horus project root.${NC}"
    exit 1
fi

echo -e "${YELLOW}[1/5] Cleaning Rust cache...${NC}"
make clean-rust

echo -e "${YELLOW}[2/5] Full clean...${NC}"
make clean

echo -e "${YELLOW}[3/5] Building kernel (Rust enabled, 64-bit)...${NC}"
make BITS=64 -j"$(nproc 2>/dev/null || echo 4)"

echo -e "${YELLOW}[4/5] Building userspace...${NC}"
make BITS=64 userspace

echo -e "${YELLOW}[5/5] Launching QEMU...${NC}"

# Clean up any stale process holding the loader port (4444).
# This prevents the common "Address already in use" error when re-running the script.
if command -v fuser >/dev/null 2>&1; then
    fuser -k -n tcp 4444 2>/dev/null || true
elif command -v lsof >/dev/null 2>&1; then
    lsof -t -i:4444 2>/dev/null | xargs -r kill -9 2>/dev/null || true
fi
sleep 0.4   # Give the kernel a moment to release the port

echo -e "${GREEN}Starting Horus. Use Ctrl+C to stop.${NC}"

echo -e "  ${YELLOW}(64-bit kernel - booting via GRUB with heavy debug)${NC}"
echo
echo -e "  Loader is on :4444 — in another terminal run:"
echo -e "    ${YELLOW}cat userspace/shell.bin | nc localhost 4444${NC}"
echo

make BITS=64 run || true   # QEMU exit (Ctrl+C or isa-debug-exit) is normal; don't fail the script on it

#include "kernel.h"

/* Very basic ATA PIO driver for primary master (QEMU IDE emulation).
 * This is a starting point for real persistent storage.
 */

#define ATA_DATA       0x1F0
#define ATA_ERROR      0x1F1
#define ATA_SECCOUNT   0x1F2
#define ATA_LBA_LOW    0x1F3
#define ATA_LBA_MID    0x1F4
#define ATA_LBA_HIGH   0x1F5
#define ATA_DRIVE      0x1F6
#define ATA_STATUS     0x1F7
#define ATA_COMMAND    0x1F7
#define ATA_CTRL       0x3F6

#define ATA_CMD_READ   0x20
#define ATA_CMD_WRITE  0x30

/* Use the kernel's existing inb/outb from lowlevel */
static inline uint16_t inw(uint16_t port) {
    uint16_t val;
    __asm__ volatile ("inw %1, %0" : "=a"(val) : "d"(port));
    return val;
}

static inline void outw(uint16_t port, uint16_t val) {
    __asm__ volatile ("outw %0, %1" : : "a"(val), "d"(port));
}

static void ata_wait_busy(void) {
    while (inb(ATA_STATUS) & 0x80) { /* busy */ }
}

static void ata_400ns_delay(void) {
    for (int i = 0; i < 4; i++) inb(ATA_CTRL);
}

static int ata_read_sector(uint32_t lba, uint8_t *buf) {
    ata_wait_busy();
    ata_400ns_delay();

    outb(ATA_DRIVE, 0xE0 | ((lba >> 24) & 0x0F));
    outb(ATA_SECCOUNT, 1);
    outb(ATA_LBA_LOW,  lba & 0xFF);
    outb(ATA_LBA_MID,  (lba >> 8) & 0xFF);
    outb(ATA_LBA_HIGH, (lba >> 16) & 0xFF);
    outb(ATA_COMMAND, ATA_CMD_READ);

    ata_wait_busy();
    ata_400ns_delay();

    uint8_t status = inb(ATA_STATUS);
    if (status & 0x01) return -1; /* error bit */

    for (int i = 0; i < 256; i++) {
        uint16_t data = inw(ATA_DATA);
        buf[i*2 + 0] = data & 0xFF;
        buf[i*2 + 1] = data >> 8;
    }
    return 0;
}

static int ata_write_sector(uint32_t lba, const uint8_t *buf) {
    ata_wait_busy();
    ata_400ns_delay();

    outb(ATA_DRIVE, 0xE0 | ((lba >> 24) & 0x0F));
    outb(ATA_SECCOUNT, 1);
    outb(ATA_LBA_LOW,  lba & 0xFF);
    outb(ATA_LBA_MID,  (lba >> 8) & 0xFF);
    outb(ATA_LBA_HIGH, (lba >> 16) & 0xFF);
    outb(ATA_COMMAND, ATA_CMD_WRITE);

    ata_wait_busy();
    ata_400ns_delay();

    for (int i = 0; i < 256; i++) {
        uint16_t data = buf[i*2 + 0] | (buf[i*2 + 1] << 8);
        outw(ATA_DATA, data);
    }

    ata_wait_busy();
    ata_400ns_delay();

    uint8_t status = inb(ATA_STATUS);
    if (status & 0x01) return -1;

    return 0;
}

/* Read a 4KiB block (8 sectors) */
static int ata_read_block(struct block_device *bd, uint64_t block, void *buf) {
    (void)bd;
    uint8_t *b = buf;
    for (int i = 0; i < 8; i++) {
        if (ata_read_sector(block * 8 + i, b + i * 512) != 0)
            return -1;
    }
    return 0;
}

static int ata_write_block(struct block_device *bd, uint64_t block, const void *buf) {
    (void)bd;
    const uint8_t *b = buf;
    for (int i = 0; i < 8; i++) {
        if (ata_write_sector(block * 8 + i, b + i * 512) != 0)
            return -1;
    }
    return 0;
}

/* Real ATA block device - now fully functional */
struct block_device ata0 = {
    .name = "ata0",
    .total_blocks = 1024 * 1024, /* 4 GiB placeholder */
    .read_block  = ata_read_block,
    .write_block = ata_write_block,
    .private = NULL,
};

void ata_init(void) {
    /* Probing and registration now narrated from kernel_main for consistent boot styling */
    outb(ATA_DRIVE, 0xA0);
    ata_400ns_delay();

    uint8_t status = inb(ATA_STATUS);
    if (status == 0xFF) {
        return;
    }

    storage_set_default_device(&ata0);
}

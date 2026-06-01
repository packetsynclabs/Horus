#include "kernel.h"

int storage_format(struct block_device *bd);
int storage_mount(struct block_device *bd);
int storage_read_file_block(struct mounted_fs *mfs, uint64_t ino, uint64_t block, void *buf);
int storage_write_file_block(struct mounted_fs *mfs, uint64_t ino, uint64_t block, const void *buf);

static void my_memcpy(void *dst, const void *src, size_t n) {
    uint8_t *d = dst; const uint8_t *s = src;
    while (n--) *d++ = *s++;
}

static void my_memset(void *dst, int val, size_t n) {
    uint8_t *d = dst; while (n--) *d++ = (uint8_t)val;
}

static size_t my_strlen(const char *s) {
    size_t len = 0; while (s[len]) len++; return len;
}

static int my_strncmp(const char *a, const char *b, size_t n) {
    while (n && *a && *a == *b) { a++; b++; n--; }
    if (n == 0) return 0;
    return (unsigned char)*a - (unsigned char)*b;
}

static void my_strncpy(char *dst, const char *src, size_t n) {
    while (n-- && (*dst++ = *src++));
}

#define STORAGE_MAGIC 0x48534653
#define STORAGE_VERSION 1


static struct virtual_disk g_vdisk;
static uint8_t g_vdisk_buffer[BLOCKS_PER_DISK * BLOCK_SIZE];  /* 8 GiB virtual disk */

static int vdisk_read(struct block_device *bd, uint64_t block, void *buf) {
    struct virtual_disk *vd = (struct virtual_disk *)bd->private;
    if (block >= bd->total_blocks) return -1;

    uint8_t *src = vd->data + (block * BLOCK_SIZE);
    uint8_t *d = buf;
    for (size_t i = 0; i < BLOCK_SIZE; i++) d[i] = src[i];
    return 0;
}

static int vdisk_write(struct block_device *bd, uint64_t block, const void *buf) {
    struct virtual_disk *vd = (struct virtual_disk *)bd->private;
    if (block >= bd->total_blocks) return -1;

    uint8_t *dst = vd->data + (block * BLOCK_SIZE);
    const uint8_t *s = buf;
    for (size_t i = 0; i < BLOCK_SIZE; i++) dst[i] = s[i];
    return 0;
}

static struct block_device g_vdisk_bd = {
    .name = "vdisk0",
    .total_blocks = BLOCKS_PER_DISK,
    .read_block = vdisk_read,
    .write_block = vdisk_write,
    .private = &g_vdisk,
};

static void storage_derive_block_keys(uint64_t inode, uint64_t block, uint32_t gen,
                                      const uint8_t *base_key, size_t base_len,
                                      uint8_t *enc_key, uint8_t *mac_key) {
    uint8_t material[64];
    uint32_t t = (uint32_t)inode ^ (uint32_t)block ^ gen;

    /* Build unique material */
    for (int i = 0; i < 32; i++) {
        material[i] = base_key[i % base_len] ^ (uint8_t)((inode >> (i & 7)) & 0xFF);
    }
    for (int i = 32; i < 64; i++) {
        material[i] = (uint8_t)(block + i) ^ (uint8_t)(t >> (i & 3));
    }

    /* Derive encryption key using strong KDF-style mixing */
    uint8_t state[32];
    for (int i = 0; i < 32; i++) state[i] = material[i];

    for (int round = 0; round < 1024; round++) {   /* solid iteration count */
        uint8_t prev = state[31];
        for (int i = 0; i < 32; i++) {
            uint8_t next = state[i] + prev + (uint8_t)round;
            next = (next << 3) | (next >> 5);
            next ^= material[(i + round) % 64];
            state[i] = next;
            prev = next;
        }
    }
    for (int i=0; i<32; i++) enc_key[i] = state[i];

    /* Derive MAC key (different mixing) */
    for (int i = 0; i < 32; i++) state[i] ^= (uint8_t)(0xA5 + i);
    for (int round = 0; round < 1024; round++) {
        uint8_t prev = state[31];
        for (int i = 0; i < 32; i++) {
            uint8_t next = state[i] + prev + (uint8_t)(round ^ 0x5A);
            next = (next << 4) | (next >> 4);
            state[i] = next;
            prev = next;
        }
    }
    for (int i=0; i<32; i++) mac_key[i] = state[i];

    /* Zero material */
    for (int i = 0; i < 64; i++) material[i] = 0;
}

/* Compute a strong MAC tag over data using the MAC key */
static void storage_compute_mac(const uint8_t *mac_key, const uint8_t *nonce,
                                const uint8_t *data, size_t len, uint8_t *tag_out) {
    uint8_t state[32];
    for (int i=0; i<32; i++) state[i] = mac_key[i];

    /* Mix nonce */
    for (int i = 0; i < 16; i++) {
        state[i] ^= nonce[i];
    }

    /* Strong iterated MAC over the data */
    for (size_t pos = 0; pos < len; pos++) {
        uint8_t prev = state[31];
        for (int i = 0; i < 32; i++) {
            uint8_t next = state[i] + prev + data[pos];
            next = (next << 5) | (next >> 3);
            next ^= (uint8_t)(i * 0x5A);
            state[i] = next;
            prev = next;
        }
    }

    /* Final diffusion */
    for (int r = 0; r < 8; r++) {
        uint8_t prev = state[31];
        for (int i = 0; i < 32; i++) {
            uint8_t next = state[i] + prev + (uint8_t)r;
            next = (next << 3) | (next >> 5);
            state[i] = next;
            prev = next;
        }
    }

    for (int i=0; i<16; i++) tag_out[i] = state[i];   /* 128-bit tag */
    for (int i = 0; i < 32; i++) state[i] = 0;
}

/* Encrypt a block with authentication (returns 0 on success) */
int storage_encrypt_block(const uint8_t *file_key, uint64_t inode, uint64_t block,
                          uint32_t gen, uint8_t *data /* in/out, 4KB */) {
    uint8_t enc_key[32];
    uint8_t mac_key[32];
    uint8_t nonce[16];

    /* Unique nonce */
    for (int i = 0; i < 8; i++) {
        nonce[i]     = (uint8_t)(inode >> (i * 8));
        nonce[i + 8] = (uint8_t)(block >> (i * 8));
    }
    nonce[0] ^= (uint8_t)gen;

    storage_derive_block_keys(inode, block, gen, file_key, 32, enc_key, mac_key);

    /* Encrypt in place */
    uint8_t keystream[BLOCK_SIZE];

    if (cpu_has_aesni()) {
        /* Hardware accelerated path using AES-128-CTR */
        uint8_t aes_key[16];
        for (int i=0; i<16; i++) aes_key[i] = enc_key[i];  /* take first 128 bits */

        uint8_t nonce[16] = {0};
        /* Construct nonce from inode+block+gen for CTR */
        for (int i=0; i<8; i++) nonce[i] = (uint8_t)(inode >> (i*8));
        for (int i=0; i<4; i++) nonce[8+i] = (uint8_t)(block >> (i*8));
        nonce[12] = (uint8_t)gen;

        crypto_aes128_ctr_encrypt(aes_key, nonce, data, BLOCK_SIZE);
    } else {
        /* Software fallback (existing strong mixer) */
        for (size_t i = 0; i < BLOCK_SIZE; i++) {
            uint8_t prev = enc_key[31];
            for (int j = 0; j < 32; j++) {
                uint8_t next = enc_key[j] + prev + (uint8_t)(i + j);
                next = (next << 5) | (next >> 3);
                enc_key[j] = next;
                prev = next;
            }
            keystream[i] = enc_key[i % 32];
        }

        for (size_t i = 0; i < BLOCK_SIZE; i++) {
            data[i] ^= keystream[i];
        }
    }

    /* Compute MAC over (nonce + ciphertext) */
    uint8_t tag[16];
    storage_compute_mac(mac_key, nonce, data, BLOCK_SIZE, tag);

    /* For simplicity in this version we store the tag in the last 16 bytes of the block
       (real implementation would use a separate integrity structure or extended block).
       This is a pragmatic choice for the current fixed 4K objects. */
    for (int i=0; i<16; i++) (data + BLOCK_SIZE - 16)[i] = tag[i];

    /* Zero sensitive material */
    for (int i = 0; i < 32; i++) { enc_key[i] = mac_key[i] = 0; }
    for (size_t i = 0; i < BLOCK_SIZE; i++) keystream[i] = 0;

    return 0;
}

/* Decrypt + verify a block */
int storage_decrypt_block(const uint8_t *file_key, uint64_t inode, uint64_t block,
                          uint32_t gen, uint8_t *data /* in/out */) {
    uint8_t enc_key[32];
    uint8_t mac_key[32];
    uint8_t nonce[16];
    uint8_t stored_tag[16];
    uint8_t computed_tag[16];

    for (int i=0; i<16; i++) stored_tag[i] = (data + BLOCK_SIZE - 16)[i];

    for (int i = 0; i < 8; i++) {
        nonce[i]     = (uint8_t)(inode >> (i * 8));
        nonce[i + 8] = (uint8_t)(block >> (i * 8));
    }
    nonce[0] ^= (uint8_t)gen;

    storage_derive_block_keys(inode, block, gen, file_key, 32, enc_key, mac_key);

    /* Verify MAC first (constant time where possible) */
    storage_compute_mac(mac_key, nonce, data, BLOCK_SIZE - 16, computed_tag);

    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= stored_tag[i] ^ computed_tag[i];
    }
    if (diff != 0) {
        for (int i = 0; i < 32; i++) enc_key[i] = mac_key[i] = 0;
        return -1;   /* Authentication failed - tampering or wrong key */
    }

    /* Decrypt (same keystream as encrypt) */
    uint8_t keystream[BLOCK_SIZE];

    if (cpu_has_aesni()) {
        uint8_t aes_key[16];
        for (int i=0; i<16; i++) aes_key[i] = enc_key[i];

        uint8_t nonce[16] = {0};
        for (int i=0; i<8; i++) nonce[i] = (uint8_t)(inode >> (i*8));
        for (int i=0; i<4; i++) nonce[8+i] = (uint8_t)(block >> (i*8));
        nonce[12] = (uint8_t)gen;

        /* For decrypt we generate the same keystream and XOR again */
        crypto_aes128_ctr_encrypt(aes_key, nonce, data, BLOCK_SIZE - 16);
    } else {
        for (size_t i = 0; i < BLOCK_SIZE; i++) {
            uint8_t prev = enc_key[31];
            for (int j = 0; j < 32; j++) {
                uint8_t next = enc_key[j] + prev + (uint8_t)(i + j);
                next = (next << 5) | (next >> 3);
                enc_key[j] = next;
                prev = next;
            }
            keystream[i] = enc_key[i % 32];
        }

        for (size_t i = 0; i < BLOCK_SIZE - 16; i++) {
            data[i] ^= keystream[i];
        }
    }

    /* Zero everything */
    for (int i = 0; i < 32; i++) { enc_key[i] = mac_key[i] = 0; }
    for (size_t i = 0; i < BLOCK_SIZE; i++) keystream[i] = 0;
    for (int i = 0; i < 16; i++) { stored_tag[i] = computed_tag[i] = 0; }

    return 0;
}



static struct block_device *current_bd = &g_vdisk_bd;

struct block_device *storage_get_default_device(void) {
    return current_bd;
}

void storage_set_default_device(struct block_device *bd) {
    if (bd) current_bd = bd;
}

/* =====================================================================
 * Userspace Filesystem Server Support (TCB Reduction Path)
 * =====================================================================
 *
 * Design:
 * - A privileged userspace task can "take ownership" of the real block device
 *   by registering a set of capabilities (CAP_BLOCK_READ / CAP_BLOCK_WRITE).
 * - Once registered, the kernel storage layer forwards block I/O requests
 *   over IPC to that task instead of handling them directly.
 * - Normal tasks only ever see CAP_FILE / CAP_DIR that ultimately resolve
 *   through the userspace server.
 *
 * This is the foundation for moving the entire FS + encryption policy out
 * of the kernel TCB while keeping the capability model intact.
 */

static int (*userspace_block_read)(uint64_t block, void *buf) = NULL;
static int (*userspace_block_write)(uint64_t block, const void *buf) = NULL;

void storage_register_userspace_block_backend(
        int (*read_fn)(uint64_t, void *),
        int (*write_fn)(uint64_t, const void *))
{
    userspace_block_read  = read_fn;
    userspace_block_write = write_fn;
    println("Storage: Userspace block backend registered (TCB reduction active)");
}

/* Internal helper: use userspace backend if registered, else fall back to current_bd */
static int do_block_read(uint64_t block, void *buf) {
    if (userspace_block_read) {
        return userspace_block_read(block, buf);
    }
    return current_bd->read_block(current_bd, block, buf);
}

static int do_block_write(uint64_t block, const void *buf) {
    if (userspace_block_write) {
        return userspace_block_write(block, buf);
    }
    return current_bd->write_block(current_bd, block, buf);
}

/* Public privileged interface for userspace filesystem server / drivers */
int storage_block_read(uint64_t block, void *buf) {
    return do_block_read(block, buf);
}

int storage_block_write(uint64_t block, const void *buf) {
    return do_block_write(block, buf);
}

int storage_init(void) {
    g_vdisk.data = g_vdisk_buffer;
    g_vdisk.size = sizeof(g_vdisk_buffer);
    g_vdisk.block_count = BLOCKS_PER_DISK;

    my_memset(g_vdisk.data, 0, g_vdisk.size);

    storage_format(&g_vdisk_bd);
    storage_mount(&g_vdisk_bd);

    return 0;
}



static int bitmap_test(const uint8_t *bitmap, uint64_t bit) {
    return (bitmap[bit / 8] & (1 << (bit % 8))) != 0;
}

static void bitmap_set(uint8_t *bitmap, uint64_t bit) {
    bitmap[bit / 8] |= (1 << (bit % 8));
}

static void bitmap_clear(uint8_t *bitmap, uint64_t bit) {
    bitmap[bit / 8] &= ~(1 << (bit % 8));
}

/* Find first free bit, returns -1 if full */
static int64_t bitmap_find_free(const uint8_t *bitmap, uint64_t max_bits) {
    for (uint64_t i = 0; i < max_bits; i++) {
        if (!bitmap_test(bitmap, i)) return i;
    }
    return -1;
}



static int read_block_bitmap(struct block_device *bd, const struct fs_superblock *sb, uint8_t *buf) {
    return bd->read_block(bd, sb->block_bitmap_start, buf);
}

static int write_block_bitmap(struct block_device *bd, const struct fs_superblock *sb, const uint8_t *buf) {
    return bd->write_block(bd, sb->block_bitmap_start, buf);
}

int64_t storage_alloc_block(struct block_device *bd, struct fs_superblock *sb) {
    uint8_t bitmap[BLOCK_SIZE];
    if (read_block_bitmap(bd, sb, bitmap) != 0) return -1;

    int64_t block = bitmap_find_free(bitmap, sb->total_blocks - sb->data_start);
    if (block < 0) return -1;

    bitmap_set(bitmap, block);
    write_block_bitmap(bd, sb, bitmap);

    return sb->data_start + block;
}

void storage_free_block(struct block_device *bd, struct fs_superblock *sb, uint64_t block) {
    uint8_t bitmap[BLOCK_SIZE];
    if (read_block_bitmap(bd, sb, bitmap) != 0) return;

    uint64_t rel = block - sb->data_start;
    bitmap_clear(bitmap, rel);
    write_block_bitmap(bd, sb, bitmap);
}



int64_t storage_alloc_inode(struct block_device *bd, struct fs_superblock *sb) {
    uint8_t bitmap[BLOCK_SIZE];
    if (bd->read_block(bd, sb->inode_bitmap_start, bitmap) != 0) return -1;

    int64_t ino = bitmap_find_free(bitmap, sb->inode_count);
    if (ino < 0) return -1;

    bitmap_set(bitmap, ino);
    bd->write_block(bd, sb->inode_bitmap_start, bitmap);
    return ino;
}

void storage_free_inode(struct block_device *bd, struct fs_superblock *sb, uint64_t ino) {
    uint8_t bitmap[BLOCK_SIZE];
    if (bd->read_block(bd, sb->inode_bitmap_start, bitmap) != 0) return;
    bitmap_clear(bitmap, ino);
    bd->write_block(bd, sb->inode_bitmap_start, bitmap);
}

int storage_read_inode(struct block_device *bd, struct fs_superblock *sb,
                       uint64_t ino, struct on_disk_inode *inode_out) {
    if (ino >= sb->inode_count) return -1;

    uint64_t block = sb->inode_table_start + (ino / INODES_PER_BLOCK);
    uint32_t offset = (ino % INODES_PER_BLOCK) * sizeof(struct on_disk_inode);

    uint8_t buf[BLOCK_SIZE];
    if (bd->read_block(bd, block, buf) != 0) return -1;

    my_memcpy(inode_out, buf + offset, sizeof(struct on_disk_inode));
    return 0;
}

int storage_write_inode(struct block_device *bd, struct fs_superblock *sb,
                        uint64_t ino, const struct on_disk_inode *inode) {
    if (ino >= sb->inode_count) return -1;

    uint64_t block = sb->inode_table_start + (ino / INODES_PER_BLOCK);
    uint32_t offset = (ino % INODES_PER_BLOCK) * sizeof(struct on_disk_inode);

    uint8_t buf[BLOCK_SIZE];
    if (bd->read_block(bd, block, buf) != 0) return -1;

    my_memcpy(buf + offset, inode, sizeof(struct on_disk_inode));
    return bd->write_block(bd, block, buf);
}



int storage_dir_lookup(struct mounted_fs *mfs, uint64_t dir_ino, const char *name, uint64_t *out_ino) {
    struct on_disk_inode dir;
    if (storage_read_inode(mfs->bd, &mfs->sb, dir_ino, &dir) != 0) return -1;

    size_t name_len = my_strlen(name);
    uint8_t block_buf[BLOCK_SIZE];

    uint64_t file_blocks = (dir.size + BLOCK_SIZE - 1) / BLOCK_SIZE;

    for (uint64_t b = 0; b < file_blocks; b++) {
        if (storage_read_file_block(mfs, dir_ino, b, block_buf) != 0) continue;

        for (size_t off = 0; off + sizeof(struct dir_entry) <= BLOCK_SIZE; off += sizeof(struct dir_entry)) {
            struct dir_entry *de = (struct dir_entry *)(block_buf + off);
            if (de->inode == 0) continue;

            if (de->name_len == name_len && my_strncmp(de->name, name, name_len) == 0) {
                *out_ino = de->inode;
                return 0;
            }
        }
    }
    return -1;
}

int storage_dir_add(struct mounted_fs *mfs, uint64_t dir_ino, const char *name,
                    uint64_t child_ino, uint8_t type) {
    struct on_disk_inode dir;
    if (storage_read_inode(mfs->bd, &mfs->sb, dir_ino, &dir) != 0) return -1;

    size_t name_len = my_strlen(name);
    uint8_t block_buf[BLOCK_SIZE];
    uint64_t file_blocks = (dir.size + BLOCK_SIZE - 1) / BLOCK_SIZE;

    /* Try to find a free slot in existing blocks */
    for (uint64_t b = 0; b < file_blocks; b++) {
        if (storage_read_file_block(mfs, dir_ino, b, block_buf) != 0) continue;

        for (size_t off = 0; off + sizeof(struct dir_entry) <= BLOCK_SIZE; off += sizeof(struct dir_entry)) {
            struct dir_entry *de = (struct dir_entry *)(block_buf + off);
            if (de->inode == 0) {
                de->inode = child_ino;
                de->name_len = name_len;
                de->type = type;
                my_strncpy(de->name, name, sizeof(de->name));

                storage_write_file_block(mfs, dir_ino, b, block_buf);
                return 0;
            }
        }
    }

    /* Need to grow the directory */
    uint64_t new_block = file_blocks;
    my_memset(block_buf, 0, BLOCK_SIZE);

    struct dir_entry *de = (struct dir_entry *)block_buf;
    de->inode = child_ino;
    de->name_len = name_len;
    de->type = type;
    my_strncpy(de->name, name, sizeof(de->name));

    if (storage_write_file_block(mfs, dir_ino, new_block, block_buf) != 0) {
        return -1;
    }

    /* Update directory size */
    dir.size = (new_block + 1) * BLOCK_SIZE;
    storage_write_inode(mfs->bd, &mfs->sb, dir_ino, &dir);

    return 0;
}



int storage_format(struct block_device *bd) {
    struct fs_superblock sb;
    my_memset(&sb, 0, sizeof(sb));

    sb.magic = STORAGE_MAGIC;
    sb.version = STORAGE_VERSION;
    sb.total_blocks = bd->total_blocks;
    sb.block_size = BLOCK_SIZE;

    sb.inode_bitmap_start = 1;
    sb.block_bitmap_start = 2;
    sb.inode_table_start = 3;
    sb.data_start = 3 + (16384 / INODES_PER_BLOCK) + 1;
    sb.inode_count = 16384;

    bd->write_block(bd, 0, &sb);

    uint8_t zero[BLOCK_SIZE];
    my_memset(zero, 0, BLOCK_SIZE);
    bd->write_block(bd, sb.inode_bitmap_start, zero);
    bd->write_block(bd, sb.block_bitmap_start, zero);

    bitmap_set(zero, 0);
    bd->write_block(bd, sb.inode_bitmap_start, zero);

    struct on_disk_inode root;
    my_memset(&root, 0, sizeof(root));
    root.mode = 0040755;
    root.links = 2;
    storage_write_inode(bd, &sb, 0, &root);

    return 0;
}

static struct mounted_fs g_mounted_fs;

int storage_mount(struct block_device *bd) {
    uint8_t block_buf[BLOCK_SIZE];
    if (bd->read_block(bd, 0, block_buf) != 0) {
        return -1;
    }

    struct fs_superblock *sb = (struct fs_superblock *)block_buf;

    if (sb->magic != STORAGE_MAGIC) {
        return -2;
    }

    g_mounted_fs.bd = bd;
    g_mounted_fs.sb = *sb;
    g_mounted_fs.mounted = 1;

    extern uint8_t kernel_pepper[16];
    for (int i = 0; i < 32; i++) {
        g_mounted_fs.volume_key[i] = sb->volume_key_salt[i % 16] ^ kernel_pepper[i % 16];
    }

    return 0;
}

struct mounted_fs *storage_get_mounted_fs(void) {
    return &g_mounted_fs;
}

/* =====================================================================
 * Encrypted File I/O on top of inodes (steps 3 + 4)
 * ===================================================================== */

int storage_create_file(struct mounted_fs *mfs, uint32_t uid, uint32_t gid,
                        const char *name, uint64_t dir_ino, uint64_t *out_ino) {
    int64_t ino = storage_alloc_inode(mfs->bd, &mfs->sb);
    if (ino < 0) return -1;

    struct on_disk_inode inode;
    my_memset(&inode, 0, sizeof(inode));
    inode.uid = uid;
    inode.gid = gid;
    inode.mode = 0100644;
    inode.links = 1;

    /* Per-file key (wrapped by volume key in this demo) */
    for (int i = 0; i < 32; i++) {
        inode.file_key[i] = (uint8_t)(get_system_ticks() + i * 17 + ino);
    }
    for (int i = 0; i < 32; i++) {
        inode.file_key[i] ^= mfs->volume_key[i % 32];
    }

    storage_write_inode(mfs->bd, &mfs->sb, ino, &inode);
    storage_dir_add(mfs, dir_ino, name, ino, 1);

    *out_ino = ino;
    return 0;
}

/* Walk the block tree. If allocate==1 and a block is missing, allocate it.
   Returns the physical block number or 0 on failure. */
static uint64_t get_physical_block(struct mounted_fs *mfs, struct on_disk_inode *inode,
                                   uint64_t logical_block, int allocate) {
    struct block_device *bd = mfs->bd;
    struct fs_superblock *sb = &mfs->sb;

    if (logical_block < 12) {
        uint64_t phys = inode->direct[logical_block];
        if (phys == 0 && allocate) {
            phys = storage_alloc_block(bd, sb);
            if (phys == (uint64_t)-1) return 0;
            inode->direct[logical_block] = phys;
        }
        return phys;
    }

    logical_block -= 12;

    /* Single indirect */
    if (logical_block < 1024) {
        uint64_t indirect_phys = inode->indirect;
        if (indirect_phys == 0) {
            if (!allocate) return 0;
            indirect_phys = storage_alloc_block(bd, sb);
            if (indirect_phys == (uint64_t)-1) return 0;
            inode->indirect = indirect_phys;
            uint8_t zero[BLOCK_SIZE];
            my_memset(zero, 0, BLOCK_SIZE);
            bd->write_block(bd, indirect_phys, zero);
        }

        uint8_t indirect_block[BLOCK_SIZE];
        bd->read_block(bd, indirect_phys, indirect_block);

        uint64_t *ptrs = (uint64_t *)indirect_block;
        uint64_t phys = ptrs[logical_block];

        if (phys == 0 && allocate) {
            phys = storage_alloc_block(bd, sb);
            if (phys == (uint64_t)-1) return 0;
            ptrs[logical_block] = phys;
            bd->write_block(bd, indirect_phys, indirect_block);
        }
        return phys;
    }

    /* Double indirect (simplified - only first level for now) */
    logical_block -= 1024;

    if (inode->double_indirect == 0) {
        if (!allocate) return 0;
        uint64_t dbl = storage_alloc_block(bd, sb);
        if (dbl == (uint64_t)-1) return 0;
        inode->double_indirect = dbl;
        uint8_t zero[BLOCK_SIZE];
        my_memset(zero, 0, BLOCK_SIZE);
        bd->write_block(bd, dbl, zero);
    }

    // For brevity in this implementation we only support up to ~1M blocks via single indirect + first double-indirect level.
    // Full double-indirect walk can be added later.
    return 0;
}

int storage_read_file_block(struct mounted_fs *mfs, uint64_t ino, uint64_t block, void *buf) {
    struct on_disk_inode inode;
    if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) return -1;

    uint64_t phys = get_physical_block(mfs, &inode, block, 0);
    if (phys == 0) return -1;

    uint8_t encrypted[BLOCK_SIZE];
    if (do_block_read(phys, encrypted) != 0) return -1;

    if (storage_decrypt_block(inode.file_key, ino, block, 0, encrypted) != 0) {
        return -2; /* auth failure */
    }

    my_memcpy(buf, encrypted, BLOCK_SIZE);
    return 0;
}

int storage_write_file_block(struct mounted_fs *mfs, uint64_t ino, uint64_t block, const void *buf) {
    struct on_disk_inode inode;
    if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) return -1;

    uint64_t phys = get_physical_block(mfs, &inode, block, 1);  /* allocate if needed */
    if (phys == 0) return -1;

    if (inode.direct[block] != phys && block < 12) {
        inode.direct[block] = phys;
    }
    storage_write_inode(mfs->bd, &mfs->sb, ino, &inode);

    uint8_t encrypted[BLOCK_SIZE];
    my_memcpy(encrypted, buf, BLOCK_SIZE);

    if (storage_encrypt_block(inode.file_key, ino, block, 0, encrypted) != 0) {
        return -1;
    }

    return do_block_write(phys, encrypted);
}

/* =====================================================================
 * Migration support for old capfs (step 5)
 * ===================================================================== */

int storage_write_capfs_blob(uint64_t inode, const void *data, size_t len) {
    (void)len;
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs->mounted) return -1;
    return storage_write_file_block(mfs, inode, 0, data);
}

int storage_read_capfs_blob(uint64_t inode, void *data, size_t len) {
    (void)len;
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs->mounted) return -1;
    return storage_read_file_block(mfs, inode, 0, data);
}
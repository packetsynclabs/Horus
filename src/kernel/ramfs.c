#include "kernel.h"

#define MAX_FILES 8
#define MAX_FILE_SIZE 4096

typedef struct {
    char name[32];
    uint8_t data[MAX_FILE_SIZE];
    uint32_t size;
    int in_use;

    /* Per-file transparent encryption metadata */
    uint32_t owner_uid;
    int      is_encrypted;
    uint8_t  enc_file_key[32];   // per-file key encrypted with user's master key (simple XOR for demo)
    uint32_t file_key_iv;        // simple per-file IV/nonce
} ramfile_t;

static ramfile_t ramfs_files[MAX_FILES];

/* Global pool of filesystem objects for the capability-based FS (defined here, declared extern in kernel.h) */
struct fs_object *fs_objects[MAX_FS_OBJECTS];

/* Static backing storage for fs_objects (avoids dynamic alloc in kernel) */
static struct fs_object fs_object_pool[MAX_FS_OBJECTS];

static int my_strcmp(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static void my_strcpy(char* dst, const char* src) {
    while ((*dst++ = *src++));
}

static size_t my_strlen(const char* s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

static void my_memcpy(void* dst, const void* src, size_t n) {
    uint8_t* d = dst;
    const uint8_t* s = src;
    while (n--) *d++ = *s++;
}

/* Keystream generator for the encrypted filesystem layer */
static void efs_keystream(uint8_t *key, size_t keylen, uint32_t offset, uint8_t *out, size_t len) {
    uint8_t state[32];
    for (int i = 0; i < 32; i++) {
        state[i] = key[i % keylen] ^ (uint8_t)(i * 0x5A) ^ (uint8_t)(offset >> (i & 3));
    }

    for (size_t pos = 0; pos < len; pos++) {
        uint8_t prev = state[31];
        for (int i = 0; i < 32; i++) {
            uint8_t next = state[i] + prev + (uint8_t)pos;
            next = (next << 5) | (next >> 3);
            state[i] = next;
            prev = next;
        }
        out[pos] = state[pos % 32];
    }
}

// Major: simple in-memory fs (open/read/write/create/list on small fixed files)
void ramfs_init(void) {
    storage_init();

    /* Legacy ramfs entries kept for transitional path-based shell cmds (ls/cat/echo) */
    my_strcpy(ramfs_files[0].name, "hello.txt");
    my_strcpy((char*)ramfs_files[0].data, "Hello from Horus ramfs!\n");
    ramfs_files[0].size = my_strlen((char*)ramfs_files[0].data);
    ramfs_files[0].in_use = 1;
    ramfs_files[0].owner_uid = 0;
    ramfs_files[0].is_encrypted = 0;

    my_strcpy(ramfs_files[1].name, "readme.txt");
    my_strcpy((char*)ramfs_files[1].data, "This is a simple in-memory ramfs.\nUse open/read/write syscalls.\n");
    ramfs_files[1].size = my_strlen((char*)ramfs_files[1].data);
    ramfs_files[1].in_use = 1;
    ramfs_files[1].owner_uid = 0;
    ramfs_files[1].is_encrypted = 0;

    capfs_init();
}

int capfs_init(void) {
    /* New storage stack (with indirect blocks + authenticated encryption) is initialized at boot.
     * Full wiring of CAP_FILE/CAP_DIR to real inodes is in progress.
     * For now we keep the legacy seed but the infrastructure is ready.
     */
    return 0;
}

struct fs_object *capfs_alloc_object(int type, const char *name) {
    for (int i = 0; i < MAX_FS_OBJECTS; i++) {
        if (fs_objects[i] == NULL) {
            struct fs_object *obj = &fs_object_pool[i];
            obj->type = type;
            obj->size = 0;
            obj->in_use = 1;
            my_strcpy(obj->name, name ? name : "unnamed");
            obj->num_children = 0;
            obj->owner_uid = 0;
            obj->is_encrypted = 0;
            obj->integrity_tag = 0xF5000000U + (addr_t)i;

            /* Fresh per-object salt */
            static uint32_t salt_counter = 0xC0DEFA17;
            for (int s = 0; s < 16; s++) {
                obj->file_salt[s] = (uint8_t)((i * 37 + s) ^ (salt_counter++ & 0xFF));
            }
            for (int k=0; k<32; k++) obj->enc_file_key[k] = 0;
            obj->file_key_iv = salt_counter;

            fs_objects[i] = obj;
            return obj;
        }
    }
    return NULL;
}

int find_file(const char* name) {
    for (int i = 0; i < MAX_FILES; i++) {
        if (ramfs_files[i].in_use && my_strcmp(ramfs_files[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

int ramfs_open(const char* path) {
    int idx = find_file(path);
    if (idx < 0) return -1;
    return 3 + idx;
}

int ramfs_read(int fd, void* buf, size_t len) {
    int idx = fd - 3;
    if (idx < 0 || idx >= MAX_FILES || !ramfs_files[idx].in_use) return -1;

    size_t to_read = len;
    if (to_read > ramfs_files[idx].size) to_read = ramfs_files[idx].size;

    extern int current_task;
    extern tcb_t tasks[MAX_TASKS];

    uint8_t data_key[32];

    if (ramfs_files[idx].is_encrypted && ramfs_files[idx].owner_uid == tasks[current_task].uid && tasks[current_task].has_file_key) {
        // Decrypt the per-file key using current user's master key
        uint8_t file_key[32];
        for (int k=0; k<32; k++) {
            file_key[k] = ramfs_files[idx].enc_file_key[k] ^ tasks[current_task].user_file_master_key[k];
        }

        // Generate keystream with the real file key + IV + offset
        efs_keystream(file_key, 32, ramfs_files[idx].file_key_iv, data_key, 32);  // use as base for stream

        // For simplicity, use a per-block stream (offset based)
        uint8_t keystream[MAX_FILE_SIZE];
        efs_keystream(file_key, 32, ramfs_files[idx].file_key_iv + (fd * 0x1000), keystream, to_read);  // rough per-fd offset

        for (size_t i = 0; i < to_read; i++) {
            ((uint8_t*)buf)[i] = ramfs_files[idx].data[i] ^ keystream[i];
        }

        for (int k=0; k<32; k++) file_key[k] = 0;
    } else {
        // Unencrypted or no key: plain copy (or old behavior)
        my_memcpy(buf, ramfs_files[idx].data, to_read);
    }

    return (int)to_read;
}

int ramfs_write(int fd, const void* buf, size_t len) {
    int idx = fd - 3;
    if (idx < 0 || idx >= MAX_FILES || !ramfs_files[idx].in_use) return -1;

    if (len > MAX_FILE_SIZE) len = MAX_FILE_SIZE;

    extern int current_task;
    extern tcb_t tasks[MAX_TASKS];

    if (ramfs_files[idx].is_encrypted && ramfs_files[idx].owner_uid == tasks[current_task].uid && tasks[current_task].has_file_key) {
        uint8_t file_key[32];
        for (int k=0; k<32; k++) {
            file_key[k] = ramfs_files[idx].enc_file_key[k] ^ tasks[current_task].user_file_master_key[k];
        }

        uint8_t keystream[MAX_FILE_SIZE];
        efs_keystream(file_key, 32, ramfs_files[idx].file_key_iv + (fd * 0x1000), keystream, len);

        for (size_t i = 0; i < len; i++) {
            ramfs_files[idx].data[i] = ((const uint8_t*)buf)[i] ^ keystream[i];
        }

        for (int k=0; k<32; k++) file_key[k] = 0;
    } else {
        my_memcpy(ramfs_files[idx].data, buf, len);
    }

    ramfs_files[idx].size = len;
    return (int)len;
}

int ramfs_create(const char* name) {
    if (find_file(name) >= 0) return -1;

    extern int current_task;
    extern tcb_t tasks[MAX_TASKS];

    for (int i = 0; i < MAX_FILES; i++) {
        if (!ramfs_files[i].in_use) {
            my_strcpy(ramfs_files[i].name, name);
            ramfs_files[i].size = 0;
            ramfs_files[i].in_use = 1;
            ramfs_files[i].owner_uid = tasks[current_task].uid;
            ramfs_files[i].is_encrypted = (tasks[current_task].has_file_key != 0);
            ramfs_files[i].file_key_iv = (addr_t)(get_system_ticks() ^ (uintptr_t)name);

            if (ramfs_files[i].is_encrypted && tasks[current_task].has_file_key) {
                uint8_t file_key[32];
                for (int k=0; k<32; k++) {
                    file_key[k] = (uint8_t)((get_system_ticks() + k + (uintptr_t)name) * 31 + k);
                }
                for (int k=0; k<32; k++) {
                    ramfs_files[i].enc_file_key[k] = file_key[k] ^ tasks[current_task].user_file_master_key[k];
                }
                for (int k=0; k<32; k++) file_key[k] = 0;
            }

            // Mark this as a capability-based file object
            // (Future: this will point to a proper fs_object instead of raw ramfs entry)
            return 3 + i;
        }
    }
    return -1;
}

int ramfs_list(char *buf, size_t bufsize) {
    size_t pos = 0;
    for (int i = 0; i < MAX_FILES; i++) {
        if (ramfs_files[i].in_use) {
            size_t namelen = my_strlen(ramfs_files[i].name);
            if (pos + namelen + 1 >= bufsize) break;
            my_memcpy(buf + pos, ramfs_files[i].name, namelen);
            pos += namelen;
            buf[pos++] = '\n';
        }
    }
    buf[pos] = 0;
    return (int)pos;
}

/* === Core Capability-based FS Operations (secure, attenuated, encrypted) === */

/* Derive real file key for an fs_object if caller holds matching session key */
static int capfs_derive_file_key(const struct fs_object *obj, uint8_t *out_key, uint32_t *out_iv) {
    extern int current_task;
    extern tcb_t tasks[MAX_TASKS];

    if (!obj || !obj->is_encrypted || !out_key) return -1;
    if (!tasks[current_task].has_file_key) return -2;

    /* Only the owner (or root) can unwrap with their current session master key */
    if (obj->owner_uid != tasks[current_task].uid && tasks[current_task].uid != 0) {
        return -3;
    }

    for (int k = 0; k < 32; k++) {
        out_key[k] = obj->enc_file_key[k] ^ tasks[current_task].user_file_master_key[k];
    }
    if (out_iv) *out_iv = obj->file_key_iv;
    return 0;
}

/* Securely erase a key buffer */
static void secure_erase_key(uint8_t *k, size_t n) {
    for (size_t i = 0; i < n; i++) k[i] = 0;
}

int capfs_lookup(struct capability *dir_cap, const char *name, struct capability *out_cap, uint32_t desired_rights) {
    if (!dir_cap || dir_cap->type != CAP_DIR || !out_cap || !name) return -1;

    struct fs_object *dir = (struct fs_object *)dir_cap->object;
    if (!dir || dir->type != FS_OBJ_DIR) return -1;

    if ((dir_cap->rights & CAP_RIGHT_FS_LOOKUP) == 0) return -2;

    extern int current_task;
    if (rust_validate_fs_operation((addr_t)current_task, 0 /*lookup*/, dir_cap->rights, (const uint8_t*)name, my_strlen(name)) < 0) {
        return -20; /* policy deny */
    }

    /* Basic name validation (confinement / no .. traversal for now) */
    if (name[0] == 0 || my_strlen(name) > 31 || my_strcmp(name, ".") == 0 || my_strcmp(name, "..") == 0) {
        return -7;
    }

    for (int i = 0; i < dir->num_children; i++) {
        if (my_strcmp(dir->child_names[i], name) == 0) {
            struct fs_object *child = dir->children[i];
            if (!child || !child->in_use) return -3;

            out_cap->type   = (child->type == FS_OBJ_DIR) ? CAP_DIR : CAP_FILE;
            out_cap->object = (addr_t)child;
            out_cap->rights = desired_rights & dir_cap->rights;  /* strict attenuation */
            out_cap->badge  = dir_cap->badge ? dir_cap->badge : dir_cap->object;  /* chain badge for revoke */

            return 0;
        }
    }
    return -4; /* not found */
}

int capfs_create(struct capability *dir_cap, const char *name, int type, struct capability *out_cap, uint32_t desired_rights) {
    if (!dir_cap || dir_cap->type != CAP_DIR || !out_cap || !name) return -1;

    struct fs_object *dir = (struct fs_object *)dir_cap->object;
    if (!dir || dir->type != FS_OBJ_DIR) return -1;

    if ((dir_cap->rights & CAP_RIGHT_FS_CREATE) == 0) return -2;
    if (dir->num_children >= FS_MAX_CHILDREN) return -5;

    /* Name validation */
    size_t nlen = my_strlen(name);
    if (nlen == 0 || nlen > 31 || my_strcmp(name, ".") == 0 || my_strcmp(name, "..") == 0) return -7;

    /* Check for duplicate */
    for (int i = 0; i < dir->num_children; i++) {
        if (my_strcmp(dir->child_names[i], name) == 0) return -8;
    }

    struct fs_object *child = capfs_alloc_object(type, name);
    if (!child) return -6;

    extern int current_task;
    extern tcb_t tasks[MAX_TASKS];

    if (rust_validate_fs_operation((addr_t)current_task, 1 /*create*/, dir_cap->rights, (const uint8_t*)name, my_strlen(name)) < 0) {
        /* undo alloc slot if we want strictness; for now just fail */
        return -20;
    }

    child->owner_uid = tasks[current_task].uid;

    /* Enable transparent encryption for this file if creator has a session key */
    if (tasks[current_task].has_file_key) {
        child->is_encrypted = 1;
        uint8_t raw_key[32];
        uint32_t t = (addr_t)get_system_ticks();
        for (int k=0; k<32; k++) {
            raw_key[k] = (uint8_t)((t + k * 17 + ((uintptr_t)child >> 2)) & 0xFF);
            raw_key[k] ^= (uint8_t)((k * 13) + (t >> (k & 3)));
        }
        /* wrap with current master */
        for (int k=0; k<32; k++) {
            child->enc_file_key[k] = raw_key[k] ^ tasks[current_task].user_file_master_key[k];
        }
        child->file_key_iv = t ^ (addr_t)(uintptr_t)child;
        secure_erase_key(raw_key, 32);
    }

    int slot = dir->num_children++;
    dir->children[slot] = child;
    my_strcpy(dir->child_names[slot], name);

    out_cap->type   = (type == FS_OBJ_DIR) ? CAP_DIR : CAP_FILE;
    out_cap->object = (addr_t)child;
    out_cap->rights = desired_rights & dir_cap->rights;
    out_cap->badge  = dir_cap->badge ? dir_cap->badge : (addr_t)dir;

    return 0;
}

int capfs_delete(struct capability *dir_cap, const char *name) {
    if (!dir_cap || dir_cap->type != CAP_DIR || !name) return -1;

    struct fs_object *dir = (struct fs_object *)dir_cap->object;
    if (!dir || dir->type != FS_OBJ_DIR) return -1;

    if ((dir_cap->rights & CAP_RIGHT_FS_DELETE) == 0) return -2;

    for (int i = 0; i < dir->num_children; i++) {
        if (my_strcmp(dir->child_names[i], name) == 0) {
            struct fs_object *victim = dir->children[i];
            if (victim) {
                /* Revoke all direct derived caps would happen via badge walk in cap_revoke */
                victim->in_use = 0;
                victim->num_children = 0;
                /* leave in pool for simplicity; real impl would free */
            }
            /* Compact children list */
            for (int j = i; j < dir->num_children - 1; j++) {
                dir->children[j] = dir->children[j+1];
                my_strcpy(dir->child_names[j], dir->child_names[j+1]);
            }
            dir->num_children--;
            return 0;
        }
    }
    return -4;
}

int capfs_readdir(struct capability *dir_cap, char *buf, size_t bufsize) {
    if (!dir_cap || dir_cap->type != CAP_DIR || !buf || bufsize < 2) return -1;
    if ((dir_cap->rights & CAP_RIGHT_FS_LOOKUP) == 0) return -2;

    struct fs_object *dir = (struct fs_object *)dir_cap->object;
    if (!dir || dir->type != FS_OBJ_DIR) return -1;

    size_t pos = 0;
    for (int i = 0; i < dir->num_children && pos + 1 < bufsize; i++) {
        size_t n = my_strlen(dir->child_names[i]);
        if (pos + n + 1 >= bufsize) break;
        my_memcpy(buf + pos, dir->child_names[i], n);
        pos += n;
        buf[pos++] = '\n';
    }
    buf[pos] = 0;
    return (int)pos;
}

/* Transparent encrypted read using per-file + session key */
int capfs_read(struct capability *file_cap, void *buf, size_t len) {
    if (!file_cap || file_cap->type != CAP_FILE) return -1;
    if ((file_cap->rights & CAP_RIGHT_FS_READ) == 0) return -2;

    extern int current_task;
    if (rust_validate_fs_operation((addr_t)current_task, 3 /*read*/, file_cap->rights, NULL, 0) < 0) return -20;

    struct fs_object *obj = (struct fs_object *)file_cap->object;
    if (!obj || obj->type != FS_OBJ_FILE) return -1;

    size_t to_read = len;
    if (to_read > obj->size) to_read = obj->size;

    uint8_t *dst = (uint8_t *)buf;

    if (obj->is_encrypted) {
        uint8_t file_key[32];
        uint32_t iv = 0;
        if (capfs_derive_file_key(obj, file_key, &iv) != 0) {
            /* Fallback: deny or return zeros for strictness */
            for (size_t i=0; i<to_read; i++) dst[i] = 0;
            secure_erase_key(file_key, 32);
            return -10; /* key/perm error */
        }

        uint8_t keystream[FS_DATA_SIZE];
        efs_keystream(file_key, 32, iv, keystream, to_read);

        for (size_t i = 0; i < to_read; i++) {
            dst[i] = obj->data[i] ^ keystream[i];
        }
        secure_erase_key(file_key, 32);
        secure_erase_key(keystream, FS_DATA_SIZE);
    } else {
        my_memcpy(buf, obj->data, to_read);
    }

    return (int)to_read;
}

int capfs_write(struct capability *file_cap, const void *buf, size_t len) {
    if (!file_cap || file_cap->type != CAP_FILE) return -1;
    if ((file_cap->rights & CAP_RIGHT_FS_WRITE) == 0) return -2;

    extern int current_task;
    if (rust_validate_fs_operation((addr_t)current_task, 4 /*write*/, file_cap->rights, NULL, 0) < 0) return -20;

    struct fs_object *obj = (struct fs_object *)file_cap->object;
    if (!obj || obj->type != FS_OBJ_FILE) return -1;

    if (len > FS_DATA_SIZE) len = FS_DATA_SIZE;

    const uint8_t *src = (const uint8_t *)buf;

    if (obj->is_encrypted) {
        uint8_t file_key[32];
        uint32_t iv = 0;
        if (capfs_derive_file_key(obj, file_key, &iv) != 0) {
            secure_erase_key(file_key, 32);
            return -10;
        }

        uint8_t keystream[FS_DATA_SIZE];
        efs_keystream(file_key, 32, iv, keystream, len);

        for (size_t i = 0; i < len; i++) {
            obj->data[i] = src[i] ^ keystream[i];
        }
        obj->size = (addr_t)len;

        secure_erase_key(file_key, 32);
        secure_erase_key(keystream, FS_DATA_SIZE);
    } else {
        my_memcpy(obj->data, src, len);
        obj->size = (addr_t)len;
    }

    return (int)len;
}

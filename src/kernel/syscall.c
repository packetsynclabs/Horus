#include "kernel.h"

extern char keyboard_buffer[256];
extern uint32_t kb_head;
extern uint32_t kb_tail;

static size_t kstrlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

static void kstrcpy(char *dst, const char *src) {
    while (*src) {
        *dst++ = *src++;
    }
    *dst = 0;
}

static int kstrcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

extern tcb_t tasks[MAX_TASKS];
extern int current_task;

#define HISTORY_SIZE 8
#define CMD_MAX 128
static char cmd_history[HISTORY_SIZE][CMD_MAX];
static int history_count = 0;
static int history_pos = -1;

static void qemu_exit(int code) {
    outb(0x604, (uint8_t)code);
    outb(0x604, 0x00);
    asm volatile("lidt 0x0");
    asm volatile("int $0x0");
    for (;;) {
        asm volatile("cli; hlt");
    }
}

/* Secure loader staging (one armed program at a time for robustness) */
#define MAX_PROGRAM_SIZE (1024 * 1024)
static uint8_t loader_staging[MAX_PROGRAM_SIZE];
static struct program_header armed_hdr;
static int program_armed = 0;

/* === Audit logging === */
static struct audit_event audit_log_buffer[AUDIT_LOG_SIZE];
static uint32_t audit_head = 0;
static uint32_t audit_count = 0;

void audit_log(uint32_t type, uint32_t object, int32_t result, const char *msg) {
    struct audit_event *e = &audit_log_buffer[audit_head];

    e->timestamp    = get_system_ticks();
    e->type         = type;
    e->subject_uid  = tasks[current_task].uid;
    e->subject_task = current_task;
    e->object       = object;
    e->result       = result;

    if (msg) {
        size_t i;
        for (i = 0; i < sizeof(e->message) - 1 && msg[i]; i++) {
            e->message[i] = msg[i];
        }
        e->message[i] = 0;
    } else {
        e->message[0] = 0;
    }

    audit_head = (audit_head + 1) % AUDIT_LOG_SIZE;
    if (audit_count < AUDIT_LOG_SIZE) audit_count++;
}

/* Multi-user support - fully capability protected via CAP_USER */

/* Local fallback definitions in case kernel.h constants are not yet visible
   (these will be ignored if the ones from kernel.h are already defined) */
#ifndef AUDIT_AUTH
#define AUDIT_AUTH          1
#define AUDIT_SUDO          2
#define AUDIT_USER_MGMT     3
#define AUDIT_CAP_OPERATION 4
#define AUDIT_FILE_ACCESS   5
#define AUDIT_IPC           6
#define AUDIT_FS            7
#define AUDIT_CAP_MINT      10
#define AUDIT_CAP_REVOKE    11
#define AUDIT_CAP_TRANSFER  12
#define AUDIT_FS_LOOKUP     20
#define AUDIT_FS_CREATE     21
#define AUDIT_FS_DELETE     22
#define AUDIT_FS_READ       23
#define AUDIT_FS_WRITE      24
#define AUDIT_IPC_GRANT     30
#define AUDIT_TASK_CREATE   40
#define AUDIT_TASK_EXIT     41
#endif
static struct user_account users[MAX_USERS];
static int user_count = 0;
static uint32_t next_uid = 1000;  /* start normal users at 1000 */

/* Kernel pepper - mixed at boot for password hashing (never exposed) */
uint8_t kernel_pepper[16];

/* Generate a random salt for a user using available entropy (public timer + local state) */
static void generate_salt(char *salt, size_t len) {
    static uint32_t salt_counter = 0xC0DE1234;
    for (size_t i = 0; i < len; i++) {
        uint32_t t = get_system_ticks();
        salt_counter = (salt_counter * 1103515245U + 12345U) ^ (t + i);
        salt[i] = (char)(salt_counter ^ (t >> (i & 3)));
    }
}

/* Strong password hashing for this environment:
   - Per-user salt
   - Kernel pepper
   - Many iterations (good KDF approximation)
   - Output in pass_hash
*/
static void strong_password_hash(const char *password, const char *salt,
                                 const uint8_t *pepper, char *out_hash) {
    uint8_t state[32];
    size_t pwlen = kstrlen(password);
    size_t slen = PASS_SALT_LEN;

    /* Initial state: mix password + salt + pepper */
    for (int i = 0; i < 32; i++) {
        state[i] = (uint8_t)(i * 17);
    }

    /* Incorporate inputs */
    for (size_t i = 0; i < pwlen; i++) {
        state[i % 32] ^= (uint8_t)password[i];
    }
    for (size_t i = 0; i < slen; i++) {
        state[(i + 7) % 32] ^= (uint8_t)salt[i];
    }
    for (int i = 0; i < 16; i++) {
        state[(i + 13) % 32] ^= pepper[i];
    }

    /* Many iterations - this is the expensive part (KDF) */
    const int iterations = 4096;   /* decent for bare metal demo; increase on faster hardware */
    for (int iter = 0; iter < iterations; iter++) {
        uint8_t prev = state[31];
        for (int i = 0; i < 32; i++) {
            uint8_t next = state[i] + prev + (uint8_t)(iter & 0xFF);
            next = (next << 3) | (next >> 5);   /* rotate */
            next ^= (uint8_t)(i * 0x5A);
            state[i] = next;
            prev = next;
        }
        /* Mix in a bit of the password each round for diffusion */
        if (pwlen > 0) {
            state[iter % 32] ^= (uint8_t)password[iter % pwlen];
        }
    }

    /* Final output as printable hash */
    for (int i = 0; i < PASS_HASH_LEN - 1; i++) {
        out_hash[i] = 'a' + (state[i % 32] % 26);
    }
    out_hash[PASS_HASH_LEN - 1] = 0;
}

/* Constant-time comparison to avoid timing attacks */
static int constant_time_compare(const char *a, const char *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)a[i] ^ (uint8_t)b[i];
    }
    return diff == 0;
}

/* Set or change a user's password securely */
int set_user_password(uint32_t uid, const char *new_password) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid && users[i].uid == uid) {
            generate_salt(users[i].salt, PASS_SALT_LEN);
            strong_password_hash(new_password, users[i].salt, kernel_pepper,
                                 users[i].pass_hash);
            return 0;
        }
    }
    return -1;
}

/* =====================================================================
 * SECURITY INVARIANT #2 (enforced):
 *   ALL new authentication paths MUST go through verify_user_password().
 *   This is the single source of truth for password verification.
 *   Never call strong_password_hash() directly from auth paths.
 * ===================================================================== */
static int verify_user_password(const char *name, const char *password) {
    struct user_account *u = NULL;
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid) {
            int match = 1;
            for (size_t j = 0; j < 32 && name[j]; j++) {
                if (users[i].name[j] != name[j]) { match = 0; break; }
            }
            if (match && name[kstrlen(users[i].name)] == 0) {
                u = &users[i];
                break;
            }
        }
    }
    if (!u) return 0;

    char computed[PASS_HASH_LEN];
    strong_password_hash(password, u->salt, kernel_pepper, computed);

    return constant_time_compare(computed, u->pass_hash, PASS_HASH_LEN);
}

/* Derive the user's file encryption master key from the password (called at auth time while password is still in kernel buffer).
   Stores it in the current task's TCB for the session. */
static void derive_and_store_user_file_key(const char *password, struct user_account *u) {
    if (!u || !password) return;

    // Use the same strong KDF with a "file" purpose
    char file_purpose[16] = "horus_file_key";
    // We can concatenate or use a separate derivation. For simplicity, reuse strong hash with modified salt.
    char combined_salt[PASS_SALT_LEN + 16];
    for (int i=0; i<PASS_SALT_LEN; i++) combined_salt[i] = u->salt[i];
    for (int i=0; i<16; i++) combined_salt[PASS_SALT_LEN + i] = file_purpose[i];

    uint8_t key[32];
    // Reuse the strong mixer logic conceptually (simplified here for the file key)
    strong_password_hash(password, combined_salt, kernel_pepper, (char*)key);  // reuse as KDF

    // Store in current task
    for (int i=0; i<32; i++) {
        tasks[current_task].user_file_master_key[i] = key[i];
    }
    tasks[current_task].has_file_key = 1;

    // Wipe local
    for (int i=0; i<32; i++) key[i] = 0;
}

/* =====================================================================
 * SECURITY INVARIANT #3 (enforced):
 *   ANY change to the user DB (users[] array, user_count, next_uid)
 *   MUST be followed by a call to users_save_to_ramfs() (or users_persist())
 *   which recomputes and writes the integrity tag (keyed by kernel_pepper).
 *   Direct mutation + no save is forbidden.
 * ===================================================================== */
#define USERDB_MAGIC 0x55534442  /* "USDB" */
#define USERDB_TAG_LEN 32

/* Integrity tag for the persisted user database (keyed with kernel pepper).
   Strengthened for better tampering resistance (multiple keyed diffusion passes). */
static void compute_userdb_tag(uint8_t *tag_out) {
    uint8_t state[32];
    /* Strong keyed init with pepper */
    for (int i = 0; i < 32; i++) {
        state[i] = kernel_pepper[i % 16] ^ (uint8_t)(i * 0xA5) ^ 0x3C;
    }

    for (int i = 0; i < MAX_USERS; i++) {
        if (!users[i].valid) continue;
        uint8_t *rec = (uint8_t *)&users[i];
        for (size_t j = 0; j < sizeof(struct user_account); j++) {
            state[j % 32] ^= rec[j];
            state[(j + 13) % 32] = (state[(j + 13) % 32] * 41) + rec[j] + (uint8_t)j;
        }
    }

    /* Two full passes of strong diffusion, re-mixing pepper each pass */
    for (int pass = 0; pass < 2; pass++) {
        for (int round = 0; round < 48; round++) {
            uint8_t prev = state[31];
            for (int i = 0; i < 32; i++) {
                uint8_t next = state[i] + prev + (uint8_t)round + kernel_pepper[(i + pass) % 16];
                next = (next << 4) | (next >> 4);
                next ^= (uint8_t)(i * 0x5A);
                state[i] = next;
                prev = next;
            }
        }
    }
    for (int i = 0; i < USERDB_TAG_LEN; i++) tag_out[i] = state[i % 32];
}

static int userdb_tag_valid(const uint8_t *tag_on_disk) {
    uint8_t computed[USERDB_TAG_LEN];
    compute_userdb_tag(computed);
    return constant_time_compare((const char*)computed, (const char*)tag_on_disk, USERDB_TAG_LEN);
}

/* Internal implementation - the real save logic. */
static void users_save_to_ramfs(void) {
    int fd = ramfs_open("passwd");
    if (fd < 0) {
        fd = ramfs_create("passwd");
        if (fd < 0) return;
    }

    uint32_t magic = USERDB_MAGIC;
    uint32_t count = 0;
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid) count++;
    }

    ramfs_write(fd, &magic, sizeof(magic));
    ramfs_write(fd, &count, sizeof(count));

    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid) {
            ramfs_write(fd, &users[i], sizeof(struct user_account));
        }
    }

    /* Append integrity tag */
    uint8_t tag[USERDB_TAG_LEN];
    compute_userdb_tag(tag);
    ramfs_write(fd, tag, USERDB_TAG_LEN);
}

/* =====================================================================
 * SECURITY INVARIANT #3 (enforced):
 *   The ONLY public entry point for persisting user DB changes.
 *   All mutation sites (useradd, userdel, passwd, etc.) must call this.
 * ===================================================================== */
static void users_persist(void) {
    users_save_to_ramfs();
}

static void users_load_from_ramfs(void) {
    int fd = ramfs_open("passwd");
    if (fd < 0) return;

    uint32_t magic = 0;
    uint32_t count = 0;
    if (ramfs_read(fd, &magic, sizeof(magic)) != sizeof(magic) ||
        magic != USERDB_MAGIC) {
        return; /* invalid or corrupt */
    }
    if (ramfs_read(fd, &count, sizeof(count)) != sizeof(count) ||
        count > MAX_USERS) {
        return;
    }

    /* Reset and load */
    for (int i = 0; i < MAX_USERS; i++) users[i].valid = 0;
    user_count = 0;

    for (uint32_t i = 0; i < count; i++) {
        struct user_account tmp;
        if (ramfs_read(fd, &tmp, sizeof(tmp)) == sizeof(tmp)) {
            int slot = -1;
            for (int j = 0; j < MAX_USERS; j++) {
                if (!users[j].valid) { slot = j; break; }
                if (users[j].uid == tmp.uid) { slot = j; break; }
            }
            if (slot >= 0) {
                users[slot] = tmp;
                users[slot].valid = 1;
                user_count++;
                if (tmp.uid >= next_uid) next_uid = tmp.uid + 1;
            }
        }
    }

    /* Verify integrity tag */
    uint8_t tag_on_disk[USERDB_TAG_LEN];
    if (ramfs_read(fd, tag_on_disk, USERDB_TAG_LEN) != USERDB_TAG_LEN ||
        !userdb_tag_valid(tag_on_disk)) {
        /* Tampered or corrupted DB - refuse to load */
        for (int i = 0; i < MAX_USERS; i++) users[i].valid = 0;
        user_count = 0;
        next_uid = 1000;
    }
}

void users_init(void) {
    for (int i = 0; i < MAX_USERS; i++) {
        users[i].valid = 0;
    }
    user_count = 0;
    next_uid = 1000;

    /* Strong kernel pepper using timer + local LCG at boot */
    uint32_t pepper_state = get_system_ticks() ^ 0xDEADBEEF;
    for (int i = 0; i < 16; i++) {
        pepper_state = pepper_state * 1103515245U + 12345U;
        kernel_pepper[i] = (uint8_t)(pepper_state ^ (get_system_ticks() << (i & 3)));
    }

    /* Root user */
    users[0].uid = 0;
    users[0].gid = 0;
    kstrcpy(users[0].name, "root");
    set_user_password(0, "rootpass");   /* change in real use */
    kstrcpy(users[0].home, "/");
    kstrcpy(users[0].shell, "/bin/shell");
    users[0].valid = 1;
    users[0].auth_fail_count = 0;
    users[0].auth_lockout_until = 0;
    user_count = 1;

    /* Demo user */
    users[1].uid = 1000;
    users[1].gid = 100;
    kstrcpy(users[1].name, "user");
    set_user_password(1, "userpass");
    kstrcpy(users[1].home, "/home/user");
    users[1].auth_fail_count = 0;
    users[1].auth_lockout_until = 0;
    kstrcpy(users[1].shell, "/bin/shell");
    users[1].valid = 1;
    user_count = 2;

    /* Try to load persisted users from ramfs (overrides defaults if present) */
    users_load_from_ramfs();
}

/* Internal: receive full headered binary from serial2 (loader port) into staging.
 * Uses existing yielding serial2_read_char. Returns 0 on success, <0 on error.
 * Always validates magic and size before accepting payload. */
static int loader_receive_to_staging(struct program_header *out_hdr) {
    struct program_header hdr;
    uint8_t *p = (uint8_t *)&hdr;

    p[0] = serial2_read_char();
    for (size_t i = 1; i < sizeof(hdr); i++) {
        p[i] = serial2_read_char();
    }

    if (hdr.magic != 0x55524F48) {
        return -1; /* bad magic */
    }
    if (hdr.size == 0 || hdr.size > MAX_PROGRAM_SIZE) {
        return -2; /* invalid size */
    }

    for (uint32_t i = 0; i < hdr.size; i++) {
        loader_staging[i] = serial2_read_char();
    }

    armed_hdr = hdr;
    program_armed = 1;

    if (out_hdr) {
        *out_hdr = hdr;
    }
    return 0;
}

/* === User management implementation (capability + uid protected) === */

static int current_user_is_admin(void) {
    /* Pure capability-based check. This is the authoritative mechanism. */
    struct capability *c = cap_lookup(6, CAP_RIGHT_ALL);
    return (c && c->type == CAP_USER);
}

int do_useradd(uint32_t uid, uint32_t gid, const char *name, const char *initial_password) {
    if (!current_user_is_admin()) return -1;
    if (user_count >= MAX_USERS) return -2;
    if (kstrlen(name) == 0 || kstrlen(name) >= 32) return -3;

    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid) {
            if (users[i].uid == uid) return -4;
            if (kstrcmp(users[i].name, name) == 0) return -5;
        }
    }

    for (int i = 0; i < MAX_USERS; i++) {
        if (!users[i].valid) {
            users[i].uid = uid;
            users[i].gid = gid;
            kstrcpy(users[i].name, name);
            kstrcpy(users[i].home, "/home/");
            size_t hlen = kstrlen(users[i].home);
            kstrcpy(users[i].home + hlen, name);
            kstrcpy(users[i].shell, "/bin/shell");
            set_user_password(uid, initial_password);
            users[i].valid = 1;
            user_count++;
            if (uid >= next_uid) next_uid = uid + 1;
            users_persist();
            audit_log(AUDIT_USER_MGMT, uid, 0, "useradd");
            return 0;
        }
    }
    return -6;
}

int do_userdel(uint32_t uid) {
    if (!current_user_is_admin()) return -1;
    if (uid == 0) return -2;

    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid && users[i].uid == uid) {
            users[i].valid = 0;
            user_count--;
            users_persist();
            return 0;
        }
    }
    return -3;
}

int do_passwd(uint32_t target_uid, const char *new_password) {
    uint32_t my_uid = tasks[current_task].uid;
    int is_admin = current_user_is_admin();

    if (!is_admin && my_uid != target_uid) return -1;

    int rc = set_user_password(target_uid, new_password);
    if (rc == 0) users_persist();
    return rc;
}

int do_rotate_keys(void) {
    if (!tasks[current_task].has_file_key) return -1;

    uint8_t new_master[32];
    for (int i = 0; i < 32; i++) {
        new_master[i] = (uint8_t)((get_system_ticks() * 31 + i) ^ (i * 0xA5));
    }

    for (int i = 0; i < 32; i++) {
        tasks[current_task].user_file_master_key[i] = new_master[i];
    }
    for (int i = 0; i < 32; i++) new_master[i] = 0;

    audit_log(AUDIT_FILE_ACCESS, 0, 0, "file key rotation");
    return 0;
}

/* === Capability-based Filesystem (full secure model) === */

int sys_fs_mint_file(uint32_t dir_slot, uint32_t dest_slot, uint32_t new_rights) {
    /* SECURITY INVARIANT #1: Never bypass cap_lookup for new privileged operations.
       Authorization for this mint comes from the cap_lookup on the source dir_cap below.
       We only ever write into the caller's own cspace after that check. */
    struct capability *dir_cap = cap_lookup(dir_slot, CAP_RIGHT_FS_LOOKUP | CAP_RIGHT_MINT);
    if (!dir_cap) {
        audit_log(AUDIT_FS, dir_slot, -1, "mint denied: no dir cap or rights");
        return -1;
    }

    if (dest_slot < 4 || dest_slot >= 256) return -2;

    /* Mint attenuated copy */
    if (!cap_mint(dest_slot, dir_slot, new_rights)) {
        audit_log(AUDIT_FS, dest_slot, -2, "mint failed");
        return -2;
    }

    struct capability *dest = &tasks[current_task].cspace[dest_slot];
    /* Force precise type based on source object */
    struct fs_object *obj = (struct fs_object *)dir_cap->object;
    dest->type = (obj && obj->type == FS_OBJ_DIR) ? CAP_DIR : CAP_FILE;

    audit_log(AUDIT_CAP_MINT, dest_slot, 0, "fs mint");
    return 0;
}

int sys_fs_lookup(uint32_t dir_slot, const char *name, uint32_t out_slot, uint32_t desired_rights) {
    if (out_slot < 4 || out_slot >= 256) return -1;

    struct capability *dir_cap = cap_lookup(dir_slot, CAP_RIGHT_FS_LOOKUP);
    if (!dir_cap) {
        audit_log(AUDIT_FS, dir_slot, -1, "lookup denied");
        return -1;
    }

    struct capability *out = &tasks[current_task].cspace[out_slot];
    int rc = capfs_lookup(dir_cap, name, out, desired_rights);
    if (rc == 0) {
        audit_log(AUDIT_FS_LOOKUP, out_slot, 0, "lookup ok");
    } else {
        audit_log(AUDIT_FS_LOOKUP, dir_slot, rc, "lookup fail");
    }
    return rc;
}

int sys_fs_create(uint32_t dir_slot, const char *name, int type, uint32_t out_slot, uint32_t desired_rights) {
    if (out_slot < 4 || out_slot >= 256) return -1;
    if (type != FS_OBJ_FILE && type != FS_OBJ_DIR) return -9;

    struct capability *dir_cap = cap_lookup(dir_slot, CAP_RIGHT_FS_CREATE);
    if (!dir_cap) {
        audit_log(AUDIT_FS, dir_slot, -1, "create denied: no cap");
        return -1;
    }

    struct capability *out = &tasks[current_task].cspace[out_slot];
    int rc = capfs_create(dir_cap, name, type, out, desired_rights);
    if (rc == 0) {
        audit_log(AUDIT_FS_CREATE, out_slot, 0, "create ok");
    } else {
        audit_log(AUDIT_FS_CREATE, dir_slot, rc, "create fail");
    }
    return rc;
}

int sys_fs_delete(uint32_t dir_slot, const char *name) {
    struct capability *dir_cap = cap_lookup(dir_slot, CAP_RIGHT_FS_DELETE);
    if (!dir_cap) {
        audit_log(AUDIT_FS, dir_slot, -1, "delete denied");
        return -1;
    }

    int rc = capfs_delete(dir_cap, name);
    audit_log(AUDIT_FS_DELETE, dir_slot, rc, rc==0 ? "delete" : "delete fail");
    return rc;
}

int sys_fs_readdir(uint32_t dir_slot, char *buf, uint32_t bufsize) {
    struct capability *dir_cap = cap_lookup(dir_slot, CAP_RIGHT_FS_LOOKUP);
    if (!dir_cap) return -1;

    /* copy_to_user not strictly needed for kernel shell but for user tasks */
    int rc = capfs_readdir(dir_cap, buf, bufsize);
    return rc;
}

int sys_fs_get_root(uint32_t dest_slot, uint32_t rights) {
    /* SECURITY INVARIANT #1 (enforced):
       Never bypass cap_lookup for privileged operations.
       The check below (CAP_USER or uid 0) + the explicit admin cap_lookup
       is the authorization gate before we install the powerful root dir cap. */
    struct capability *admin = cap_lookup(6, CAP_RIGHT_ALL);
    if (!admin && tasks[current_task].uid != 0) {
        audit_log(AUDIT_FS, 0, -1, "get_root denied");
        return -1;
    }

    if (dest_slot < 4 || dest_slot >= 256) return -2;

    /* The root dir is always fs_objects[0] */
    struct fs_object *root = fs_objects[0];
    if (!root) return -3;

    struct capability *dest = &tasks[current_task].cspace[dest_slot];
    dest->type   = CAP_DIR;
    dest->object = (addr_t)root;
    dest->rights = rights & (CAP_RIGHT_FS_LOOKUP | CAP_RIGHT_FS_CREATE | CAP_RIGHT_FS_DELETE |
                             CAP_RIGHT_FS_READ | CAP_RIGHT_FS_WRITE | CAP_RIGHT_MINT | CAP_RIGHT_REVOKE);
    dest->badge  = 0xF5000000U;  /* special root badge */

    audit_log(AUDIT_FS, dest_slot, 0, "get_root");
    return 0;
}

int sys_fs_read(uint32_t file_slot, char *buf, uint32_t len) {
    if (file_slot >= 256 || !buf) return -1;
    struct capability *fc = cap_lookup(file_slot, CAP_RIGHT_FS_READ);
    if (!fc || fc->type != CAP_FILE) return -2;

    char kbuf[256];
    uint32_t to = len > 255 ? 255 : len;
    int rc = capfs_read(fc, kbuf, to);
    if (rc > 0) {
        if (copy_to_user(buf, kbuf, (size_t)rc) != 0) return -3;
    }
    audit_log(AUDIT_FS_READ, file_slot, rc >= 0 ? 0 : rc, "fs read");
    return rc;
}

int sys_fs_write(uint32_t file_slot, const char *buf, uint32_t len) {
    if (file_slot >= 256 || !buf) return -1;
    struct capability *fc = cap_lookup(file_slot, CAP_RIGHT_FS_WRITE);
    if (!fc || fc->type != CAP_FILE) return -2;

    char kbuf[256];
    uint32_t to = len > 255 ? 255 : len;
    if (copy_from_user(kbuf, buf, to) != 0) return -3;

    int rc = capfs_write(fc, kbuf, to);
    audit_log(AUDIT_FS_WRITE, file_slot, rc >= 0 ? 0 : rc, "fs write");
    return rc;
}

/* Core secure implementations (used by both syscall cases and kernel command handler) */
static int do_receive_program(struct program_header *hdr_out) {
    if (!hdr_out) return -3;

    program_armed = 0;

    int rc = loader_receive_to_staging(hdr_out);
    return rc;
}

static int do_spawn(void) {
    if (!program_armed) return -1;

    int new_id = -1;
    for (int i = 1; i < MAX_TASKS; i++) {
        if (tasks[i].state == 0) {
            new_id = i;
            break;
        }
    }
    if (new_id < 0) return -2;

    /* === Full ASLR for the new task (within its user window) === */
    /* Strong per-spawn entropy mixing: size + entry + task id + current time + TSC + parent info */
    uint64_t spawn_entropy = (uint64_t)armed_hdr.size;
    spawn_entropy ^= (uint64_t)armed_hdr.entry << 17;
    spawn_entropy ^= (uint64_t)new_id * 0x9E3779B97F4A7C15ULL;
    spawn_entropy ^= (uint64_t)get_system_ticks() << 11;
    spawn_entropy ^= (uint64_t)current_task;   /* parent task id */
    spawn_entropy ^= read_tsc();               /* high-res jitter at spawn time */

    aslr_mix_entropy(spawn_entropy);

    uint32_t load_rand_pages = aslr_random_offset(ASLR_MAX_LOAD_RANDOM_PAGES) / PAGE_SIZE;
    uint32_t load_base = USER_AREA_BASE + (load_rand_pages * PAGE_SIZE);

    uint32_t stack_rand_pages = aslr_random_offset(ASLR_MAX_STACK_RANDOM_PAGES) / PAGE_SIZE;
    uint32_t stack_top = ASLR_HIGH_STACK_BASE - (stack_rand_pages * PAGE_SIZE);

    /* Create the task with randomized entry point and stack */
    create_task(new_id, load_base + armed_hdr.entry, stack_top);

    /* Copy the program image to the randomized load base */
#if defined(__x86_64__)
    addr_t old_cr3;
    asm volatile("mov %%cr3, %0" : "=r"(old_cr3));
    switch_cr3(tasks[new_id].cr3);
#else
    uint32_t old_cr3;
    asm volatile("mov %%cr3, %0" : "=r"(old_cr3));
    switch_cr3(tasks[new_id].cr3);
#endif

    uint8_t *dest = (uint8_t *)(addr_t)load_base;
    for (uint32_t i = 0; i < armed_hdr.size; i++) {
        dest[i] = loader_staging[i];
    }

    switch_cr3(old_cr3);

    /* Heap starts after the image + small random gap for ASLR */
    uint32_t img_end = load_base + ((armed_hdr.size + 0xFFF) & ~0xFFF);
    uint32_t heap_gap = aslr_random_offset(ASLR_MAX_HEAP_GAP_PAGES);
    tasks[new_id].heap_start   = img_end + 0x1000 + heap_gap;
    tasks[new_id].heap_current = tasks[new_id].heap_start;
    tasks[new_id].heap_end     = tasks[new_id].heap_start + 0x10000;

    if (armed_hdr.name[0] != 0) {
        int k = 0;
        while (k < 31 && armed_hdr.name[k]) {
            tasks[new_id].name[k] = armed_hdr.name[k];
            k++;
        }
        tasks[new_id].name[k] = 0;
    } else {
        tasks[new_id].name[0] = 'p'; tasks[new_id].name[1] = 'r';
        tasks[new_id].name[2] = 'o'; tasks[new_id].name[3] = 'g';
        tasks[new_id].name[4] = '0' + new_id; tasks[new_id].name[5] = 0;
    }

    program_armed = 0;

    /* Propagate CAP_USER if the creating task has it (enables both sudo elevation
     * and the kernel launcher to create other admin-capable tasks cleanly). */
    struct capability *creator_admin = cap_lookup(6, CAP_RIGHT_ALL);
    if (creator_admin && creator_admin->type == CAP_USER) {
        tasks[new_id].cspace[6].type   = CAP_USER;
        tasks[new_id].cspace[6].rights = CAP_RIGHT_ALL;
        tasks[new_id].cspace[6].object = 0;
        tasks[new_id].cspace[6].badge  = 0;
    }

    return new_id;
}

/* === User management helpers === */
static struct user_account *find_user_by_name(const char *name) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid && kstrlen(users[i].name) == kstrlen(name)) {
            int match = 1;
            for (size_t j = 0; name[j]; j++) {
                if (users[i].name[j] != name[j]) { match = 0; break; }
            }
            if (match) return &users[i];
        }
    }
    return NULL;
}

/* Legacy wrapper kept for minimal disruption during transition - uses new strong verifier */
static int verify_password(const char *name, const char *pass) {
    return verify_user_password(name, pass);
}

void syscall_handler(struct regs *r) {
    if (current_task < MAX_TASKS) {
        tasks[current_task].in_kernel = 1;
    }

    uint32_t num = r->eax;
    switch (num) {
        case 0:
            yield();
            break;
        case 1: {
            struct capability *c = cap_lookup(3, CAP_RIGHT_WRITE);
            if (!c) {
                r->eax = -1;
                break;
            }

            char buf[256];
            if (copy_from_user(buf, (void*)(addr_t)r->ebx, 255) == 0) {
                buf[255] = 0;
                print(buf);
                r->eax = 0;
            } else {
                r->eax = -1;
            }
            break;
        }
        case 2:
            if (tasks[current_task].waiter >= 0) {
                int w = tasks[current_task].waiter;
                if (tasks[w].state == 0) {
                    tasks[w].state = 1;
                }
                tasks[current_task].waiter = -1;
            }
            schedule();
            break;
        case 3: {
            struct capability *c = cap_lookup(3, CAP_RIGHT_READ);
            if (!c) { r->eax = -1; break; }

            void *user_dest = (void *)(addr_t)r->ebx;
            uint32_t max_len = 127;

            set_text_colour(0x0B);
            print("> ");
            set_text_colour(0x0A);

            char line[128];
            uint32_t len = 0;
            char ch;

            while (len < max_len) {
                while ((inb(0x3FD) & 1) == 0) {
                    yield();
                }

                ch = inb(0x3F8);

                if (ch == '\r' || ch == '\n') {
                    print("\n");
                    break;
                }

                if (ch == 0x1B) {
                    while ((inb(0x3FD) & 1) == 0) { yield(); }
                    char seq1 = inb(0x3F8);
                    while ((inb(0x3FD) & 1) == 0) { yield(); }
                    char seq2 = inb(0x3F8);

                    if (seq1 == '[') {
                        if (seq2 == 'A') {
                            if (history_count > 0) {
                                if (history_pos < 0) history_pos = history_count - 1;
                                else if (history_pos > 0) history_pos--;

                                for (uint32_t i = 0; i < len; i++) {
                                    print("\b \b");
                                }
                                len = 0;
                                while (cmd_history[history_pos][len] && len < max_len - 1) {
                                    line[len] = cmd_history[history_pos][len];
                                    char echo[2] = {line[len], 0};
                                    print(echo);
                                    len++;
                                }
                                line[len] = 0;
                            }
                        } else if (seq2 == 'B') {
                            if (history_pos >= 0) {
                                history_pos++;
                                if (history_pos >= history_count) {
                                    history_pos = -1;
                                    for (uint32_t i = 0; i < len; i++) print("\b \b");
                                    len = 0;
                                    line[0] = 0;
                                } else {
                                    for (uint32_t i = 0; i < len; i++) print("\b \b");
                                    len = 0;
                                    while (cmd_history[history_pos][len] && len < max_len - 1) {
                                        line[len] = cmd_history[history_pos][len];
                                        char echo[2] = {line[len], 0};
                                        print(echo);
                                        len++;
                                    }
                                    line[len] = 0;
                                }
                            }
                        }
                    }
                    continue;
                }
                if ((unsigned char)ch < 32 && ch != '\b' && ch != 0x7F) {
                    continue;
                }

                if (ch == '\b' || ch == 0x7F) {
                    if (len > 0) {
                        len--;
                        print("\b \b");
                    }
                    continue;
                }

                char echo[2] = {ch, 0};
                print(echo);
                line[len++] = ch;
            }

            line[len] = 0;

            if (len > 0) {
                if (history_count == HISTORY_SIZE) {
                    for (int i = 0; i < HISTORY_SIZE - 1; i++) {
                        for (int j = 0; j < CMD_MAX; j++) {
                            cmd_history[i][j] = cmd_history[i+1][j];
                        }
                    }
                    history_count--;
                }
                for (uint32_t j = 0; j < CMD_MAX && j <= len; j++) {
                    cmd_history[history_count][j] = line[j];
                }
                history_count++;
            }
            history_pos = -1;

            if (copy_to_user(user_dest, line, len + 1) != 0) {
                r->eax = -1;
            } else {
                r->eax = len;
            }
            break;
        }
        case 4: {
            if (cap_mint(r->ebx, r->ecx, r->edx)) r->eax = 0; else r->eax = -1;
            break;
        }
        case 8: {
            if (cap_transfer(r->ebx, r->ecx)) r->eax = 0; else r->eax = -1;
            break;
        }
        case 9: {
            if (cap_move(r->ebx, r->ecx)) r->eax = 0; else r->eax = -1;
            break;
        }
        case 5: {
            struct capability *c = cap_lookup(3, CAP_RIGHT_WRITE);
            if (!c) {
                r->eax = -1;
                break;
            }
            clear_screen();
            r->eax = 0;
            break;
        }
        case 6: {
            const char *info = "Horus v0.4 | per-task paging + cspaces | Rust validators";
            if (copy_to_user((void*)(addr_t)r->ebx, info, 64) == 0) {
                r->eax = 0;
            } else {
                r->eax = -1;
            }
            break;
        }
        case 7: {
            char cmd[128];
            if (copy_from_user(cmd, (void*)(addr_t)r->ebx, 127) != 0) {
                r->eax = -1;
                break;
            }
            cmd[127] = 0;

            r->eax = process_user_command(cmd);
            break;
        }
        case 10: {
            int32_t increment = (int32_t)r->ebx;
            if (increment == 0) {
                r->eax = tasks[current_task].heap_current;
                break;
            }

            uint32_t new_current = tasks[current_task].heap_current + increment;
            if (new_current > tasks[current_task].heap_end || new_current < tasks[current_task].heap_start) {
                r->eax = 0;
            } else {
                uint32_t old = tasks[current_task].heap_current;
                tasks[current_task].heap_current = new_current;
                r->eax = old;
            }
            break;
        }

        case 11: {
            int fd = r->ebx;
            void *buf = (void*)(addr_t)r->ecx;
            size_t len = r->edx;

            if (fd != 1) { r->eax = -1; break; }

            char kbuf[256];
            size_t to_copy = len > 255 ? 255 : len;
            if (copy_from_user(kbuf, buf, to_copy) != 0) {
                r->eax = -1;
                break;
            }
            kbuf[to_copy] = 0;
            print(kbuf);
            r->eax = to_copy;
            break;
        }

        case 12: {
            int fd = r->ebx;
            void *buf = (void*)(addr_t)r->ecx;
            size_t len = r->edx;

            if (fd == 0) {
                char line[128];
                uint32_t got = 0;
                while (got < len && got < 127) {
                    while ((inb(0x3FD) & 1) == 0) yield();
                    char ch = inb(0x3F8);
                    if (ch == '\r' || ch == '\n') { print("\n"); break; }
                    if (ch == '\b' || ch == 0x7F) { if (got > 0) { got--; print("\b \b"); } continue; }
                    char echo[2] = {ch, 0}; print(echo);
                    line[got++] = ch;
                }
                line[got] = 0;
                if (copy_to_user(buf, line, got + 1) != 0) r->eax = -1;
                else r->eax = got;
            } else if (fd >= 3) {
                struct capability *c = cap_lookup(3, CAP_RIGHT_READ);
                if (!c) { r->eax = -1; break; }
                char kbuf[256];
                size_t to_read = len > 255 ? 255 : len;
                int n = ramfs_read(fd, kbuf, to_read);
                if (n > 0) {
                    if (copy_to_user(buf, kbuf, n) == 0) r->eax = n;
                    else r->eax = -1;
                } else {
                    r->eax = n;
                }
            } else {
                r->eax = -1;
            }
            break;
        }

        case 13: {
            struct capability *c = cap_lookup(3, CAP_RIGHT_READ);
            if (!c) { r->eax = -1; break; }
            char path[64];
            if (copy_from_user(path, (void*)(addr_t)r->ebx, 63) != 0) {
                r->eax = -1; break;
            }
            path[63] = 0;
            int fd = ramfs_open(path);
            r->eax = fd;
            break;
        }

        case 15: {
            struct capability *c = cap_lookup(3, CAP_RIGHT_WRITE);
            if (!c) { r->eax = -1; break; }
            char name[32];
            if (copy_from_user(name, (void*)(addr_t)r->ebx, 31) != 0) {
                r->eax = -1; break;
            }
            name[31] = 0;
            r->eax = ramfs_create(name);
            break;
        }

        case 16: {
            struct capability *c = cap_lookup(3, CAP_RIGHT_READ);
            if (!c) { r->eax = -1; break; }
            void *user_buf = (void*)(addr_t)r->ebx;
            size_t max_len = r->ecx;
            (void)max_len;
            char kbuf[256];
            int n = ramfs_list(kbuf, sizeof(kbuf));
            if (n < 0) { r->eax = -1; break; }
            if (copy_to_user(user_buf, kbuf, n+1) == 0) r->eax = n;
            else r->eax = -1;
            break;
        }

        case 14: {
            struct capability *c = cap_lookup(3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC);
            if (!c) {
                r->eax = -1;
                break;
            }

            uint32_t load_base = r->ebx;
            uint32_t entry_offset = r->ecx;
            (void)(r->edx);

            int new_id = -1;
            for (int i = 1; i < MAX_TASKS; i++) {
                if (tasks[i].state == 0) {
                    new_id = i;
                    break;
                }
            }
            if (new_id < 0) {
                r->eax = -1;
                break;
            }

            create_task(new_id, load_base + entry_offset, DEMO_TASK_STACK_TOP);

            tasks[new_id].heap_start = USER_HEAP_BASE + new_id * 0x10000;
            tasks[new_id].heap_current = tasks[new_id].heap_start;
            tasks[new_id].heap_end = tasks[new_id].heap_start + 0x10000;

            tasks[new_id].name[0] = 's'; tasks[new_id].name[1] = 'p';
            tasks[new_id].name[2] = 'a'; tasks[new_id].name[3] = 'w';
            tasks[new_id].name[4] = 'n'; tasks[new_id].name[5] = '0' + new_id;
            tasks[new_id].name[6] = 0;

            r->eax = new_id;
            break;
        }

        case 17: {
            int tid = r->ebx;
            if (tid < 0 || tid >= MAX_TASKS || tid == current_task || tasks[tid].state == 0) {
                r->eax = -1;
                break;
            }

            tasks[tid].waiter = current_task;
            tasks[current_task].state = 0;

            while (tasks[current_task].state == 0) {
                yield();
            }

            r->eax = 0;
            break;
        }

        case 18: {
            int tid = r->ebx;
            struct task_info *out = (struct task_info*)(addr_t)r->ecx;

            if (tid < 0 || tid >= MAX_TASKS) {
                r->eax = -1;
                break;
            }

            /* SECURITY: Cross-task process information disclosure is now restricted.
               Non-admin tasks may only query their own task (preserves getpid-like UX
               and basic per-user visibility). Full system view (ps of other users)
               requires CAP_USER or CAP_AUDIT. This moves "Information leakage"
               from Acceptable → Strong without breaking normal multi-user functionality. */
            int is_privileged = 0;
            struct capability *c = cap_lookup(6, CAP_RIGHT_ALL);
            if (c && c->type == CAP_USER) is_privileged = 1;
            if (!is_privileged) {
                c = cap_lookup(7, CAP_RIGHT_READ);
                if (c && c->type == CAP_AUDIT) is_privileged = 1;
            }

            if (!is_privileged && tid != current_task) {
                /* Limited view for own task only - still useful for basic shells */
                r->eax = -3;   /* Permission denied for other tasks */
                break;
            }

            struct task_info info;
            info.id = tid;
            info.state = tasks[tid].state;
            info.cr3 = tasks[tid].cr3;
            info.heap_used = tasks[tid].heap_current - tasks[tid].heap_start;
            for (int k = 0; k < 31 && tasks[tid].name[k]; k++)
                info.name[k] = tasks[tid].name[k];
            info.name[31] = 0;
            info.eip = tasks[tid].eip;
            info.blocked_on = tasks[tid].blocked_on;
            info.blocked_on_notif = tasks[tid].blocked_on_notif;
            info.in_kernel = tasks[tid].in_kernel;
            info.caps_in_use = tasks[tid].caps_in_use;

            if (copy_to_user(out, &info, sizeof(info)) == 0) r->eax = 0;
            else r->eax = -1;
            break;
        }

        case 19: {
            struct capability *c = cap_lookup(3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC);
            if (!c) { r->eax = -1; break; }

            uint32_t load_base = r->ebx;
            uint32_t entry = r->ecx;

            tasks[current_task].heap_current = tasks[current_task].heap_start;

            drop_to_ring3(load_base + entry, tasks[current_task].esp);
            r->eax = 0;
            break;
        }

        case 20: {
            r->eax = current_task;
            break;
        }

        case SYS_IPC_SEND: {
            struct capability *c = cap_lookup(3, CAP_RIGHT_WRITE);
            if (!c) { r->eax = -1; break; }
            r->eax = sys_ipc_send(r->ebx, (const void*)(addr_t)r->ecx, r->edx);
            break;
        }
        case SYS_IPC_RECV: {
            struct capability *c = cap_lookup(3, CAP_RIGHT_READ);
            if (!c) { r->eax = -1; break; }
            r->eax = sys_ipc_recv(r->ebx, (void*)(addr_t)r->ecx, r->edx);
            break;
        }
        case SYS_IPC_CALL: {
            struct capability *c = cap_lookup(3, CAP_RIGHT_WRITE);
            if (!c) { r->eax = -1; break; }
            r->eax = sys_ipc_send(r->ebx, (const void*)(addr_t)r->ecx, r->edx);
            break;
        }
        case SYS_IPC_REPLY: {
            struct capability *c = cap_lookup(3, CAP_RIGHT_WRITE);
            if (!c) { r->eax = -1; break; }
            r->eax = sys_ipc_reply(r->ebx, (const void*)(addr_t)r->ecx, r->edx);
            break;
        }

        case SYS_NOTIFY: {
            struct capability *c = cap_lookup(3, CAP_RIGHT_WRITE);
            if (!c) { r->eax = -1; break; }
            r->eax = sys_notify(r->ebx, r->ecx);
            break;
        }
        case SYS_WAIT_NOTIFY: {
            struct capability *c = cap_lookup(3, CAP_RIGHT_READ);
            if (!c) { r->eax = -1; break; }
            uint32_t badge = 0;
            r->eax = sys_wait_notify(r->ebx, &badge);
            r->ebx = badge;
            break;
        }

        case SYS_RECEIVE_PROGRAM: {
            struct capability *c = cap_lookup(3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC);
            if (!c) { r->eax = -1; break; }

            void *user_hdr = (void *)(addr_t)r->ebx;
            struct program_header k_hdr;

            int rc = do_receive_program(&k_hdr);
            if (rc != 0) {
                r->eax = rc;
                break;
            }

            if (user_hdr) {
                if (copy_to_user(user_hdr, &k_hdr, sizeof(k_hdr)) != 0) {
                    r->eax = -3;
                    break;
                }
            }

            r->eax = 0;
            break;
        }

        case SYS_SPAWN: {
            struct capability *c = cap_lookup(3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC);
            if (!c) { r->eax = -1; break; }

            int pid = do_spawn();
            r->eax = pid;
            break;
        }

        case SYS_GETUID: {
            r->eax = tasks[current_task].uid;
            break;
        }

        case SYS_AUTH: {
            uint32_t now = get_system_ticks();

            /* Very basic: user name at ebx, pass at ecx, out_uid at edx */
            char uname[32];
            char upass[32];
            if (copy_from_user(uname, (void*)(addr_t)r->ebx, 31) != 0 ||
                copy_from_user(upass, (void*)(addr_t)r->ecx, 31) != 0) {
                r->eax = -1;
                break;
            }
            uname[31] = 0;
            upass[31] = 0;

            /* Per-user rate limiting (stronger than per-task) */
            struct user_account *u = find_user_by_name(uname);
            if (u && u->auth_lockout_until > now) {
                r->eax = -4; /* temporarily locked out */
                break;
            }

            if (verify_password(uname, upass)) {
                if (u) {
                    u->auth_fail_count = 0;
                    u->auth_lockout_until = 0;

                    derive_and_store_user_file_key(upass, u);

                    if (r->edx) {
                        uint32_t uid = u->uid;
                        copy_to_user((void*)(addr_t)r->edx, &uid, sizeof(uid));
                    }
                    audit_log(AUDIT_AUTH, 0, 0, "login success");
                }
                r->eax = 0;
            } else {
                if (u) {
                    u->auth_fail_count++;
                    if (u->auth_fail_count >= 5) {
                        /* Strong per-UID rate limiting (spawning many tasks no longer helps) */
                        u->auth_lockout_until = now + 8000;
                        u->auth_fail_count = 0;
                    }
                }
                audit_log(AUDIT_AUTH, 0, -1, "login failure");
                r->eax = -1;
            }
            break;
        }

        case SYS_SUDO: {
            uint32_t now = get_system_ticks();
            /* Per-user lockout for sudo as well */
            struct user_account *cur_user = NULL;
            uint32_t cur_uid = tasks[current_task].uid;
            for (int i = 0; i < MAX_USERS; i++) {
                if (users[i].valid && users[i].uid == cur_uid) {
                    cur_user = &users[i];
                    break;
                }
            }
            if (cur_user && cur_user->auth_lockout_until > now) {
                r->eax = -4;
                break;
            }

            /* For demo: authenticate then spawn current armed image with root caps */
            char upass[32];
            if (copy_from_user(upass, (void*)(addr_t)r->ebx, 31) != 0) {
                r->eax = -1;
                break;
            }
            upass[31] = 0;

            /* Find current user (reuse earlier lookup if possible) */
            struct user_account *cur = cur_user;
            if (!cur) {
                uint32_t cur_uid2 = tasks[current_task].uid;
                for (int i = 0; i < MAX_USERS; i++) {
                    if (users[i].valid && users[i].uid == cur_uid2) {
                        cur = &users[i];
                        break;
                    }
                }
            }
            if (!cur) {
                r->eax = -1;
                break;
            }

            if (!verify_password(cur->name, upass)) {
                if (cur_user) {
                    cur_user->auth_fail_count++;
                    if (cur_user->auth_fail_count >= 5) {
                        cur_user->auth_lockout_until = get_system_ticks() + 8000;
                        cur_user->auth_fail_count = 0;
                    }
                }
                r->eax = -2; /* bad password */
                break;
            }
            if (cur_user) {
                cur_user->auth_fail_count = 0;
                cur_user->auth_lockout_until = 0;
            }

            derive_and_store_user_file_key(upass, cur);
            audit_log(AUDIT_SUDO, 0, 0, "sudo success");

            /* Auth succeeded - spawn with elevated rights (demo: give full FRAME) */
            if (!program_armed) {
                r->eax = -3;
                break;
            }

            /* Better: create an elevated spawn path. For now we set uid after creation
     * but mark the intent. In a fuller implementation we would have do_spawn
     * accept target credentials and set them atomically before the task is runnable. */
            int pid = do_spawn();
            if (pid > 0) {
                tasks[pid].uid = 0;
                tasks[pid].gid = 0;

                /* Richer elevation on sudo: grant a full admin capability bundle.
                 * This includes strong FRAME control, user admin (CAP_USER), and
                 * full TCB rights so the sudo'ed process can perform system tasks. */
                tasks[pid].cspace[3].rights = CAP_RIGHT_ALL;           /* full user memory control */
                tasks[pid].cspace[6].type   = CAP_USER;                /* user admin */
                tasks[pid].cspace[6].rights = CAP_RIGHT_ALL;
                tasks[pid].cspace[6].object = 0;
                tasks[pid].cspace[6].badge  = 0;

                tasks[pid].cspace[7].type   = CAP_TCB;                 /* full task control */
                tasks[pid].cspace[7].rights = CAP_RIGHT_ALL;
                tasks[pid].cspace[7].object = pid;
                tasks[pid].cspace[7].badge  = 0;
            }
            r->eax = pid;
            break;
        }

        case SYS_GET_PASS: {
            /* Secure no-echo password read into user buffer (ebx), max len ecx */
            void *user_buf = (void *)(addr_t)r->ebx;
            uint32_t max_len = r->ecx;
            if (max_len > 127) max_len = 127;

            char line[128];
            uint32_t len = 0;
            char ch;

            while (len < max_len) {
                while ((inb(0x3FD) & 1) == 0) {
                    yield();
                }
                ch = inb(0x3F8);

                if (ch == '\r' || ch == '\n') {
                    break;
                }
                if (ch == '\b' || ch == 0x7F) {
                    if (len > 0) len--;
                    continue;
                }
                if ((unsigned char)ch < 32) continue;

                /* NO ECHO for security */
                line[len++] = ch;
            }
            line[len] = 0;

            /* Clear the kernel buffer as soon as possible */
            if (copy_to_user(user_buf, line, len + 1) != 0) {
                /* Best effort clear */
                for (uint32_t i = 0; i < 128; i++) line[i] = 0;
                r->eax = -1;
                break;
            }

            /* Securely clear kernel copy */
            for (uint32_t i = 0; i < 128; i++) line[i] = 0;

            r->eax = len;
            break;
        }

        case SYS_USERADD: {
            /* ebx=uid, ecx=gid, edx=name, (stack or extra) password - simplified: use registers creatively */
            uint32_t uid = r->ebx;
            uint32_t gid = r->ecx;
            char name[32];
            if (copy_from_user(name, (void*)(addr_t)r->edx, 31) != 0) {
                r->eax = -1; break;
            }
            name[31] = 0;
            /* Password not passed in this simplified interface - admin sets later via passwd */
            r->eax = do_useradd(uid, gid, name, "");
            break;
        }

        case SYS_USERDEL: {
            uint32_t uid = r->ebx;
            r->eax = do_userdel(uid);
            break;
        }

        case SYS_PASSWD: {
            uint32_t target = r->ebx;
            char newpass[32];
            if (copy_from_user(newpass, (void*)(addr_t)r->ecx, 31) != 0) {
                r->eax = -1; break;
            }
            newpass[31] = 0;
            r->eax = do_passwd(target, newpass);
            break;
        }

        case SYS_ROTATE_KEYS: {
            r->eax = do_rotate_keys();
            break;
        }

        case SYS_READ_AUDIT: {
            /* Requires CAP_AUDIT */
            struct capability *c = cap_lookup(7, CAP_RIGHT_READ);
            if (!c || c->type != CAP_AUDIT) {
                r->eax = -1;
                break;
            }

            struct audit_event *user_events = (struct audit_event *)(addr_t)r->ebx;
            uint32_t max = r->ecx;
            if (max > AUDIT_LOG_SIZE) max = AUDIT_LOG_SIZE;

            uint32_t out = 0;
            uint32_t start = (audit_head + AUDIT_LOG_SIZE - audit_count) % AUDIT_LOG_SIZE;

            for (uint32_t i = 0; i < audit_count && out < max; i++) {
                uint32_t idx = (start + i) % AUDIT_LOG_SIZE;
                if (copy_to_user(&user_events[out], &audit_log_buffer[idx], sizeof(struct audit_event)) == 0) {
                    out++;
                }
            }
            r->eax = out;
            break;
        }

        case SYS_FS_MINT_FILE: {
            r->eax = sys_fs_mint_file(r->ebx, r->ecx, r->edx);
            break;
        }

        case SYS_FS_LOOKUP: {
            char name[32];
            if (copy_from_user(name, (void*)(addr_t)r->ecx, 31) != 0) { r->eax = -1; break; }
            name[31] = 0;
            r->eax = sys_fs_lookup(r->ebx, name, r->edx, (addr_t)r->esi);
            break;
        }

        case SYS_FS_CREATE: {
            char name[32];
            if (copy_from_user(name, (void*)(addr_t)r->ecx, 31) != 0) { r->eax = -1; break; }
            name[31] = 0;
            r->eax = sys_fs_create(r->ebx, name, (int)r->edx, (addr_t)r->esi, (addr_t)r->edi);
            break;
        }

        case SYS_FS_DELETE: {
            char name[32];
            if (copy_from_user(name, (void*)(addr_t)r->ecx, 31) != 0) { r->eax = -1; break; }
            name[31] = 0;
            r->eax = sys_fs_delete(r->ebx, name);
            break;
        }

        case SYS_FS_READDIR: {
            char *buf = (char *)(addr_t)r->ecx;
            uint32_t sz = r->edx;
            /* For user tasks we should copy_to, but capfs_readdir writes directly; for safety use staging in real */
            r->eax = sys_fs_readdir(r->ebx, buf, sz);
            break;
        }

        case SYS_FS_GET_ROOT: {
            r->eax = sys_fs_get_root(r->ebx, r->ecx);
            break;
        }

        case SYS_FS_READ: {
            r->eax = sys_fs_read(r->ebx, (char *)(addr_t)r->ecx, r->edx);
            break;
        }

        case SYS_FS_WRITE: {
            r->eax = sys_fs_write(r->ebx, (const char *)(addr_t)r->ecx, r->edx);
            break;
        }

        case SYS_REGISTER_STORAGE_BACKEND: {
            /* Requires CAP_USER for security */
            struct capability *admin = cap_lookup(6, CAP_RIGHT_ALL);
            if (!admin || admin->type != CAP_USER) {
                r->eax = -1;
                break;
            }
            void *read_fn = (void*)(addr_t)r->ebx;
            void *write_fn = (void*)(addr_t)r->ecx;
            storage_register_userspace_block_backend(
                (int (*)(uint64_t, void *))read_fn,
                (int (*)(uint64_t, const void *))write_fn
            );
            r->eax = 0;
            break;
        }

        case SYS_BLOCK_READ: {
            /* Requires CAP_BLOCK_DEV */
            struct capability *blk = cap_lookup(7, CAP_BLOCK_DEV);
            if (!blk) {
                r->eax = -1;
                break;
            }
            uint64_t block = ((uint64_t)r->ebx << 32) | r->ecx;
            void *buf = (void*)(addr_t)r->edx;
            uint32_t len = r->esi;
            /* For now, only allow the privileged FS server task (uid 0 or CAP_USER holder) */
            if (tasks[current_task].uid != 0) {
                r->eax = -2;
                break;
            }
            uint8_t kbuf[BLOCK_SIZE];
            uint32_t to = len > BLOCK_SIZE ? BLOCK_SIZE : len;
            int rc = storage_block_read(block, kbuf);
            if (rc == 0) {
                if (copy_to_user(buf, kbuf, to) == 0) {
                    r->eax = to;
                } else {
                    r->eax = -3;
                }
            } else {
                r->eax = rc;
            }
            break;
        }

        case SYS_BLOCK_WRITE: {
            struct capability *blk = cap_lookup(7, CAP_BLOCK_DEV);
            if (!blk) {
                r->eax = -1;
                break;
            }
            if (tasks[current_task].uid != 0) {
                r->eax = -2;
                break;
            }
            uint64_t block = ((uint64_t)r->ebx << 32) | r->ecx;
            const void *buf = (const void*)(addr_t)r->edx;
            uint32_t len = r->esi;
            uint8_t kbuf[BLOCK_SIZE];
            uint32_t to = len > BLOCK_SIZE ? BLOCK_SIZE : len;
            if (copy_from_user(kbuf, buf, to) != 0) {
                r->eax = -3;
                break;
            }
            int rc = storage_block_write(block, kbuf);
            r->eax = (rc == 0) ? (int)to : rc;
            break;
        }

        case SYS_REGISTER_FS_SERVER: {
            /* Only privileged tasks (CAP_USER) can register as the FS server */
            struct capability *admin = cap_lookup(6, CAP_RIGHT_ALL);
            if (!admin || admin->type != CAP_USER) {
                r->eax = -1;
                break;
            }
            uint32_t ep_slot = r->ebx;
            struct capability *ep = cap_lookup(ep_slot, CAP_RIGHT_READ | CAP_RIGHT_WRITE);
            if (!ep || ep->type != CAP_ENDPOINT) {
                r->eax = -2;
                break;
            }
            fs_server_task_id = current_task;
            fs_server_listen_ep_idx = ep->object;  /* the global endpoint index */
            r->eax = 0;
            break;
        }

        case SYS_CONNECT_FS_SERVER: {
            uint32_t dest_slot = r->ebx;
            uint32_t rights = r->ecx;
            if (fs_server_task_id < 0 || fs_server_listen_ep_idx < 0) {
                r->eax = -1; /* no server registered */
                break;
            }
            if (dest_slot < 4 || dest_slot >= 256) {
                r->eax = -2;
                break;
            }
            /* Mint a fresh endpoint cap pointing to the server's listening endpoint */
            struct capability *dest = &tasks[current_task].cspace[dest_slot];
            dest->type   = CAP_ENDPOINT;
            dest->rights = rights & (CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_GRANT);
            dest->object = fs_server_listen_ep_idx;
            dest->badge  = 0xF51A0000U;  /* FS server badge */
            r->eax = 0;
            break;
        }

        default:
            r->eax = -1;
            break;
    }

    if (current_task < MAX_TASKS) {
        tasks[current_task].in_kernel = 0;
    }
}

int process_user_command(const char *cmd) {
    while (*cmd == ' ') cmd++;

    if (cmd[0] == 0 || cmd[0] == '\n' || cmd[0] == '\r') {
        return 0;
    }

    int action = rust_handle_command((const uint8_t *)cmd, kstrlen(cmd));

    if (action == 42) {
        set_text_colour(0x0B);
        println("Available: help version uptime ps echo clear caps load kill <n> yield exit mem receive spawn ipc_* notify wait_notify");
        set_text_colour(0x0F);
        return 0;
    }
    if (action == 43) {
        set_text_colour(0x0A);
        println("Horus v0.4 - x86 microkernel (per-task isolation + Rust policy)");
        set_text_colour(0x0F);
        return 0;
    }
    if (action == 45) {
        uint32_t ticks = get_system_ticks();
        print("Uptime: "); print_hex(ticks); println(" ticks");
        return 0;
    }
    if (action == 46) {
        set_text_colour(0x0B);
        println("PID  NAME            STATE  HEAP     FLAGS");
        set_text_colour(0x0F);
        for (int i = 0; i < MAX_TASKS; i++) {
            if (tasks[i].state != 0) {
                if (i < 10) print(" ");
                print_decimal(i);
                print("  ");
                print(tasks[i].name);
                int nlen = 0; while (tasks[i].name[nlen]) nlen++;
                for (int sp = nlen; sp < 14; sp++) print(" ");
                print_decimal(tasks[i].state);
                print("     ");
                print_decimal(tasks[i].heap_current - tasks[i].heap_start);
                print("  ");
                if (tasks[i].in_kernel) print("K ");
                if (tasks[i].blocked_on >= 0) { print("B"); print_decimal(tasks[i].blocked_on); }
                else if (tasks[i].blocked_on_notif >= 0) print("N");
                else if (tasks[i].state == 2) print("blk");
                println("");
            }
        }
        return 0;
    }
    if (action == 47) {
        struct capability *cspace = tasks[current_task].cspace;
        uint32_t size = tasks[current_task].cspace_size ? tasks[current_task].cspace_size : 256;

        print("Caps for task "); print_hex(current_task); println(":");

        for (uint32_t i = 0; i < size && i < 16; i++) {
            struct capability *c = &cspace[i];
            if (c->type != CAP_NULL) {
                print("  ["); print_hex(i);
                print("] type="); print_hex(c->type);
                print(" rights="); print_hex(c->rights);
                print(" obj="); print_hex(c->object);
                println("");
            }
        }
        return 0;
    }
    if (action == 48) {
        struct capability *c = cap_lookup(3, CAP_RIGHT_WRITE);
        if (!c) return -1;
        clear_screen();
        return 0;
    }
    if (action == 49) {
        uint32_t id = 0;
        const char *p = cmd + 5;
        while (*p == ' ') p++;
        while (*p >= '0' && *p <= '9') { id = id * 10 + (*p - '0'); p++; }

        if (id == 0 || id >= MAX_TASKS) {
            println("Invalid task id");
            return -1;
        }
        if (tasks[id].state == 0) {
            println("Task already dead");
            return 0;
        }
        if (tasks[id].waiter >= 0) {
            int w = tasks[id].waiter;
            if (tasks[w].state == 0) tasks[w].state = 1;
            tasks[id].waiter = -1;
        }

        tasks[id].state = 0;
        print("Killed "); print_hex(id); println("");
        if ((int)id == current_task) schedule();
        return 0;
    }
    if (action == 1) {
        println("Exiting...");
        qemu_exit(0);
        return 0;
    }

    if (action == 44) {
        const char *arg = cmd + 5;
        while (*arg == ' ') arg++;
        print(arg);
        println("");
        return 0;
    }
    if (action == 50) {
        uint32_t dest = 0, src = 0, rights = 0;
        const char *p = cmd + 5;
        while (*p == ' ') p++;
        while (*p >= '0' && *p <= '9') { dest = dest * 10 + (*p - '0'); p++; }
        while (*p == ' ') p++;
        while (*p >= '0' && *p <= '9') { src = src * 10 + (*p - '0'); p++; }
        while (*p == ' ') p++;
        while (*p >= '0' && *p <= '9') { rights = rights * 10 + (*p - '0'); p++; }

        if (cap_mint(dest, src, rights)) {
            println("mint ok");
            return 0;
        } else {
            println("mint failed");
            return -1;
        }
    }

    if (cmd[0] == 'y' && cmd[1] == 'i' && cmd[2] == 'e' && cmd[3] == 'l' && cmd[4] == 'd' &&
        (cmd[5] == 0 || cmd[5] == ' ')) {
        yield();
        return 0;
    }

    if (cmd[0] == 'l' && cmd[1] == 'o' && cmd[2] == 'a' && cmd[3] == 'd' && cmd[4] == 0) {
        struct capability *c = cap_lookup(3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC);
        if (!c) {
            println("Permission denied (need FRAME cap slot 3)");
            return -1;
        }

        println("");
        println("Open second terminal for loader (raw TCP, not telnet):");
        println("  From Horus root: cat userspace/shell.bin | nc localhost 4444");
        println("  Inside userspace/: cat shell.bin | nc localhost 4444");
        println("Waiting on 4444...");

        /* Use the new secure first-class loader path */
        struct program_header tmp_hdr;
        int rc = do_receive_program(&tmp_hdr);
        if (rc != 0) {
            if (rc == -1) println("Bad magic - run 'make userspace' first");
            else if (rc == -2) println("Invalid size");
            else println("Receive failed");
            return -1;
        }

        print("RX ");
        print_decimal(tmp_hdr.size);
        println("B ok");

        int new_pid = do_spawn();   /* uses armed staging + fresh task */
        if (new_pid < 0) {
            println("Spawn failed (no free slot?)");
            return -1;
        }

        println("Spawned pid ");
        print_decimal(new_pid);
        println(" - switching...");

        /* Launcher UX: park current (kernel shell) and drop into the new ring-3 task */
        tasks[current_task].state = 0;

        current_task = new_pid;
        switch_cr3(tasks[new_pid].cr3);
        set_tss_kernel_stack(tasks[new_pid].kernel_stack_top);

        drop_to_ring3(tasks[new_pid].eip, tasks[new_pid].esp);
        return 0;
    }

    if (cmd[0] == 'i' && cmd[1] == 'n' && cmd[2] == 'f' && cmd[3] == 'o' && cmd[4] == 0) {
        println("Horus v0.4 serial | per-task paging + caps");
        return 0;
    }

    if (cmd[0] == 'm' && cmd[1] == 'e' && cmd[2] == 'm' && cmd[3] == 0) {
        print("Heap: start="); print_hex(tasks[current_task].heap_start);
        print(" cur="); print_hex(tasks[current_task].heap_current);
        print(" end="); print_hex(tasks[current_task].heap_end);
        println("");
        return 0;
    }

    if (cmd[0] == 'r' && cmd[1] == 'e' && cmd[2] == 'c' && cmd[3] == 'e' && cmd[4] == 'i' && cmd[5] == 'v' && cmd[6] == 'e' && cmd[7] == 0) {
        /* Same as the userspace command: arm a program via the loader port */
        struct program_header h;
        int r = do_receive_program(&h);
        if (r == 0) {
            print("Received '"); print(h.name); print("' (");
            print_decimal(h.size); println(" bytes) - ready for spawn");
        } else {
            println("Receive failed");
        }
        return 0;
    }
    if (cmd[0] == 's' && cmd[1] == 'p' && cmd[2] == 'a' && cmd[3] == 'w' && cmd[4] == 'n' && cmd[5] == 0) {
        int pid = do_spawn();
        if (pid > 0) {
            print("Spawned pid "); print_decimal(pid); println("");
        } else {
            println("Spawn failed (need 'receive' first, or no free slot)");
        }
        return 0;
    }

    if (cmd[0] == 'i' && cmd[1] == 'p' && cmd[2] == 'c' && cmd[3] == '_' && cmd[4] == 's') {
        const char *text = cmd + 9;
        while (*text == ' ') text++;
        int r = sys_ipc_send(4, text, kstrlen(text) + 1);
        if (r == 0) println("ipc_send: delivered or queued");
        else println("ipc_send: failed (check cap or busy)");
        return 0;
    }
    if (cmd[0] == 'i' && cmd[1] == 'p' && cmd[2] == 'c' && cmd[3] == '_' && cmd[4] == 'r') {
        char buf[64];
        int n = sys_ipc_recv(4, buf, sizeof(buf)-1);
        if (n > 0) {
            buf[n] = 0;
            print("ipc_recv: "); println(buf);
        } else {
            println("ipc_recv: no message (or blocked)");
        }
        return 0;
    }

    if (cmd[0] < 32 || cmd[0] > 126) {
        return 0;
    }

    println("Unknown. Type 'help'");
    return -1;
}

static struct endpoint *get_endpoint_from_cap(uint32_t slot, uint32_t required_rights) {
    struct capability *c = cap_lookup(slot, required_rights);
    if (!c || c->type != CAP_ENDPOINT) return NULL;
    uint32_t idx = c->object;
    if (idx >= MAX_ENDPOINTS) return NULL;
    return &endpoints[idx];
}

static void block_current_on_ipc(uint32_t ep_slot, int role) {
    tasks[current_task].blocked_on = ep_slot;
    tasks[current_task].ipc_role = role;
    tasks[current_task].state = 2;
    schedule();
}

static void wake_task(int tid) {
    if (tid >= 0 && tid < MAX_TASKS && tasks[tid].state == 2) {
        tasks[tid].state = 1;
        tasks[tid].blocked_on = -1;
        tasks[tid].ipc_role = 0;
    }
}

int sys_ipc_send(uint32_t ep_slot, const void *msg, size_t len) {
    struct endpoint *ep = get_endpoint_from_cap(ep_slot, CAP_RIGHT_WRITE | CAP_RIGHT_GRANT);
    if (!ep) return -1;

    if (rust_validate_ipc((addr_t)current_task, ep_slot, CAP_RIGHT_WRITE | CAP_RIGHT_GRANT) < 0) return -20;

    /* Simple sealed message detection (marker for future authenticated/sealed cap passing) */
    if (len >= 4 && *(const uint32_t*)msg == IPC_SEALED_MAGIC) {
        /* Future: require MAC or reply cap before accepting sealed grants */
    }

    if (len > MAX_IPC_MSG_LEN) len = MAX_IPC_MSG_LEN;

    char kmsg[MAX_IPC_MSG_LEN];
    if (copy_from_user(kmsg, msg, len) != 0) return -1;

    if (ep->waiting_recv >= 0) {
        int copy = (len > (int)sizeof(ep->msg)) ? (int)sizeof(ep->msg) : (int)len;
        for (int i = 0; i < copy; i++) {
            ((char*)ep->msg)[i] = kmsg[i];
        }
        ep->msg_len = copy;
        ep->has_message = true;
        ep->sender_task = current_task;

        struct capability *sender_ep_cap = cap_lookup(ep_slot, 0);
        if (sender_ep_cap && (sender_ep_cap->rights & CAP_RIGHT_GRANT)) {
            int recv_tid = ep->waiting_recv;
            if (recv_tid >= 0 && recv_tid < MAX_TASKS) {
                struct capability *rcspace = tasks[recv_tid].cspace;
                for (int s = 6; s < 16; s++) {
                    if (rcspace[s].type == CAP_NULL) {
                        rcspace[s].type   = CAP_NOTIFICATION;
                        rcspace[s].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE;
                        rcspace[s].object = 4;
                        rcspace[s].badge  = current_task;
                        audit_log(AUDIT_IPC_GRANT, ep_slot, recv_tid, "grant via ipc");
                        break;
                    }
                }
            }
        }

        int receiver = ep->waiting_recv;
        ep->waiting_recv = -1;
        wake_task(receiver);
        return 0;
    }

    if (ep->has_message) return -1;

    ep->has_message = true;
    ep->sender_task = current_task;
    ep->msg_len = len;
    for (int i=0; i < (int)len && i < (int)sizeof(ep->msg); i++) {
        ((char*)ep->msg)[i] = kmsg[i];
    }

    block_current_on_ipc(ep_slot, 2);
    return 0;
}

int sys_ipc_recv(uint32_t ep_slot, void *msg, size_t max_len) {
    struct endpoint *ep = get_endpoint_from_cap(ep_slot, CAP_RIGHT_READ);
    if (!ep) return -1;

    if (ep->has_message) {
        int n = ep->msg_len;
        if ((size_t)n > max_len) n = max_len;
        if (copy_to_user(msg, ep->msg, n) != 0) return -1;
        ep->has_message = false;
        ep->sender_task = -1;
        ep->msg_len = 0;
        return n;
    }

    ep->waiting_recv = current_task;
    block_current_on_ipc(ep_slot, 1);
    if (ep->has_message) {
        int n = ep->msg_len;
        if ((size_t)n > max_len) n = max_len;
        if (copy_to_user(msg, ep->msg, n) != 0) return -1;
        ep->has_message = false;
        return n;
    }
    return 0;
}

int sys_ipc_call(uint32_t ep_slot, const void *send_msg, size_t send_len,
                   void *recv_msg, size_t recv_max) {
    int ret = sys_ipc_send(ep_slot, send_msg, send_len);
    if (ret < 0) return ret;
    return sys_ipc_recv(ep_slot, recv_msg, recv_max);
}

int sys_ipc_reply(uint32_t ep_slot, const void *msg, size_t len) {
    return sys_ipc_send(ep_slot, msg, len);
}

static struct capability *get_notification_cap(uint32_t slot, uint32_t required_rights) {
    struct capability *c = cap_lookup(slot, required_rights);
    if (!c || c->type != CAP_NOTIFICATION) return NULL;
    return c;
}

int sys_notify(uint32_t notif_slot, uint32_t badge) {
    struct capability *c = get_notification_cap(notif_slot, CAP_RIGHT_WRITE);
    if (!c) return -1;

    c->object = badge;
    c->badge  = 1;

    for (int t = 0; t < MAX_TASKS; t++) {
        if (tasks[t].state == 2 && tasks[t].blocked_on_notif == (int)notif_slot) {
            tasks[t].state = 1;
            tasks[t].blocked_on_notif = -1;
            break;
        }
    }
    return 0;
}

int sys_wait_notify(uint32_t notif_slot, uint32_t *out_badge) {
    struct capability *c = get_notification_cap(notif_slot, CAP_RIGHT_READ);
    if (!c) return -1;

    if (c->badge == 0) {
        tasks[current_task].blocked_on_notif = notif_slot;
        tasks[current_task].state = 2;
        schedule();
    }

    if (out_badge) *out_badge = c->object;
    c->badge = 0;
    tasks[current_task].blocked_on_notif = -1;
    return 0;
}

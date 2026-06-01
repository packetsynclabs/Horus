#ifndef KERNEL_H
#define KERNEL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Address type that is 64 bits wide on x86-64 and 32 bits wide on i386.
   Used throughout the kernel for pointers and physical/virtual addresses. */
#ifdef __x86_64__
typedef uint64_t addr_t;
#else
typedef uint32_t addr_t;
#endif

#define PAGE_SIZE 4096
#define USER_VIRT_BASE 0x400000
#define KERNEL_STACK_SIZE 16384

#define USER_MEM_START   USER_VIRT_BASE
#define USER_MEM_END     (USER_VIRT_BASE + 0x400000)
#define USER_MEM_MAX_COPY 4096

#define DEMO_TASK_STACK_TOP   0x7FF000
#define KERNEL_TSS_STACK      0x200000
#define VGA_BUFFER            0xB8000
#define PIC1_CMD              0x20
#define PIC2_CMD              0xA0

#define USER_AREA_BASE        0x400000
#define USER_MAP_PAGES        640
#define USER_LOAD_BASE        0x500000
#define USER_HEAP_BASE        0x580000

/* ASLR parameters (within the per-task user window) */
#define ASLR_MAX_LOAD_RANDOM_PAGES   64     /* up to ~256KB randomization for load base */
#define ASLR_HIGH_STACK_BASE         0x650000
#define ASLR_MAX_STACK_RANDOM_PAGES  32
#define ASLR_MAX_HEAP_GAP_PAGES       8

#define MAX_ENDPOINTS 16
#define IPC_MSG_WORDS 4

struct endpoint {
    int waiting_recv;
    int waiting_send;
    uint32_t msg[IPC_MSG_WORDS];
    int msg_len;
    int sender_task;
    bool has_message;
};

#define MAX_IPC_MSG_LEN 64

/* Simple sealed message marker for future capability sealing / authenticated IPC */
#define IPC_SEALED_MAGIC 0x5345414C  /* 'SEAL' */

/* Audit logging */
#define AUDIT_LOG_SIZE 64

struct audit_event {
    uint32_t timestamp;
    uint32_t type;           /* AUDIT_* constants */
    uint32_t subject_uid;
    uint32_t subject_task;
    uint32_t object;         /* cap slot, file id, etc. */
    uint32_t result;         /* 0 = success, negative = error */
    char     message[48];
};

struct regs {
    uint32_t gs, fs, es, ds;
    uint32_t edi, esi, ebp, esp, ebx, edx, ecx, eax;
    uint32_t int_no, err_code;
    uint32_t eip, cs, eflags, useresp, ss;
};

/* 64-bit interrupt frame (pushed by lowlevel64.S + our stub) */
struct regs64 {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rbp, rdi, rsi, rdx, rcx, rbx, rax;
    uint64_t int_no, err_code;
    uint64_t rip, cs, rflags, rsp, ss;   /* user rsp/ss when from ring 3 */
};

typedef struct {
    addr_t   esp;               /* user stack pointer (or kernel esp when in_kernel) */
    addr_t   eip;               /* user instruction pointer */
    uint32_t state;
    uint32_t cap_tcb;
    addr_t   cr3;               /* per-task PML4 physical (0 = share kernel identity map for now) */
    uint32_t priority;
    struct capability *cspace;
    uint32_t cspace_size;
    addr_t   kernel_stack_top;  /* top of this task's dedicated kernel stack */

    addr_t   heap_start;
    addr_t   heap_current;
    addr_t   heap_end;

    char name[32];

    int waiter;

    int blocked_on;
    int ipc_role;
    uint32_t ipc_msg[IPC_MSG_WORDS];
    int ipc_msg_len;

    int in_kernel;

    int blocked_on_notif;

    /* User identity (for multi-user and sudo) */
    uint32_t uid;
    uint32_t gid;

    /* Very basic per-task auth rate limiting */
    uint32_t auth_fail_count;
    uint32_t auth_lockout_until;

    /* Per-session file encryption master key (derived at login/sudo, wiped on exit) */
    uint8_t user_file_master_key[32];
    int     has_file_key;   /* 0 = no valid key */

    /* Basic resource accounting / quotas (prevents cspace exhaustion attacks) */
    uint32_t caps_in_use;
} tcb_t;

#define MAX_TASKS 64  // Significantly raised thanks to large demand-paged physical pool + per-task quotas (caps_in_use, etc.)

/* Simple per-task capability quota (resource control + DoS protection) */
#define MAX_CAPS_PER_TASK 64

/* Simple user account database (research kernel - basic security) */
#define MAX_USERS 8
#define PASS_SALT_LEN 16
#define PASS_HASH_LEN 32

struct user_account {
    uint32_t uid;
    uint32_t gid;
    char     name[32];
    char     salt[PASS_SALT_LEN];
    char     pass_hash[PASS_HASH_LEN];
    char     home[64];
    char     shell[32];
    int      valid;

    /* Per-user auth rate limiting (moved from per-task for much stronger brute-force resistance) */
    uint32_t auth_fail_count;
    uint32_t auth_lockout_until;
};

struct task_info {
    uint32_t id;
    uint32_t state;
    addr_t   cr3;
    addr_t   heap_used;
    char     name[32];
    addr_t   eip;           /* current or last known */
    int      blocked_on;    /* -1 or cap slot */
    int      blocked_on_notif;
    int      in_kernel;
    uint32_t caps_in_use;   /* resource quota visibility */
};

void terminal_init(void);
void print(const char* str);
void println(const char* str);
void clear_screen(void);
void print_hex(uint32_t n);
void print_hex64(uint64_t n);   /* for 64-bit addresses and values */
void print_char(char c);
void print_decimal(uint32_t n);
void set_text_colour(uint8_t attr);

/* Boot log visual helpers for long, readable, non-ugly startup */
void print_hrule(uint8_t color);
void print_blanks(int count);
void print_section(const char* title, uint8_t title_color);

void gdt_init(void);
void set_tss_kernel_stack(uintptr_t esp0);
void tss_flush(void);

void idt_init(void);

void paging_init(void);
void create_user_pagedir(uint32_t task_id);
void switch_cr3(addr_t cr3);
void drop_to_ring3(addr_t entry, addr_t stack);   /* 64-bit: uses compat user segments for 32-bit binaries */
void create_task(int id, addr_t entry, addr_t stack_top);

#define CAP_RIGHT_READ     (1 << 0)
#define CAP_RIGHT_WRITE    (1 << 1)
#define CAP_RIGHT_GRANT    (1 << 2)
#define CAP_RIGHT_MINT     (1 << 3)
#define CAP_RIGHT_REVOKE   (1 << 4)
#define CAP_RIGHT_EXEC     (1 << 5)
#define CAP_RIGHT_ALL      (0x3F)

/* Filesystem-specific rights interpretations (for CAP_DIR / CAP_FILE) */
#define CAP_RIGHT_FS_LOOKUP   CAP_RIGHT_READ     /* Can resolve names in directory */
#define CAP_RIGHT_FS_CREATE   CAP_RIGHT_WRITE    /* Can create files/dirs */
#define CAP_RIGHT_FS_DELETE   (1 << 6)           /* Can delete/rename */
#define CAP_RIGHT_FS_READ     CAP_RIGHT_READ
#define CAP_RIGHT_FS_WRITE    CAP_RIGHT_WRITE
#define CAP_RIGHT_FS_EXEC     CAP_RIGHT_EXEC
#define CAP_RIGHT_FS_APPEND   (1 << 7)           /* Write-only append */
#define CAP_RIGHT_FS_TRUNCATE (1 << 8)
#define CAP_RIGHT_AUDIT_WRITE (1 << 9)           /* Ability to append to audit log (for future audit daemon) */

enum cap_type {
    CAP_NULL = 0,
    CAP_TCB,
    CAP_ENDPOINT,
    CAP_NOTIFICATION,
    CAP_CNODE,
    CAP_FRAME,
    CAP_IRQ_CONTROL,
    CAP_USER,          /* User account management */
    CAP_FS,            /* Filesystem root / volume */
    CAP_FILE,          /* Individual file capability */
    CAP_DIR,           /* Directory capability */
    CAP_AUDIT,         /* Ability to read/write audit logs */
    CAP_BLOCK_DEV,     /* Raw block device access (for userspace FS server / drivers) */
    CAP_REVOCATION,    /* Revocation handle: revoking this invalidates target + derived */
    CAP_MAX
};

struct capability {
    uint32_t type;
    uint32_t rights;
    uintptr_t object;   /* Pointer or object ID — now 64-bit clean */
    uint32_t badge;
};

/* =====================================================================
 * Threading + Shared Memory Model (64-bit ready design)
 * =====================================================================
 * 
 * Core concepts:
 *   - Task   : Protection domain (own CR3, own cspace, own memory objects)
 *   - Thread : Schedulable execution context (own kernel stack, registers, TLS)
 *
 * Multiple threads can share a task's address space and capabilities.
 * This is the foundation for a real multi-threaded userspace FS server, etc.
 *
 * Shared memory is represented as first-class Memory Objects (CAP_MEMORY_OBJECT).
 * These can be mapped into any task's address space with appropriate rights.
 */
#define MAX_THREADS_PER_TASK   16
#define MAX_MEMORY_OBJECTS     128

typedef struct thread {
    uint32_t tid;
    uint32_t state;           /* 0=dead, 1=ready, 2=running, 3=blocked, etc. */

    /* Full 64-bit execution state */
    uint64_t rsp0;            /* Kernel stack top (for this thread) */
    uint64_t rip;
    uint64_t rflags;
    uint64_t cr3;

    uint64_t gprs[16];        /* rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8-r15 */

    int      task_id;         /* Owning task */
    int      in_kernel;

    /* Scheduling */
    uint64_t time_slice;
    int      priority;
} thread_t;

typedef struct memory_object {
    uint64_t phys_base;
    uint64_t size;
    uint32_t refcount;
    uint32_t flags;           /* COW, executable, etc. */
    int      in_use;
} memory_object_t;

extern thread_t         threads[MAX_TASKS * MAX_THREADS_PER_TASK];
extern memory_object_t  memory_objects[MAX_MEMORY_OBJECTS];

/* =====================================================================
 * Shared Memory via Capabilities
 * =====================================================================
 * Memory objects that can be mapped into multiple tasks with fine-grained
 * rights and proper revocation.
 */
#define CAP_MEMORY_OBJECT   0x100   /* New capability type for shared memory */

/* (consolidated into the improved definition above) */

/* Capability-based Filesystem objects - first class, capability mediated */
#define FS_OBJ_FILE   1
#define FS_OBJ_DIR    2
#define MAX_FS_OBJECTS 16
#define FS_MAX_CHILDREN 8
#define FS_DATA_SIZE 4096

/* Note: In 64-bit these pointer fields become 64-bit naturally.
   We keep the design compatible. */
struct fs_object {
    uint32_t type;                    /* FS_OBJ_FILE or FS_OBJ_DIR */
    uint32_t size;
    uint8_t  data[FS_DATA_SIZE];      /* In-memory backing store (demand/COW later) */
    char     name[32];
    uint8_t  file_salt[16];           /* Per-object salt for encryption KDF */
    int      in_use;

    /* Ownership + transparent encryption (integrates with per-user master keys) */
    uint32_t owner_uid;
    int      is_encrypted;
    uint8_t  enc_file_key[32];        /* file key wrapped by user's master key */
    uint32_t file_key_iv;

    /* Directory children (for DIR objects) */
    struct fs_object *children[FS_MAX_CHILDREN];
    char              child_names[FS_MAX_CHILDREN][32];
    int               num_children;

    /* Integrity / future persistence tag */
    uint32_t integrity_tag;
};

struct fs_cap {
    struct fs_object *obj;
    uint32_t         rights;
};

/* =====================================================================
 * Full Featured Storage Stack + 100% Encryption
 * =====================================================================
 *
 * Design goals:
 * - Proper block device abstraction (pluggable backends: virtual disk now,
 *   real ATA/NVMe later).
 * - On-disk structures with proper allocation and scalability.
 * - Authenticated encryption on every block (encrypt-then-MAC) using the
 *   kernel's strong audited KDF construction + unique nonces.
 * - Tight integration with capability model and per-user keys.
 * - Foundation for future userspace fs-server (block device caps can be
 *   delegated).
 */

/* Block device constants */
#define BLOCK_SIZE          4096
#define BLOCKS_PER_DISK     (8 * 1024 * 1024 / BLOCK_SIZE)   /* 8 GiB virtual disk for now */
#define MAX_BLOCK_DEVICES   4

/* Forward declarations for storage stack */
struct block_device;
struct inode;

/* Block device interface (the foundation of the storage stack) */
struct block_device {
    const char *name;
    uint64_t    total_blocks;
    int         (*read_block)(struct block_device *bd, uint64_t block, void *buf);
    int         (*write_block)(struct block_device *bd, uint64_t block, const void *buf);
    void       *private;   /* Backend-specific data (VirtualDisk, etc.) */
};

/* Storage stack public API */
int storage_init(void);
struct block_device *storage_get_default_device(void);
int storage_encrypt_block(const uint8_t *file_key, uint64_t inode, uint64_t block,
                          uint32_t gen, uint8_t *data);
int storage_decrypt_block(const uint8_t *file_key, uint64_t inode, uint64_t block,
                          uint32_t gen, uint8_t *data);

void storage_set_default_device(struct block_device *bd);

void storage_register_userspace_block_backend(
        int (*read_fn)(uint64_t, void *),
        int (*write_fn)(uint64_t, const void *));

/* Privileged block I/O for userspace FS server (CAP_BLOCK_DEV) */
int storage_block_read(uint64_t block, void *buf);
int storage_block_write(uint64_t block, const void *buf);

/* Userspace FS server registration (for bootstrapping IPC connections) */
extern int fs_server_task_id;
extern int fs_server_listen_ep_idx;  /* global endpoint index the server listens on */

/* Virtual in-memory disk backend (first implementation, can be made persistent) */
struct virtual_disk {
    uint8_t *data;           /* Backing memory for the entire disk */
    size_t   size;           /* Total bytes */
    uint32_t block_count;
};

/* On-disk superblock (placed at block 0) */
struct fs_superblock {
    uint32_t magic;          /* 'HFS1' */
    uint32_t version;
    uint64_t total_blocks;
    uint64_t inode_bitmap_start;
    uint64_t block_bitmap_start;
    uint64_t inode_table_start;
    uint64_t data_start;
    uint32_t inode_count;
    uint32_t block_size;
    uint8_t  volume_key_salt[16];   /* For deriving volume encryption key */
    uint8_t  reserved[128];
} __attribute__((packed));

/* On-disk inode (simplified but proper) */
struct on_disk_inode {
    uint32_t mode;           /* Unix-style mode + type */
    uint32_t uid;
    uint32_t gid;
    uint64_t size;
    uint64_t atime;
    uint64_t mtime;
    uint64_t ctime;
    uint32_t links;
    uint32_t flags;          /* encrypted, etc. */

    /* Encryption metadata (per-inode) */
    uint8_t  file_key[32];   /* Wrapped with volume or user key */
    uint8_t  file_iv[16];

    /* Block pointers (direct + single indirect for starters) */
    uint64_t direct[12];
    uint64_t indirect;
    uint64_t double_indirect;

    uint8_t  reserved[64];
} __attribute__((packed));

/* Directory entry */
struct dir_entry {
    uint64_t inode;
    uint16_t name_len;
    uint8_t  type;
    char     name[255];
} __attribute__((packed));

/* In-memory filesystem state (mounted filesystem) */
#define MAX_MOUNTED_FS 4
#define INODES_PER_BLOCK (BLOCK_SIZE / sizeof(struct on_disk_inode))

struct mounted_fs {
    struct block_device *bd;
    struct fs_superblock sb;
    int mounted;
    uint8_t volume_key[32];   /* Derived at mount using user/volume salt */
};

void cap_init(void);
struct capability *cap_lookup(uint32_t slot, uint32_t required_rights);
bool cap_mint(uint32_t dest_slot, uint32_t src_slot, uint32_t new_rights);
bool cap_revoke(uint32_t slot);
bool cap_transfer(uint32_t dest_slot, uint32_t src_slot);
bool cap_move(uint32_t dest_slot, uint32_t src_slot);

void scheduler_init(void);
void timer_handler(void);
void context_switch(int next);
void schedule(void);
void yield(void);
uint32_t get_system_ticks(void);
void print_boot_timestamp(void);

/* ASLR support */
void aslr_init_seed(void);
uint32_t aslr_random_offset(uint32_t max_pages);
void aslr_mix_entropy(uint64_t val);  /* for additional per-spawn entropy */

/* High-resolution timer for entropy (used by ASLR and spawn paths) */
uint64_t read_tsc(void);

void cpu_detect_features(void);
int  cpu_has_aesni(void);

/* =====================================================================
 * Platform / Hardware Detection
 * =====================================================================
 * Rich detection run early in boot. Used to:
 *   - Decide 32-bit vs 64-bit paths
 *   - Enable/disable SMP
 *   - Report capabilities (TSC, AES-NI, etc.)
 *   - Adapt boot and driver initialization
 */
typedef struct {
    char     vendor[13];           /* CPU vendor string (GenuineIntel, AuthenticAMD, ...) */
    uint32_t family;
    uint32_t model;
    uint32_t stepping;

    int      has_long_mode;        /* 64-bit capable (CPUID 0x80000001) */
    int      has_sse;
    int      has_sse2;
    int      has_sse4_2;
    int      has_aesni;
    int      has_rdrand;
    int      has_tsc;
    int      has_invariant_tsc;    /* Constant TSC across P-states */

    uint32_t num_logical_cpus;     /* Basic count (CPUID or later ACPI) */
    uint32_t num_physical_cpus;

    uint64_t total_memory_bytes;   /* From multiboot or later ACPI */
} platform_info_t;

extern platform_info_t platform;   /* Global populated early in boot */

void platform_detect(void);
void platform_print_summary(void);   /* Nice output for boot log */

/* Early 64-bit IDT setup (called from the long-mode trampoline) */
void setup_early_idt64(void);

void crypto_aes128_block_encrypt(const uint8_t *key, const uint8_t *in, uint8_t *out);
void crypto_aes128_ctr_encrypt(const uint8_t *key, const uint8_t *nonce_iv, uint8_t *inout, size_t len);

void ata_init(void);

extern uint8_t kernel_pepper[16];  /* secret pepper for auth and encryption */

int handle_demand_page_fault(uint32_t fault_addr, uint32_t err_code);

uint32_t alloc_user_physical_page(void);
void free_user_physical_page(uint32_t phys_addr);
void page_ref_inc(uint32_t phys_addr);
int page_ref_dec(uint32_t phys_addr);

// Rust will become the authority for these in the near future
int rust_handle_demand_page_fault(uint32_t fault_addr, uint32_t err_code, bool is_cow, uint16_t ref_count);

/* User management (implemented in syscall.c) */
void users_init(void);

void outb(uint16_t port, uint8_t val);
uint8_t inb(uint16_t port);

char serial2_read_char(void);

void syscall_handler(struct regs *r);
int process_user_command(const char *cmd);

void ramfs_init(void);
int ramfs_open(const char* path);
int ramfs_read(int fd, void* buf, size_t len);
int ramfs_write(int fd, const void* buf, size_t len);
int ramfs_create(const char* name);
int ramfs_list(char *buf, size_t bufsize);

/* Capability-based FS layer (new model) */
extern struct fs_object *fs_objects[MAX_FS_OBJECTS];

int  capfs_init(void);
struct fs_object *capfs_alloc_object(int type, const char *name);
int  capfs_lookup(struct capability *dir_cap, const char *name, struct capability *out_cap, uint32_t desired_rights);
int  capfs_create(struct capability *dir_cap, const char *name, int type, struct capability *out_cap, uint32_t desired_rights);
int  capfs_delete(struct capability *dir_cap, const char *name);
int  capfs_readdir(struct capability *dir_cap, char *buf, size_t bufsize);
int  capfs_read(struct capability *file_cap, void *buf, size_t len);
int  capfs_write(struct capability *file_cap, const void *buf, size_t len);

int copy_from_user(void *dst, const void *src, size_t n);
int copy_to_user(void *dst, const void *src, size_t n);

struct program_header {
    uint32_t magic;
    uint32_t entry;
    uint32_t size;
    char     name[32];
};

extern struct endpoint endpoints[MAX_ENDPOINTS];

bool rust_validate_page_fault(uint32_t task_id, uint32_t fault_addr, uint32_t error_code);
int  rust_handle_command(const uint8_t *cmd, size_t len);
uint32_t rust_get_user_page_protection(uint32_t task_id, uint32_t vaddr);
int  rust_validate_fs_operation(uint32_t task_id, uint32_t op, uint32_t rights, const uint8_t *name, size_t nlen);
int  rust_validate_ipc(uint32_t task_id, uint32_t ep_slot, uint32_t rights);

#define SYS_IPC_SEND   21
#define SYS_IPC_RECV   22
#define SYS_IPC_CALL   23
#define SYS_IPC_REPLY  24

#define SYS_NOTIFY          25
#define SYS_WAIT_NOTIFY     26
#define SYS_RECEIVE_PROGRAM 27
#define SYS_SPAWN           28

/* User / sudo syscalls (capability protected where sensitive) */
#define SYS_GETUID   29
#define SYS_AUTH     30   /* authenticate user/pass -> uid */
#define SYS_SUDO     31   /* password auth + elevated spawn */
#define SYS_GET_PASS 32   /* secure no-echo password read */

/* User management (admin only via cap or uid 0) */
#define SYS_USERADD  33
#define SYS_USERDEL  34
#define SYS_PASSWD   35
#define SYS_ROTATE_KEYS 36   /* Re-encrypt user file keys (key rotation) */
#define SYS_READ_AUDIT   37   /* Read kernel audit log (requires CAP_AUDIT) */
#define SYS_FS_MINT_FILE 38   /* Mint a file capability from a directory cap */
#define SYS_FS_LOOKUP    39   /* Lookup name in dir cap -> new cap */
#define SYS_FS_CREATE    40   /* Create name in dir cap -> new cap */
#define SYS_FS_DELETE    41   /* Unlink name from dir cap (requires DELETE right) */
#define SYS_FS_READDIR   42   /* Enumerate children of dir cap */
#define SYS_FS_GET_ROOT  43   /* Bootstrap: obtain root dir cap into slot (admin only) */
#define SYS_FS_READ      44   /* Read from a file cap slot (rights checked in kernel) */
#define SYS_FS_WRITE     45   /* Write to a file cap slot */
#define SYS_REGISTER_STORAGE_BACKEND 46  /* Userspace task registers as block backend (requires strong caps) */
#define SYS_BLOCK_READ   47   /* Privileged block read (for FS server / drivers, requires CAP_BLOCK_DEV) */
#define SYS_BLOCK_WRITE  48   /* Privileged block write (for FS server / drivers) */
#define SYS_REGISTER_FS_SERVER 49  /* FS server registers its listening endpoint (CAP_USER) */
#define SYS_CONNECT_FS_SERVER  50  /* Client gets a cap to the FS server's endpoint */

/* Audit event types */
#define AUDIT_AUTH          1
#define AUDIT_SUDO          2
#define AUDIT_USER_MGMT     3
#define AUDIT_CAP_OPERATION 4
#define AUDIT_FILE_ACCESS   5
#define AUDIT_IPC           6
#define AUDIT_FS            7   /* Capability FS operations (lookup/create/delete/read/write) */

/* Finer-grained audit event types (for professional logging + future filtering) */
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

/* User management syscalls (require admin capabilities or uid==0) */
#define SYS_USERADD   33
#define SYS_USERDEL   34
#define SYS_PASSWD    35   /* change own or other's password (with cap) */

int sys_ipc_send(uint32_t ep_slot, const void *msg, size_t len);
int sys_ipc_recv(uint32_t ep_slot, void *msg, size_t max_len);
int sys_ipc_call(uint32_t ep_slot, const void *send_msg, size_t send_len,
                   void *recv_msg, size_t recv_max);
int sys_ipc_reply(uint32_t ep_slot, const void *msg, size_t len);

int sys_receive_program(struct program_header *hdr_out);
int sys_spawn(void);

int sys_getuid(void);
int sys_auth(const char *user, const char *pass, uint32_t *out_uid);
int sys_sudo(const char *cmd, const char *pass);  /* simplistic for now */

int sys_notify(uint32_t notif_slot, uint32_t badge);
int sys_wait_notify(uint32_t notif_slot, uint32_t *out_badge);

int sys_useradd(uint32_t uid, uint32_t gid, const char *name, const char *initial_password);
int sys_userdel(uint32_t uid);
int sys_passwd(uint32_t target_uid, const char *new_password);  /* target_uid == current or 0 for root */
int sys_rotate_keys(void);  /* Re-encrypt all user's file keys with a fresh master key */

/* Capability-based Filesystem (full first-class model) */
int sys_fs_mint_file(uint32_t dir_slot, uint32_t dest_slot, uint32_t new_rights);
int sys_fs_lookup(uint32_t dir_slot, const char *name, uint32_t out_slot, uint32_t desired_rights);
int sys_fs_create(uint32_t dir_slot, const char *name, int type, uint32_t out_slot, uint32_t desired_rights);
int sys_fs_delete(uint32_t dir_slot, const char *name);
int sys_fs_readdir(uint32_t dir_slot, char *buf, uint32_t bufsize);
int sys_fs_get_root(uint32_t dest_slot, uint32_t rights);
int sys_fs_read(uint32_t file_slot, char *buf, uint32_t len);
int sys_fs_write(uint32_t file_slot, const char *buf, uint32_t len);

/* Audit logging */
int sys_read_audit(struct audit_event *events, uint32_t max_events);

#endif

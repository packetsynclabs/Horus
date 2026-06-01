#include "syscall.h"

static void print(const char *s) {
    sys_print(s);
}

static void println(const char *s) {
    print(s);
    print("\n");
}

static int strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static int strncmp(const char *a, const char *b, size_t n) {
    while (n > 0 && *a && *a == *b) { a++; b++; n--; }
    if (n == 0) return 0;
    return (unsigned char)*a - (unsigned char)*b;
}

static const char* strstr(const char *haystack, const char *needle) {
    if (!*needle) return haystack;
    for (; *haystack; haystack++) {
        const char *h = haystack, *n = needle;
        while (*h && *n && *h == *n) { h++; n++; }
        if (!*n) return haystack;
    }
    return 0;
}

/* FS Server IPC protocol (must match fs_server.c) */
#define FSS_OP_LOOKUP   1
#define FSS_OP_CREATE   2
#define FSS_OP_MKDIR    3
#define FSS_OP_DELETE   4
#define FSS_OP_READDIR  5
#define FSS_OP_READ     6
#define FSS_OP_WRITE    7
#define FSS_OP_STAT     8

struct fss_req {
    uint32_t op;
    uint32_t handle;
    char name[32];
    uint32_t type;
    uint32_t rights;
    uint32_t offset;
    uint32_t len;
    uint8_t  data[128];
};

struct fss_rep {
    int32_t  rc;
    uint32_t new_handle;
    uint32_t size;
    uint8_t  data[128];
    char     listing[256];
};

static int fss_connected = 0;
static uint32_t fss_ep_slot = 0;  /* slot in our cspace with cap to server's endpoint */

static int fss_strlen(const char *s) { int l=0; while(s[l]) l++; return l; }
static void fss_strcpy(char *d, const char *s) { while((*d++ = *s++)); }

static int fss_connect(void) {
    if (fss_connected) return 0;
    /* Ask kernel to give us a cap to the registered FS server's endpoint */
    fss_ep_slot = 20;  /* arbitrary free-ish slot */
    int rc = sys_connect_fs_server(fss_ep_slot, 3 /* READ|WRITE */);
    if (rc == 0) {
        fss_connected = 1;
        return 0;
    }
    return -1;
}

static int fss_call(struct fss_req *req, struct fss_rep *rep) {
    if (!fss_connected) {
        if (fss_connect() != 0) return -1;
    }
    int r = sys_ipc_call(fss_ep_slot, (const char*)req, sizeof(*req), (char*)rep, sizeof(*rep));
    return r;
}

static void *memcpy(void *dest, const void *src, size_t n) {
    unsigned char *d = dest;
    const unsigned char *s = src;
    while (n--) *d++ = *s++;
    return dest;
}

static size_t strlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

static void print_decimal(uint32_t n) {
    char buf[11];
    int i = 10;
    buf[i] = '\0';
    if (n == 0) {
        buf[--i] = '0';
    } else {
        while (n > 0) {
            buf[--i] = '0' + (n % 10);
            n /= 10;
        }
    }
    print(&buf[i]);
}

static void handle_command(char *cmd) {
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "man") == 0) {
        println("Horus Userspace Shell - Available Commands (man style)");
        println("");
        println("Core:");
        println("  help, man          - Show this command list");
        println("  exit, logout       - Exit current session / return to login");
        println("  yield              - Voluntarily yield CPU");
        println("");
        println("User & Security:");
        println("  whoami             - Show current user id");
        println("  id                 - Show uid and gid");
        println("  sudo <password>    - Elevate privileges (requires armed binary)");
        println("  passwd             - Change your password (uses secure input)");
        println("  rotate_keys        - Rotate your file encryption keys (re-encrypt all your files)");
        println("");
        println("User Management (admin only):");
        println("  useradd <uid> <name> - Create new user");
        println("  userdel <uid>        - Delete user");
        println("");
        println("Filesystem (capability-based, primary model):");
        println("  fsroot [slot] [rights]   - Obtain root dir cap (admin)");
        println("  cap_ls <dirslot>         - List directory via cap");
        println("  cap_cat <fileslot>       - Read file via cap");
        println("  cap_write <fileslot> <text> - Write/append via cap");
        println("  cap_mint <src> <dst> <r> - Mint attenuated cap");
        println("  cap_revoke <slot>        - Revoke cap + derived");
        println("  cap_create <dir> <name> <0|1> - Create file(0)/dir(1)");
        println("  cap_delete <dir> <name>  - Unlink from dir");
        println("  Legacy: ls cat echo still available for transition");
        println("");
        println("Process & Loader:");
        println("  ps                 - List processes");
        println("  mem                - Show memory usage");
        println("  receive            - Receive binary from loader port (arms for spawn)");
        println("  spawn              - Spawn armed binary as new task");
        println("  load               - Receive + spawn (convenience)");
        println("");
        println("IPC & Notifications:");
        println("  ipc_send <slot> <msg>   - Send message on endpoint");
        println("  ipc_recv <slot>         - Receive message");
        println("  notify <slot> <badge>   - Send notification");
        println("  wait_notify <slot>      - Wait for notification");
        println("");
        println("Note: Most privileged operations require the appropriate capability (usually slot 3).");
    } else if (strcmp(cmd, "exit") == 0) {
        println("Exiting userspace shell...");
        sys_exit();
    } else if (strcmp(cmd, "yield") == 0) {
        println("Yielding...");
        sys_yield();
    } else if (strcmp(cmd, "mem") == 0) {
        println("Userspace heap demo (using sbrk)");
        void *p = sys_sbrk(4096);
        if (p) {
            println("Allocated 4KB from userspace heap");
        } else {
            println("sbrk failed");
        }
    } else if (strcmp(cmd, "ps") == 0) {
        println("PID  NAME            STATE  HEAP     CAPS  FLAGS");
        int mypid = sys_getpid();
        print("My pid: ");
        print_decimal(mypid);
        println("");
        int saw_any = 0;
        for (int i = 0; i < 16; i++) {   /* scan wider now that we have more tasks */
            struct task_info info;
            int r = sys_get_task_info(i, &info);
            if (r == 0 && info.state != 0) {
                saw_any = 1;
                if (info.id < 10) print(" ");
                print_decimal(info.id);
                print("  ");
                print(info.name);
                int nlen = 0; while (info.name[nlen]) nlen++;
                for (int sp = nlen; sp < 14; sp++) print(" ");
                print_decimal(info.state);
                print("     ");
                print_decimal(info.heap_used);
                print("  ");
                print_decimal(info.caps_in_use);
                print("   ");
                if (info.in_kernel) print("K ");
                if (info.blocked_on >= 0) { print("B"); print_decimal(info.blocked_on); }
                else if (info.blocked_on_notif >= 0) print("N");
                println("");
            }
        }
        if (!saw_any) {
            println("(limited visibility - only own task shown for non-admin)");
        }
    } else if (strcmp(cmd, "ls") == 0) {
        println("hello.txt");
        println("readme.txt");
    } else if (strncmp(cmd, "cat ", 4) == 0) {
        const char* filename = cmd + 4;
        int fd = sys_open(filename);
        if (fd < 0) {
            println("File not found");
            return;
        }
        char buf[256];
        int n = sys_read(fd, buf, sizeof(buf)-1);
        if (n > 0) {
            buf[n] = 0;
            print(buf);
            if (buf[n-1] != '\n') print("\n");
        }
    } else if (cmd[0] == 'e' && cmd[1] == 'c' && cmd[2] == 'h' && cmd[3] == 'o' && cmd[4] == ' ') {
        const char* rest = cmd + 5;
        const char* redirect = strstr(rest, " > ");
        if (redirect) {
            char text[128];
            char fname[32];
            size_t tlen = redirect - rest;
            if (tlen >= sizeof(text)) tlen = sizeof(text)-1;
            memcpy(text, rest, tlen);
            text[tlen] = 0;

            const char* fstart = redirect + 3;
            size_t flen = strlen(fstart);
            if (flen >= sizeof(fname)) flen = sizeof(fname)-1;
            memcpy(fname, fstart, flen);
            fname[flen] = 0;

            int fd = sys_open(fname);
            if (fd >= 0) {
                sys_write(fd, text, strlen(text));
            } else {
                println("Cannot write to file");
            }
        } else {
            println(rest);
        }
    } else if (cmd[0] == 0) {
    } else if (strncmp(cmd, "ipc_send ", 9) == 0) {
        const char *p = cmd + 9;
        while (*p == ' ') p++;
        sys_ipc_send(4, p, strlen(p)+1);
        println("sent (or blocked on endpoint 4)");
    } else if (strncmp(cmd, "ipc_recv ", 9) == 0) {
        char buf[64];
        int n = sys_ipc_recv(4, buf, sizeof(buf)-1);
        if (n > 0) { buf[n]=0; print("recv: "); println(buf); }
        else println("no message (or blocked)");
    } else if (strncmp(cmd, "notify ", 7) == 0) {
        const char *p = cmd + 7;
        while (*p == ' ') p++;
        uint32_t badge = 0;
        while (*p >= '0' && *p <= '9') { badge = badge*10 + (*p-'0'); p++; }
        sys_notify(4, badge);
        println("notified");
    } else if (strncmp(cmd, "wait_notify ", 12) == 0) {
        uint32_t badge = 0;
        sys_wait_notify(4, &badge);
        print("wait_notify badge="); print_decimal(badge); println("");
    } else if (strcmp(cmd, "whoami") == 0) {
        uint32_t uid = sys_getuid();
        print("uid=");
        print_decimal(uid);
        if (uid == 0) println(" (root)");
        else println("");
    } else if (strcmp(cmd, "id") == 0) {
        uint32_t uid = sys_getuid();
        print("uid="); print_decimal(uid);
        print(" gid=100");
        println("");
    } else if (strncmp(cmd, "sudo ", 5) == 0) {
        const char *pass = cmd + 5;
        int r = sys_sudo(pass);
        if (r > 0) {
            println("sudo: elevated spawn successful (pid ");
            print_decimal(r);
            println(")");
        } else if (r == -2) {
            println("sudo: incorrect password");
        } else {
            println("sudo: failed (no armed image or auth error)");
        }
    } else if (strncmp(cmd, "useradd ", 8) == 0) {
        /* simplistic: useradd <uid> <name> */
        const char *p = cmd + 8;
        uint32_t newuid = 0;
        char newname[32];
        while (*p == ' ') p++;
        while (*p >= '0' && *p <= '9') { newuid = newuid*10 + (*p-'0'); p++; }
        while (*p == ' ') p++;
        int ni = 0;
        while (*p && *p != ' ' && ni < 31) { newname[ni++] = *p++; }
        newname[ni] = 0;

        int r = sys_useradd(newuid, 100, newname);
        if (r == 0) println("user added");
        else println("useradd failed");
    } else if (strncmp(cmd, "userdel ", 8) == 0) {
        const char *p = cmd + 8;
        uint32_t deluid = 0;
        while (*p == ' ') p++;
        while (*p >= '0' && *p <= '9') { deluid = deluid*10 + (*p-'0'); p++; }
        int r = sys_userdel(deluid);
        println(r == 0 ? "user deleted" : "userdel failed");
    } else if (strncmp(cmd, "passwd ", 7) == 0) {
        /* passwd [target_uid]  - prompts for new password securely */
        println("New password: ");
        char newp[32];
        int plen = sys_get_pass(newp, 31);
        if (plen > 0) {
            newp[plen] = 0;
            uint32_t target = 0; /* self for now */
            int r = sys_passwd(target, newp);
            for (int i=0; i<32; i++) newp[i]=0;
            println(r == 0 ? "password changed" : "passwd failed");
        } else {
            println("passwd aborted");
        }
    } else if (strcmp(cmd, "rotate_keys") == 0) {
        int r = sys_rotate_keys();
        println(r == 0 ? "Keys rotated successfully" : "Key rotation failed");
    } else if (strcmp(cmd, "fsroot") == 0 || strncmp(cmd, "fsroot ", 7) == 0) {
        uint32_t slot = 9;
        uint32_t rights = 0x1FF; /* most FS rights */
        /* very rough parse */
        const char *p = cmd + 6;
        while (*p == ' ') p++;
        if (*p) slot = (uint32_t)(*p - '0');
        int r = sys_fs_get_root(slot, rights);
        if (r == 0) {
            print("Root dir cap installed at slot "); print_decimal(slot); println("");
        } else {
            println("fsroot denied (need admin cap or uid0)");
        }
    } else if (strncmp(cmd, "cap_ls ", 7) == 0) {
        uint32_t slot = 0;
        const char *p = cmd + 7;
        while (*p == ' ') p++;
        if (*p >= '0' && *p <= '9') slot = (uint32_t)(*p - '0');
        char buf[256];
        int rc = sys_fs_readdir(slot, buf, sizeof(buf)-1);
        if (rc >= 0) {
            buf[sizeof(buf)-1] = 0;
            if (buf[0]) print(buf); else println("(empty)");
        } else {
            println("cap_ls failed (bad slot or no LOOKUP right)");
        }
    } else if (strncmp(cmd, "cap_cat ", 8) == 0) {
        uint32_t slot = 0;
        const char *p = cmd + 8;
        while (*p == ' ') p++;
        if (*p >= '0' && *p <= '9') slot = (uint32_t)(*p - '0');
        char buf[512];
        int rc = sys_fs_read(slot, buf, sizeof(buf)-1);
        if (rc > 0) {
            buf[rc < 511 ? rc : 511] = 0;
            print(buf);
            if (buf[rc-1] != '\n') println("");
        } else if (rc == 0) {
            println("(empty file)");
        } else {
            println("cap_cat failed (no READ right or bad slot)");
        }
    } else if (strncmp(cmd, "cap_write ", 10) == 0) {
        uint32_t slot = 0;
        const char *p = cmd + 10;
        while (*p == ' ') p++;
        if (*p >= '0' && *p <= '9') { slot = (uint32_t)(*p - '0'); p++; }
        while (*p == ' ') p++;
        /* crude strlen */
        size_t wl = 0; while (p[wl]) wl++;
        int rc = sys_fs_write(slot, p, (uint32_t)wl);
        println(rc >= 0 ? "write ok" : "cap_write failed (no WRITE right)");
    } else if (strncmp(cmd, "cap_mint ", 9) == 0) {
        /* cap_mint <srcslot> <dstslot> <rights> */
        println("cap_mint: implemented via direct syscall in advanced usage");
    } else if (strncmp(cmd, "cap_revoke ", 11) == 0) {
        const char *p = cmd + 11;
        while (*p == ' ') p++;
        uint32_t slot = (*p >= '0' && *p <= '9') ? (uint32_t)(*p - '0') : 0;
        (void)slot;
        /* direct revoke via cap API not exposed to user; kernel cmd or future SYS_REVOKE */
        println("cap_revoke: use kernel REVOKE or slot management for demo");
    } else if (strncmp(cmd, "cap_create ", 11) == 0) {
        println("cap_create <dirslot> <name> <type 0=file 1=dir>: use syscall layer");
    } else if (strncmp(cmd, "cap_delete ", 11) == 0) {
        println("cap_delete: syscall supported (SYS_FS_DELETE)");
    } else if (strcmp(cmd, "receive") == 0) {
        struct program_header h;
        int r = sys_receive_program(&h);
        if (r == 0) {
            print("Received '");
            print(h.name);
            print("' (");
            print_decimal(h.size);
            println(" bytes) - armed for spawn");
        } else if (r == -1) {
            println("Bad magic");
        } else if (r == -2) {
            println("Invalid size");
        } else {
            println("Receive error");
        }
    } else if (strcmp(cmd, "spawn") == 0) {
        int pid = sys_spawn();
        if (pid > 0) {
            print("Spawned new task pid=");
            print_decimal(pid);
            println("");
        } else {
            println("Spawn failed (no armed image or no free slot)");
        }
    } else if (strcmp(cmd, "load") == 0) {
        /* Convenience: receive then immediately spawn as background task */
        struct program_header h;
        int r = sys_receive_program(&h);
        if (r != 0) {
            println("Receive failed");
            return;
        }
        int pid = sys_spawn();
        if (pid > 0) {
            print("Loaded '");
            print(h.name);
            print("' as pid ");
            print_decimal(pid);
            println("");
        } else {
            println("Spawn failed after receive");
        }
    } else if (strncmp(cmd, "fss", 3) == 0) {
        /* Userspace FS Server client commands (talk to real userspace fs_server) */
        if (strcmp(cmd, "fss_connect") == 0 || strcmp(cmd, "fss") == 0) {
            if (fss_connect() == 0) {
                println("Connected to userspace FS server");
            } else {
                println("Failed to connect to FS server (is it running? use receive + spawn fs_server.bin)");
            }
        } else if (strcmp(cmd, "fss_ls") == 0) {
            struct fss_req req = {0};
            struct fss_rep rep;
            req.op = FSS_OP_READDIR;
            req.handle = 0; /* root */
            if (fss_call(&req, &rep) == 0 && rep.rc == 0) {
                print("Userspace FS contents:\n");
                print(rep.listing);
            } else {
                println("fss_ls failed (server not connected?)");
            }
        } else if (strncmp(cmd, "fss_cat ", 8) == 0) {
            const char *name = cmd + 8;
            struct fss_req req = {0};
            struct fss_rep rep;
            req.op = FSS_OP_LOOKUP;
            req.handle = 0;
            fss_strcpy(req.name, name);
            if (fss_call(&req, &rep) == 0 && rep.rc == 0) {
                req.op = FSS_OP_READ;
                req.handle = rep.new_handle;
                req.len = 128;
                if (fss_call(&req, &rep) == 0 && rep.rc > 0) {
                    rep.data[rep.rc < 128 ? rep.rc : 127] = 0;
                    print((char*)rep.data);
                    println("");
                } else {
                    println("read failed");
                }
            } else {
                println("file not found in userspace FS");
            }
        } else if (strncmp(cmd, "fss_write ", 10) == 0) {
            /* fss_write filename "content"  (very simple, one arg for demo) */
            char *space = (char*)strstr(cmd + 10, " ");
            if (space) {
                *space = 0;
                const char *fname = cmd + 10;
                const char *content = space + 1;
                struct fss_req req = {0};
                struct fss_rep rep;
                req.op = FSS_OP_LOOKUP;
                req.handle = 0;
                fss_strcpy(req.name, fname);
                if (fss_call(&req, &rep) == 0 && rep.rc == 0) {
                    req.op = FSS_OP_WRITE;
                    req.handle = rep.new_handle;
                    req.offset = 0;
                    req.len = fss_strlen(content) > 128 ? 128 : fss_strlen(content);
                    fss_strcpy((char*)req.data, content);
                    int w = fss_call(&req, &rep);
                    print("wrote "); print_decimal(w > 0 ? w : 0); println(" bytes to userspace FS");
                } else {
                    println("file not found for write (create it first with fss_mkdir or fss_create in server)");
                }
            } else {
                println("usage: fss_write <file> <text>");
            }
        } else if (strcmp(cmd, "fss_tree") == 0) {
            println("Userspace FS server tree (demo):");
            println("/\n  home/\n    user/\n      readme.txt\n  etc/\n    hostname\n  motd");
        } else {
            println("fss commands: fss fss_connect fss_ls fss_cat <name> fss_write <file> <txt> fss_tree");
        }
    } else {
        println("Unknown command. Type 'help'");
    }
}

// Userspace entry: simple REPL using only syscalls (ramfs, ipc, notify, sbrk via get_line)
/* Secure login state */
static uint32_t current_login_uid = 0;
static char current_login_name[32] = "root";

static void do_login(void) {
    char username[32];
    char password[128];
    int attempts = 0;
    const int max_attempts = 5;

    println("\nHorus Secure Login");

    while (1) {
        print("username: ");
        int ulen = sys_get_line(username, sizeof(username) - 1);
        if (ulen <= 0) continue;
        username[ulen] = 0;

        print("password: ");
        int plen = sys_get_pass(password, sizeof(password) - 1);
        if (plen < 0) {
            println("\nInput error");
            continue;
        }
        password[plen] = 0;

        uint32_t got_uid = 0;
        int auth_ok = sys_auth(username, password, &got_uid);

        /* Securely clear password immediately */
        for (int i = 0; i < 128; i++) password[i] = 0;

        if (auth_ok == 0 && got_uid != 0) {
            current_login_uid = got_uid;
            /* Copy safe name */
            int j;
            for (j = 0; j < 31 && username[j]; j++) current_login_name[j] = username[j];
            current_login_name[j] = 0;

            println("Login successful.");
            attempts = 0;
            return;
        }

        println("Login incorrect.");
        attempts++;

        if (attempts >= max_attempts) {
            /* Basic rate limiting / backoff */
            println("Too many attempts. Please wait...");
            for (volatile int d = 0; d < 20000000; d++) { } /* crude delay */
            attempts = 0;
        }
    }
}

void _start(void) {
    println("=== Horus Userspace Shell (init/login) ===");
    println("This is the system init. Login to begin a session.");

    /* Act as init / login manager */
    do_login();

    char cmd[128];

    while (1) {
        uint32_t uid = sys_getuid();   /* kernel knows real uid */
        print(current_login_name);
        print("@horus");
        if (uid == 0) print("# ");
        else print("$ ");
        int len = sys_get_line(cmd, sizeof(cmd));
        if (len < 0) {
            println("Input error");
            continue;
        }

        if (strcmp(cmd, "logout") == 0 || strcmp(cmd, "exit") == 0) {
            println("Logging out...");
            /* Clear sensitive state */
            current_login_uid = 0;
            for (int i = 0; i < 32; i++) current_login_name[i] = 0;
            do_login();   /* back to login prompt - init behavior */
            continue;
        }

        handle_command(cmd);
    }
}

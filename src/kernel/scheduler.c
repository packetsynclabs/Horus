#include "kernel.h"

tcb_t tasks[MAX_TASKS];
int current_task = 0;
static uint8_t kernel_stacks[MAX_TASKS][KERNEL_STACK_SIZE] __attribute__((aligned(16)));

struct endpoint endpoints[MAX_ENDPOINTS];

// Scheduler and task management initialization
void scheduler_init(void) {
    for (int i = 0; i < MAX_TASKS; i++) {
        tasks[i].state = 0;
        tasks[i].esp = 0;
        tasks[i].eip = 0;
        tasks[i].cap_tcb = 0;
        tasks[i].cr3 = 0;
        tasks[i].priority = 1;
        tasks[i].cspace = 0;
        tasks[i].cspace_size = 0;
        tasks[i].heap_start = 0;
        tasks[i].heap_current = 0;
        tasks[i].heap_end = 0;
        tasks[i].name[0] = 0;
        tasks[i].waiter = -1;
        tasks[i].blocked_on = -1;
        tasks[i].ipc_role = 0;
        tasks[i].in_kernel = 0;
        tasks[i].blocked_on_notif = -1;
        tasks[i].auth_fail_count = 0;
        tasks[i].auth_lockout_until = 0;
    }

#if defined(__x86_64__)
    /* For 64-bit we create a minimal root task 0 on the shared identity map.
     * Full per-task 4-level paging + ring3 drop for user tasks is future work. */
    create_task(0, 0, 0);   /* entry/stack not used for kernel shell task */
#else
    create_task(0, USER_VIRT_BASE + 3, DEMO_TASK_STACK_TOP);
#endif

    /* Root identity for initial task */
    tasks[0].uid = 0;
    tasks[0].gid = 0;

    /* Initialize user database (called once at boot) */
    users_init();

    for (int i = 0; i < MAX_ENDPOINTS; i++) {
        endpoints[i].waiting_recv = -1;
        endpoints[i].waiting_send = -1;
        endpoints[i].has_message = false;
        endpoints[i].msg_len = 0;
        endpoints[i].sender_task = -1;
    }
}

// Major: per-task TCB + private cspace + pre-populated caps (TCB+FRAME+endpoints) + pagedir
void create_task(int id, addr_t entry, addr_t stack_top) {
    if (id >= MAX_TASKS) return;

    tasks[id].state = 1;
    tasks[id].esp = (addr_t)(stack_top ? (stack_top - 64) : 0);
    tasks[id].eip = entry;
    tasks[id].cap_tcb = id;

#if !defined(__x86_64__)
    create_user_pagedir(id);
#else
    /* 64-bit: kernel task 0 shares the trampoline identity map for now.
     * No private PD/PTs yet — avoids 32-bit page table code running under long mode. */
    if (id == 0) {
        tasks[id].cr3 = 0;   /* special value meaning "use current (trampoline) CR3" */
    } else {
        create_user_pagedir(id);
    }
#endif

    static struct capability cspace_pool[MAX_TASKS][256];
    tasks[id].cspace = cspace_pool[id];
    tasks[id].cspace_size = 256;

    tasks[id].cspace[0].type   = CAP_TCB;
    tasks[id].cspace[0].rights = CAP_RIGHT_ALL;
    tasks[id].cspace[0].object = id;
    tasks[id].cspace[0].badge  = 0;

    tasks[id].cspace[3].type   = CAP_FRAME;
    tasks[id].cspace[3].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_EXEC;
    tasks[id].cspace[3].object = USER_AREA_BASE;
    tasks[id].cspace[3].badge  = 0;

    tasks[id].cspace[4].type   = CAP_ENDPOINT;
    tasks[id].cspace[4].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE;   /* no GRANT by default */
    tasks[id].cspace[4].object = 0;
    tasks[id].cspace[4].badge  = 0;

    tasks[id].cspace[5].type   = CAP_ENDPOINT;
    tasks[id].cspace[5].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE;
    tasks[id].cspace[5].object = 1;
    tasks[id].cspace[5].badge  = 0;

    /* Grant powerful user administration capability to root task (task 0) */
    if (id == 0) {
        tasks[id].cspace[6].type   = CAP_USER;
        tasks[id].cspace[6].rights = CAP_RIGHT_ALL;
        tasks[id].cspace[6].object = 0;
        tasks[id].cspace[6].badge  = 0;

        /* Audit capability (read + write for privileged audit tasks) */
        tasks[id].cspace[7].type   = CAP_AUDIT;
        tasks[id].cspace[7].rights = CAP_RIGHT_READ | CAP_RIGHT_AUDIT_WRITE;
        tasks[id].cspace[7].object = 0;
        tasks[id].cspace[7].badge  = 0;

        /* Bootstrap root directory capability for the initial shell (slot 8) */
        if (fs_objects[0]) {
            tasks[id].cspace[8].type   = CAP_DIR;
            tasks[id].cspace[8].rights = CAP_RIGHT_FS_LOOKUP | CAP_RIGHT_FS_CREATE |
                                         CAP_RIGHT_FS_DELETE | CAP_RIGHT_FS_READ | CAP_RIGHT_FS_WRITE |
                                         CAP_RIGHT_MINT | CAP_RIGHT_REVOKE | CAP_RIGHT_ALL;
            tasks[id].cspace[8].object = (addr_t)fs_objects[0];
            tasks[id].cspace[8].badge  = 0xF5000000U;
        }
    }

    tasks[id].heap_start   = USER_HEAP_BASE + id * 0x10000;
    tasks[id].heap_current = tasks[id].heap_start;
    tasks[id].heap_end     = tasks[id].heap_start + 0x10000;

    if (id == 0) {
        tasks[id].name[0] = 's'; tasks[id].name[1] = 'h';
        tasks[id].name[2] = 'e'; tasks[id].name[3] = 'l';
        tasks[id].name[4] = 'l'; tasks[id].name[5] = 0;
    } else {
        tasks[id].name[0] = 't'; tasks[id].name[1] = 'a';
        tasks[id].name[2] = 's'; tasks[id].name[3] = 'k';
        tasks[id].name[4] = '0' + id; tasks[id].name[5] = 0;
    }

    tasks[id].waiter = -1;
    tasks[id].blocked_on = -1;
    tasks[id].ipc_role = 0;
    tasks[id].in_kernel = 0;
    tasks[id].blocked_on_notif = -1;

    /* Inherit identity from creator unless overridden (e.g. by sudo) */
    if (id != 0) {
        tasks[id].uid = tasks[current_task].uid;
        tasks[id].gid = tasks[current_task].gid;
    }

    tasks[id].auth_fail_count = 0;
    tasks[id].auth_lockout_until = 0;
    tasks[id].has_file_key = 0;
    for (int k=0; k<32; k++) tasks[id].user_file_master_key[k] = 0;

    /* Initialize quota counter by counting the caps we just pre-populated */
    tasks[id].caps_in_use = 0;
    for (int s = 0; s < 256; s++) {
        if (tasks[id].cspace[s].type != CAP_NULL) tasks[id].caps_in_use++;
    }
}

static uint32_t system_ticks = 0;

/* Userspace FS server bootstrap info (set by the server via syscall) */
int fs_server_task_id = -1;
int fs_server_listen_ep_idx = -1;

/* Stronger ASLR PRNG for bare-metal environment.
   Uses two 64-bit xorshift+ style states with good diffusion + multiple entropy sources.
   Goal: move from "Moderate-Good" to "Strong" posture for research kernel while remaining
   fully auditable and free of external dependencies. */
static uint64_t aslr_rng_state[2] = { 0xdeadbeefcafebabeULL, 0x1234567890abcdefULL };

/* Read high-resolution cycle counter for jitter/entropy (rdtsc on i386).
   Exposed for use in syscall paths for per-spawn entropy. */
uint64_t read_tsc(void) {
    uint32_t lo, hi;
    asm volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

/* Core PRNG step - improved xorshift+ with final multiply for better output */
static uint32_t aslr_rand(void) {
    uint64_t x = aslr_rng_state[0];
    uint64_t y = aslr_rng_state[1];

    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;

    y ^= y >> 12;
    y ^= y << 25;
    y ^= y >> 27;

    aslr_rng_state[0] = x;
    aslr_rng_state[1] = y;

    /* Combine with good avalanche */
    uint64_t combined = x + y;
    combined ^= combined >> 17;
    combined *= 0x2545F4914F6CDD1DULL;

    return (addr_t)(combined >> 32);
}

uint32_t aslr_random_offset(uint32_t max_pages) {
    if (max_pages == 0) return 0;
    return (aslr_rand() % max_pages) * PAGE_SIZE;
}

/* Mix additional entropy into the ASLR PRNG state (called from syscall paths).
   Now mixes into both state words with strong constants and TSC jitter. */
void aslr_mix_entropy(uint64_t val) {
    uint64_t t = read_tsc();
    aslr_rng_state[0] ^= val * 0x9E3779B97F4A7C15ULL;
    aslr_rng_state[1] ^= (val >> 32) * 0xC2B2AE3D27D4EB4FULL ^ t;
    (void)aslr_rand();  /* strong churn */
}

void timer_handler(void) {
    system_ticks++;

    /* Mix high-resolution timer + tick counter on every interrupt for continuous entropy */
    uint64_t t = read_tsc();
    aslr_rng_state[0] ^= (uint64_t)system_ticks * 0x9E3779B97F4A7C15ULL ^ (t & 0xFFFFFFFFULL);
    aslr_rng_state[1] ^= (t >> 32) ^ ((uint64_t)system_ticks << 17);

    /* Scheduler side-channel mitigation: add small TSC-based jitter to preemption decisions
       so that exact timing of voluntary vs involuntary yields is harder to use for leaks. */
    if ((system_ticks % 23 == 0) || ((t & 0x3FF) < 8)) {
        schedule();
    }
}

uint32_t get_system_ticks(void) {
    return system_ticks;
}

/* Called once early in boot to improve ASLR seed.
   Collects significantly more entropy than before: multiple TSC samples with jitter,
   kernel addresses, stack canary-like values, and a small amount of timing variation. */
void aslr_init_seed(void) {
    uint64_t t1 = read_tsc();

    /* Basic sources */
    aslr_rng_state[0] ^= (uint64_t)system_ticks * 0x9E3779B97F4A7C15ULL;
    aslr_rng_state[0] ^= (addr_t)&aslr_rng_state;
    aslr_rng_state[0] ^= (addr_t)kernel_stacks;
    aslr_rng_state[1] ^= (addr_t)&system_ticks ^ (t1 & 0xFFFFFFFFULL);

    /* Collect jitter by spinning and reading TSC (cheap hardware entropy on real CPUs) */
    for (int i = 0; i < 64; i++) {
        uint64_t t = read_tsc();
        aslr_rng_state[0] ^= t;
        aslr_rng_state[1] ^= t >> 19;
        /* Small delay to allow timer drift / interrupt jitter */
        for (volatile int j = 0; j < 32; j++) { }
    }

    uint64_t t2 = read_tsc();
    aslr_rng_state[1] ^= (t2 - t1) * 0xC2B2AE3D27D4EB4FULL;

    /* Strong initial churn */
    for (int i = 0; i < 64; i++) (void)aslr_rand();
}

void print_boot_timestamp(void) {
    uint32_t ms = system_ticks;
    uint32_t sec = ms / 1000;
    uint32_t frac = ms % 1000;

    print("[ ");
    if (sec < 10) print("   ");
    else if (sec < 100) print("  ");
    else if (sec < 1000) print(" ");
    print_decimal(sec);
    print(".");
    if (frac < 10) print("00");
    else if (frac < 100) print("0");
    print_decimal(frac);
    print(" ] ");
}

// Major: snapshot current, install next CR3 + TSS.esp0, switch
void context_switch(int next) {
    if (next == current_task || tasks[next].state != 1) return;

    /* Scheduler side-channel hardening: clear sensitive registers before switching
       to reduce leakage across privilege domains. */
    asm volatile(
        "xor %%eax, %%eax\n"
        "xor %%ebx, %%ebx\n"
        "xor %%ecx, %%ecx\n"
        "xor %%edx, %%edx\n"
        ::: "eax", "ebx", "ecx", "edx", "memory"
    );

    asm volatile("mov %%esp, %0" : "=m"(tasks[current_task].esp) : : "memory");
    tasks[current_task].eip = (addr_t)__builtin_return_address(0);

    current_task = next;

    uint32_t kstack_top = tasks[current_task].kernel_stack_top;
    if (kstack_top == 0) {
        kstack_top = (addr_t)&kernel_stacks[current_task][KERNEL_STACK_SIZE - 16];
    }
    set_tss_kernel_stack(kstack_top);

    switch_cr3(tasks[current_task].cr3);
}

// Major: round-robin to next runnable task
void schedule(void) {
    int next = (current_task + 1) % MAX_TASKS;
    while (next != current_task && tasks[next].state != 1) {
        next = (next + 1) % MAX_TASKS;
    }
    if (next != current_task) {
        context_switch(next);
    }
}

void yield(void) {
    schedule();
}

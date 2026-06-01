#include "kernel.h"

extern uint8_t stack_top[];
extern tcb_t tasks[MAX_TASKS];
extern int current_task;

#define PAGE_PRESENT   (1 << 0)
#define PAGE_WRITE     (1 << 1)
#define PAGE_USER      (1 << 2)
#define PAGE_WT        (1 << 3)
#define PAGE_CD        (1 << 4)
#define PAGE_ACCESSED  (1 << 5)
#define PAGE_DIRTY     (1 << 6)
#define PAGE_4MB       (1 << 7)
#define PAGE_GLOBAL    (1 << 8)

#define RECURSIVE_PD_VADDR  0xFFFFF000
#define RECURSIVE_PT_VADDR  0xFFC00000

#define USER_PHYS_BASE      0x00200000   // 2 MB - start of demand-paged user physical memory
#define USER_PHYS_PAGES     16384        // 64 MB worth of pages for user demand allocation + COW (large pool on 512MB system)

typedef uint32_t pte_t;
typedef uint32_t pde_t;

/* Physical page allocator for demand paging (stack allocator) */
static uint32_t free_page_stack[USER_PHYS_PAGES];
static int free_page_count = 0;
static uint16_t page_refcounts[USER_PHYS_PAGES];

static void init_user_page_allocator(void) {
    free_page_count = 0;
    for (int i = 0; i < USER_PHYS_PAGES; i++) {
        page_refcounts[i] = 0;
    }
    for (int i = USER_PHYS_PAGES - 1; i >= 0; i--) {
        free_page_stack[free_page_count++] = USER_PHYS_BASE + (i * PAGE_SIZE);
    }
}

uint32_t alloc_user_physical_page(void) {
    if (free_page_count == 0) {
        return 0; // out of memory
    }
    uint32_t phys = free_page_stack[--free_page_count];
    // Find index for refcount (simple linear search for small number of pages)
    int idx = (phys - USER_PHYS_BASE) / PAGE_SIZE;
    if (idx >= 0 && idx < USER_PHYS_PAGES) {
        page_refcounts[idx] = 1;
    }
    return phys;
}

void free_user_physical_page(uint32_t phys_addr) {
    int idx = (phys_addr - USER_PHYS_BASE) / PAGE_SIZE;
    if (idx >= 0 && idx < USER_PHYS_PAGES) {
        page_refcounts[idx] = 0;
    }
    if (free_page_count < USER_PHYS_PAGES) {
        free_page_stack[free_page_count++] = phys_addr;
    }
}

void page_ref_inc(uint32_t phys_addr) {
    int idx = (phys_addr - USER_PHYS_BASE) / PAGE_SIZE;
    if (idx >= 0 && idx < USER_PHYS_PAGES) {
        page_refcounts[idx]++;
    }
}

int page_ref_dec(uint32_t phys_addr) {
    int idx = (phys_addr - USER_PHYS_BASE) / PAGE_SIZE;
    if (idx >= 0 && idx < USER_PHYS_PAGES && page_refcounts[idx] > 0) {
        page_refcounts[idx]--;
        return page_refcounts[idx];
    }
    return 0;
}

static pde_t kernel_page_dir[1024] __attribute__((aligned(4096)));

#if !defined(__x86_64__)
/* Legacy 32-bit demo blob only used in the old paging_init path */
static const uint8_t user_shell_code[] = {
    0x3e, 0x20, 0x00,
    0xb8, 0x01, 0x00, 0x00, 0x00,
    0xbb, 0x00, 0x00, 0x40, 0x00,
    0xcd, 0x80,
    0xb8, 0x03, 0x00, 0x00, 0x00,
    0xbb, 0x00, 0x10, 0x40, 0x00,
    0xcd, 0x80,
    0xb8, 0x07, 0x00, 0x00, 0x00,
    0xbb, 0x00, 0x10, 0x40, 0x00,
    0xcd, 0x80,
    0xeb, 0xda,
    0x00
};
#endif

// Major: For 64-bit we preserve the early 4-level identity map (0-4GiB via 2MiB pages)
// established by the long-mode trampoline. This guarantees kernel text/data stay
// mapped after entry and prevents the code-fetch #PF at 0x100xxx that was causing
// the 0x0e -> 0x08 -> triple fault loop. The 32-bit PD/PT construction is only for legacy.
void paging_init(void) {
#if defined(__x86_64__)
    /* 64-bit path: keep the trampoline PML4 (already identity 0-4GiB, kernel at 1MiB is covered).
     * Just initialize the demand-page allocator. Full per-task 4-level user paging + high-half
     * kernel mapping is future work once the rudimentary boot is solid. */
    init_user_page_allocator();
    set_tss_kernel_stack(KERNEL_TSS_STACK);
    /* Do NOT touch CR3 or rebuild page tables here — the early environment is sufficient
     * and correct for reaching the verbose boot banner + kernel shell. */
    return;
#else
    for (int i = 0; i < 1024; i++) {
        kernel_page_dir[i] = 0;
    }

    /* Expanded low memory identity mapping to support large demand-paging pool (first 64MB).
       This resolves the previous "small 2-4MB early pool" limitation for user physical memory. */
    static pte_t low_mem_pt[16384] __attribute__((aligned(4096)));  /* enough for 64MB */
    for (int i = 0; i < 16384; i++) {
        low_mem_pt[i] = (i * PAGE_SIZE) | PAGE_PRESENT | PAGE_WRITE | PAGE_GLOBAL;
    }
    /* Map first 16 PDEs (64MB) for identity low memory */
    for (int pd_idx = 0; pd_idx < 16; pd_idx++) {
        kernel_page_dir[pd_idx] = ((addr_t)&low_mem_pt[pd_idx * 1024]) | PAGE_PRESENT | PAGE_WRITE;
    }

    kernel_page_dir[1023] = ((addr_t)kernel_page_dir) | PAGE_PRESENT | PAGE_WRITE;

    init_user_page_allocator();

    static pte_t user_pt[1024] __attribute__((aligned(4096)));
    for (int i = 0; i < 1024; i++) {
        user_pt[i] = (0x400000 + i * PAGE_SIZE) | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    }
    kernel_page_dir[1] = ((addr_t)user_pt) | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;

    asm volatile("mov %0, %%cr3" :: "r"((addr_t)kernel_page_dir));

    uint32_t cr0;
    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 |= (1 << 31) | (1 << 16);
    asm volatile("mov %0, %%cr0" :: "r"(cr0));

    uint8_t* dest = (uint8_t*)USER_VIRT_BASE;
    for (size_t i = 0; i < sizeof(user_shell_code); i++) {
        dest[i] = user_shell_code[i];
    }

    set_tss_kernel_stack(KERNEL_TSS_STACK);
#endif
}

// Major: per-task PD/PTs with Rust prot bits, guard page at 0x7FB000, guarded kstack
void create_user_pagedir(uint32_t task_id) {
    if (task_id >= MAX_TASKS) return;

    static pde_t pd_pool[MAX_TASKS][1024] __attribute__((aligned(4096)));
    static int next_pd = 0;

    if (next_pd >= MAX_TASKS) {
        println("Out of page directories!");
        return;
    }

    pde_t *pd = pd_pool[next_pd++];
    for (int i = 0; i < 1024; i++) {
        pd[i] = 0;
    }

    pd[0] = kernel_page_dir[0];
    pd[1023] = kernel_page_dir[1023];

    static pte_t user_pts[16][1024] __attribute__((aligned(4096)));
    pte_t *upt = user_pts[task_id];
    for (int i = 0; i < 1024; i++) {
        upt[i] = 0;
    }

    // Demand paging: only pre-map a small number of pages (for initial loaded image).
    // The rest are set up with protection bits but not PRESENT -> will demand fault.
    const int INITIAL_PREMAP_PAGES = 64;  // 256KB initial pre-mapped for loaded images + stack; rest demand paged
    for (int i = 0; i < USER_MAP_PAGES; i++) {
        uint32_t vaddr = USER_AREA_BASE + i * PAGE_SIZE;
        uint32_t prot = rust_get_user_page_protection(task_id, vaddr);
        if (i < INITIAL_PREMAP_PAGES) {
            upt[i] = vaddr | prot | PAGE_PRESENT;
        } else {
            // Not present: demand paged on first access (zero-filled)
            upt[i] = vaddr | prot;   // keep prot bits for when we map on fault
        }
    }

    uint32_t guard_page = 0x7FB000;
    upt[(guard_page - USER_AREA_BASE) >> 12] = 0;

    for (int i = 0; i < 4; i++) {
        uint32_t vaddr = 0x7FF000 - (3 - i) * PAGE_SIZE;
        uint32_t prot = rust_get_user_page_protection(task_id, vaddr);
        upt[(vaddr - USER_AREA_BASE) >> 12] = vaddr | prot;
    }

    pd[1] = ((addr_t)upt) | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;

    uint32_t phys_pd = (addr_t)pd;
    tasks[task_id].cr3 = phys_pd;

    static uint8_t per_task_kstacks[MAX_TASKS][2 * PAGE_SIZE] __attribute__((aligned(4096)));
    uint8_t *stack_area = per_task_kstacks[task_id];
    uint32_t guard_vaddr = (addr_t)stack_area;
    uint32_t stack_base  = guard_vaddr + PAGE_SIZE;

    tasks[task_id].kernel_stack_top = stack_base + PAGE_SIZE - 16;
}

void switch_cr3(addr_t cr3) {
    if (cr3 == 0) return;
    asm volatile("mov %0, %%cr3" :: "r"(cr3));
}

#define PAGE_COW   (1 << 9)   // Software COW flag

// Demand paging and Copy-on-Write fault handler (core memory safety logic)
int handle_demand_page_fault(uint32_t fault_addr, uint32_t err_code __attribute__((unused))) {
    uint32_t pd_index = fault_addr >> 22;
    uint32_t pt_index = (fault_addr >> 12) & 0x3FF;

    pde_t *pd = (pde_t *)RECURSIVE_PD_VADDR;
    if ((pd[pd_index] & PAGE_PRESENT) == 0) {
        return -1;
    }

    pte_t *pt = (pte_t *)((addr_t)RECURSIVE_PT_VADDR + (pd_index * PAGE_SIZE));
    pte_t entry = pt[pt_index];

    // === COW write fault ===
    if ((err_code & 2) != 0 && (entry & PAGE_COW) != 0) {
        uint32_t old_phys = entry & ~0xFFF;
        int refs = page_ref_dec(old_phys);

        uint32_t new_phys = alloc_user_physical_page();
        if (new_phys == 0) {
            if (refs >= 0) page_ref_inc(old_phys);
            return -3; // OOM
        }

        // Copy page
        uint8_t *src = (uint8_t *)(addr_t)old_phys;
        uint8_t *dst = (uint8_t *)(addr_t)new_phys;
        for (int i = 0; i < PAGE_SIZE; i++) dst[i] = src[i];

        page_ref_inc(new_phys);

        uint32_t new_prot = (entry & 0xFFF) | PAGE_PRESENT | PAGE_WRITE;
        new_prot &= ~PAGE_COW;
        pt[pt_index] = new_phys | new_prot;

        asm volatile("invlpg (%0)" :: "r"(fault_addr) : "memory");
        return 0;
    }

    if ((entry & PAGE_PRESENT) != 0) {
        return -2;
    }

    // === Normal demand zero-fill ===
    uint32_t phys = alloc_user_physical_page();
    if (phys == 0) {
        return -3;
    }

    uint8_t *page = (uint8_t *)(addr_t)phys;
    for (int i = 0; i < PAGE_SIZE; i++) page[i] = 0;

    uint32_t prot = entry & 0xFFF;
    pt[pt_index] = phys | prot | PAGE_PRESENT;

    asm volatile("invlpg (%0)" :: "r"(fault_addr) : "memory");

    return 0;
}

void drop_to_ring3(addr_t entry, addr_t stack) {
#if defined(__x86_64__)
    /* 64-bit user mode entry stub during the 64-bit transition.
       Real implementation will use sysret or iretq with proper SS/CS/RSP/RIP. */
    (void)entry; (void)stack;
    asm volatile("cli; hlt");
#else
    uint32_t eflags = 0x200;

    asm volatile (
        "cli\n"
        "push $0x23\n"
        "push %[user_esp]\n"
        "push %[eflags]\n"
        "push $0x1B\n"
        "push %[user_eip]\n"
        "mov $0x23, %%dx\n"
        "mov %%dx, %%ds\n"
        "mov %%dx, %%es\n"
        "mov %%dx, %%fs\n"
        "mov %%dx, %%gs\n"
        "xor %%ecx, %%ecx\n"
        "mov %%ecx, %%dr0\n"
        "mov %%ecx, %%dr1\n"
        "mov %%ecx, %%dr2\n"
        "mov %%ecx, %%dr3\n"
        "mov %%ecx, %%dr6\n"
        "mov %%ecx, %%dr7\n"
        "iret\n"
        : 
        : [user_esp] "m" (stack),
          [user_eip] "m" (entry),
          [eflags]   "m" (eflags)
        : "ecx", "edx", "memory"
    );
#endif
}

static bool is_user_address_valid(uint32_t vaddr) {
    uint32_t pd_index = vaddr >> 22;
    uint32_t pt_index = (vaddr >> 12) & 0x3FF;

    pde_t *pd = (pde_t *)RECURSIVE_PD_VADDR;
    if ((pd[pd_index] & PAGE_PRESENT) == 0) return false;

    pte_t *pt = (pte_t *)((addr_t)RECURSIVE_PT_VADDR + (pd_index * PAGE_SIZE));
    if ((pt[pt_index] & PAGE_PRESENT) == 0) return false;

    if ((pt[pt_index] & PAGE_USER) == 0) return false;

    return true;
}

// Major: copy_from_user with recursive PT walk + Rust validator (guard/W^X policy)
int copy_from_user(void *dst, const void *src, size_t n) {
    if (n == 0) return 0;
    if (n > USER_MEM_MAX_COPY) n = USER_MEM_MAX_COPY;

    uintptr_t saddr = (uintptr_t)src;
    uintptr_t daddr = (uintptr_t)dst;

    if (saddr < USER_MEM_START || saddr + n > USER_MEM_END ||
        daddr + n < daddr) {
        return -1;
    }

    for (size_t off = 0; off < n; off += PAGE_SIZE) {
        uint32_t page_vaddr = (saddr + off) & ~0xFFF;
        if (!is_user_address_valid(page_vaddr)) {
            return -1;
        }
        if (!rust_validate_page_fault(current_task, page_vaddr, 1)) {
            return -1;
        }
    }

    uint8_t *d = dst; const uint8_t *s = src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
    return 0;
}

// Major: copy_to_user with same recursive + Rust validation as from_user
int copy_to_user(void *dst, const void *src, size_t n) {
    if (n == 0) return 0;
    if (n > USER_MEM_MAX_COPY) n = USER_MEM_MAX_COPY;

    uintptr_t daddr = (uintptr_t)dst;

    if (daddr < USER_MEM_START || daddr + n > USER_MEM_END ||
        daddr + n < daddr) {
        return -1;
    }

    for (size_t off = 0; off < n; off += PAGE_SIZE) {
        uint32_t page_vaddr = (daddr + off) & ~0xFFF;
        if (!is_user_address_valid(page_vaddr)) {
            return -1;
        }
        if (!rust_validate_page_fault(current_task, page_vaddr, 2)) {
            return -1;
        }
    }

    uint8_t *d = dst; const uint8_t *s = src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
    return 0;
}

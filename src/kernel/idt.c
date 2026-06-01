#include "kernel.h"

#define PAGE_PRESENT   (1 << 0)
#define RECURSIVE_PD_VADDR  0xFFFFF000
#define RECURSIVE_PT_VADDR  0xFFC00000

typedef uint32_t pde_t;
typedef uint32_t pte_t;

// Forward declarations for demand paging support
int handle_demand_page_fault(uint32_t fault_addr, uint32_t err_code);



// Weak 4-parameter fallback (matches the Rust signature).
// When RUST_ENABLED=1 the real Rust implementation overrides this via --whole-archive.
__attribute__((weak))
int rust_handle_demand_page_fault(uint32_t fault_addr, uint32_t err_code, bool is_cow, uint16_t ref_count) {
    // Fallback to the pure C implementation
    (void)is_cow; (void)ref_count;
    return handle_demand_page_fault(fault_addr, err_code);
}

struct idt_entry {
    uint16_t base_low;
    uint16_t sel;
    uint8_t  always0;
    uint8_t  flags;
    uint16_t base_high;
} __attribute__((packed));

struct idt_ptr {
    uint16_t limit;
    addr_t   base;
} __attribute__((packed));

static struct idt_entry idt[256];
static struct idt_ptr idt_ptr;

/* 64-bit IDT entry format */
struct idt_entry64 {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t  ist;
    uint8_t  type_attr;
    uint16_t offset_mid;
    uint32_t offset_high;
    uint32_t zero;
} __attribute__((packed));

/* Early minimal 64-bit IDT used during the very first moments in long mode */
static struct idt_entry64 early_idt[32] __attribute__((aligned(16)));
static struct idt_ptr early_idt_ptr;

/* Symbol from lowlevel64.S */
extern void early_page_fault64(void);

void setup_early_idt64(void) {
    /* Only set up vector 14 (page fault) for now — this stops the 0x0e → 0x08 loop */
    uint64_t handler = (uint64_t)early_page_fault64;

    early_idt[14].offset_low  = handler & 0xFFFF;
    early_idt[14].selector    = 0x08;           /* 64-bit code segment */
    early_idt[14].ist         = 0;
    early_idt[14].type_attr   = 0x8E;           /* Present + Interrupt Gate */
    early_idt[14].offset_mid  = (handler >> 16) & 0xFFFF;
    early_idt[14].offset_high = (handler >> 32) & 0xFFFFFFFF;
    early_idt[14].zero        = 0;

    early_idt_ptr.limit = sizeof(early_idt) - 1;
    early_idt_ptr.base  = (addr_t)&early_idt[0];

    __asm__ volatile ("lidt %0" : : "m"(early_idt_ptr));
}

char keyboard_buffer[256];
uint32_t kb_head = 0;
uint32_t kb_tail = 0;

extern void idt_load(addr_t);
extern void isr0(void); extern void isr1(void); extern void isr2(void); extern void isr3(void);
extern void isr4(void); extern void isr5(void); extern void isr6(void); extern void isr7(void);
extern void isr8(void); extern void isr9(void); extern void isr10(void); extern void isr11(void);
extern void isr12(void); extern void isr13(void); extern void isr14(void); extern void isr15(void);
extern void isr16(void); extern void isr17(void); extern void isr18(void); extern void isr19(void);
extern void isr20(void); extern void isr21(void); extern void isr22(void); extern void isr23(void);
extern void isr24(void); extern void isr25(void); extern void isr26(void); extern void isr27(void);
extern void isr28(void); extern void isr29(void); extern void isr30(void); extern void isr31(void);
extern void isr32(void); extern void isr33(void); extern void isr34(void); extern void isr35(void);
extern void isr36(void); extern void isr37(void); extern void isr38(void); extern void isr39(void);
extern void isr40(void); extern void isr41(void); extern void isr42(void); extern void isr43(void);
extern void isr44(void); extern void isr45(void); extern void isr46(void); extern void isr47(void);
extern void isr128(void);

void interrupt_handler(struct regs *r);
void page_fault_handler(struct regs *r);

/* Temporary stub so lowlevel64.S links while we finish the real 64-bit interrupt handling */
void interrupt_handler64(void *frame) {
    (void)frame;
    __asm__ volatile ("cli; hlt");
}

extern int current_task;
extern tcb_t tasks[MAX_TASKS];

static void pic_init(void) {
    outb(0x20, 0x11); outb(0xA0, 0x11);
    outb(0x21, 0x20); outb(0xA1, 0x28);
    outb(0x21, 0x04); outb(0xA1, 0x02);
    outb(0x21, 0x01); outb(0xA1, 0x01);
    outb(0x21, 0xFC);
    outb(0xA1, 0xFF);
}

static void keyboard_init(void) {
    uint8_t status;

    while (inb(0x64) & 2);
    outb(0x64, 0xAD);
    while (inb(0x64) & 2);
    outb(0x64, 0xA7);

    while (inb(0x64) & 1) { inb(0x60); }

    while (inb(0x64) & 2);
    outb(0x64, 0x20);
    status = inb(0x60);

    status |= (1 << 0);
    status &= ~(1 << 1);
    status |= (1 << 6);

    while (inb(0x64) & 2);
    outb(0x64, 0x60);
    outb(0x60, status);

    while (inb(0x64) & 2);
    outb(0x64, 0xAE);

    while (inb(0x64) & 2);
    outb(0x60, 0xF4);

    int got_ack = 0;
    int timeout = 100000;
    while (timeout-- > 0) {
        if (inb(0x64) & 1) {
            uint8_t ack = inb(0x60);
            if (ack == 0xFA) { got_ack = 1; break; }
        }
    }

    while (inb(0x64) & 1) { inb(0x60); }
    (void)got_ack;
}

static void serial_init(void) {
    outb(0x3F9, 0x00);
    outb(0x3FB, 0x80);
    outb(0x3F8, 0x03);
    outb(0x3F9, 0x00);
    outb(0x3FB, 0x03);
    outb(0x3FA, 0xC7);
    outb(0x3FC, 0x0B);

    outb(0x2F9, 0x00);
    outb(0x2FB, 0x80);
    outb(0x2F8, 0x03);
    outb(0x2F9, 0x00);
    outb(0x2FB, 0x03);
    outb(0x2FA, 0xC7);
    outb(0x2FC, 0x0B);
}

static void idt_set_gate(uint8_t num, addr_t base, uint16_t sel, uint8_t flags) {
    idt[num].base_low  = base & 0xFFFF;
    idt[num].base_high = (base >> 16) & 0xFFFF;
    idt[num].sel       = sel;
    idt[num].always0   = 0;
    idt[num].flags     = flags;
}

// Major: IDT setup, PIC remap, serial/keyboard init, syscall gate (0x80, DPL=3)
void idt_init(void) {
    idt_ptr.limit = sizeof(struct idt_entry) * 256 - 1;
    idt_ptr.base  = (addr_t)&idt[0];

    idt_set_gate(0, (addr_t)isr0, 0x08, 0x8E);
    idt_set_gate(1, (addr_t)isr1, 0x08, 0x8E);
    idt_set_gate(2, (addr_t)isr2, 0x08, 0x8E);
    idt_set_gate(3, (addr_t)isr3, 0x08, 0x8E);
    idt_set_gate(4, (addr_t)isr4, 0x08, 0x8E);
    idt_set_gate(5, (addr_t)isr5, 0x08, 0x8E);
    idt_set_gate(6, (addr_t)isr6, 0x08, 0x8E);
    idt_set_gate(7, (addr_t)isr7, 0x08, 0x8E);
    idt_set_gate(8, (addr_t)isr8, 0x08, 0x8E);
    idt_set_gate(9, (addr_t)isr9, 0x08, 0x8E);
    idt_set_gate(10, (addr_t)isr10, 0x08, 0x8E);
    idt_set_gate(11, (addr_t)isr11, 0x08, 0x8E);
    idt_set_gate(12, (addr_t)isr12, 0x08, 0x8E);
    idt_set_gate(13, (addr_t)isr13, 0x08, 0x8E);
    idt_set_gate(14, (addr_t)isr14, 0x08, 0x8E);
    idt_set_gate(15, (addr_t)isr15, 0x08, 0x8E);
    idt_set_gate(16, (addr_t)isr16, 0x08, 0x8E);
    idt_set_gate(17, (addr_t)isr17, 0x08, 0x8E);
    idt_set_gate(18, (addr_t)isr18, 0x08, 0x8E);
    idt_set_gate(19, (addr_t)isr19, 0x08, 0x8E);
    idt_set_gate(20, (addr_t)isr20, 0x08, 0x8E);
    idt_set_gate(21, (addr_t)isr21, 0x08, 0x8E);
    idt_set_gate(22, (addr_t)isr22, 0x08, 0x8E);
    idt_set_gate(23, (addr_t)isr23, 0x08, 0x8E);
    idt_set_gate(24, (addr_t)isr24, 0x08, 0x8E);
    idt_set_gate(25, (addr_t)isr25, 0x08, 0x8E);
    idt_set_gate(26, (addr_t)isr26, 0x08, 0x8E);
    idt_set_gate(27, (addr_t)isr27, 0x08, 0x8E);
    idt_set_gate(28, (addr_t)isr28, 0x08, 0x8E);
    idt_set_gate(29, (addr_t)isr29, 0x08, 0x8E);
    idt_set_gate(30, (addr_t)isr30, 0x08, 0x8E);
    idt_set_gate(31, (addr_t)isr31, 0x08, 0x8E);

    idt_set_gate(32, (addr_t)isr32, 0x08, 0x8E);
    idt_set_gate(33, (addr_t)isr33, 0x08, 0x8E);
    idt_set_gate(34, (addr_t)isr34, 0x08, 0x8E);
    idt_set_gate(35, (addr_t)isr35, 0x08, 0x8E);
    idt_set_gate(36, (addr_t)isr36, 0x08, 0x8E);
    idt_set_gate(37, (addr_t)isr37, 0x08, 0x8E);
    idt_set_gate(38, (addr_t)isr38, 0x08, 0x8E);
    idt_set_gate(39, (addr_t)isr39, 0x08, 0x8E);
    idt_set_gate(40, (addr_t)isr40, 0x08, 0x8E);
    idt_set_gate(41, (addr_t)isr41, 0x08, 0x8E);
    idt_set_gate(42, (addr_t)isr42, 0x08, 0x8E);
    idt_set_gate(43, (addr_t)isr43, 0x08, 0x8E);
    idt_set_gate(44, (addr_t)isr44, 0x08, 0x8E);
    idt_set_gate(45, (addr_t)isr45, 0x08, 0x8E);
    idt_set_gate(46, (addr_t)isr46, 0x08, 0x8E);
    idt_set_gate(47, (addr_t)isr47, 0x08, 0x8E);

    idt_set_gate(0x80, (addr_t)isr128, 0x08, 0xEE);

    pic_init();
    keyboard_init();
    serial_init();
    idt_load((addr_t)&idt_ptr);

    /* Enable maskable interrupts now that IDT + PIC remap are live.
     * This is required for the 1 kHz PIT timer to drive system_ticks
     * (used by msleep for the paced, readable boot log and later preemption).
     */
    asm volatile("sti");
}

// Page fault handler (Rust policy + demand paging / COW support)
void page_fault_handler(struct regs *r) {
    addr_t fault_addr;
    asm volatile("mov %%cr2, %0" : "=r"(fault_addr));

    uint32_t err = r->err_code;

    // Try demand paging / COW first (Rust is now the policy authority for safety)
    if ((err & 1) == 0 && current_task > 0 && fault_addr >= USER_AREA_BASE) {
        // Gather COW metadata for Rust policy decision
        bool is_cow = false;
        uint16_t ref_count = 1;

        // Walk to check for our software COW flag (bit 9) and get refcount if possible
        // (simplified walk — production version would be more careful with races)
        uint32_t pd_index = fault_addr >> 22;
        uint32_t pt_index = (fault_addr >> 12) & 0x3FF;
        pde_t *pd = (pde_t *)(addr_t)RECURSIVE_PD_VADDR;
        if ((pd[pd_index] & PAGE_PRESENT) != 0) {
            pte_t *pt = (pte_t *)((addr_t)RECURSIVE_PT_VADDR + (pd_index * PAGE_SIZE));
            pte_t entry = pt[pt_index];
            if ((entry & (1 << 9)) != 0) {  // PAGE_COW software bit
                is_cow = true;
            }
            // Best-effort refcount (real version could store it in available PTE bits too)
            ref_count = 1; // conservative default; C side will double-check on COW path
        }

        int action = rust_handle_demand_page_fault(fault_addr, err, is_cow, ref_count);

        if (action == 0 /* DemandZero */ || action == 1 /* CowCopyNeeded */) {
            // Let the existing C demand/COW logic handle the heavy lifting
            // (allocation, copying, PTE update, TLB shootdown)
            if (handle_demand_page_fault(fault_addr, err) == 0) {
                return; // success
            }
        } else if (action == 2 /* NoAction */) {
            return; // Rust decided no work needed (e.g. last ref on COW)
        }

        // Invalid or error from Rust policy → fall through to kill path
    }
    println("PAGE FAULT at ");
    print_hex(fault_addr);
    println(" err=");
    print_hex(err);
    println(" task=");
    print_hex(current_task);

    bool allowed = rust_validate_page_fault(current_task, fault_addr, err);

    if (!allowed) {
        println("Rejected by validator - killing task ");
        print_hex(current_task);
        println("");
        tasks[current_task].state = 0;
        schedule();

        if (tasks[current_task].state == 0) {
            for (;;) {
                asm volatile("cli; hlt");
            }
        }
        return;
    }

    asm volatile("cli; hlt");
}

// Central interrupt dispatcher
void interrupt_handler(struct regs *r) {
    if (r->int_no == 0x80) {
        syscall_handler(r);
    } else if (r->int_no == 14) {
        page_fault_handler(r);
    } else if (r->int_no < 32) {
        if (r->int_no == 1) {
            return;
        }
        println("Exception! Vector: ");
        print_hex(r->int_no);
        println(" at EIP=");
        print_hex(r->eip);
        println("");
        asm volatile("cli; hlt");
    } else if (r->int_no >= 32 && r->int_no < 48) {
        if (r->int_no == 32) {
            if (current_task < MAX_TASKS && !tasks[current_task].in_kernel) {
                uint32_t uesp = r->useresp;
                if (uesp > 0x400000 && (r->cs & 3) == 3) {
                    tasks[current_task].esp = uesp;
                    tasks[current_task].eip = r->eip;
                }
            }
            timer_handler();
        } else if (r->int_no == 33) {
            uint8_t scancode = inb(0x60);

            if (scancode < 0x80) {
                char c = 0;
                if (scancode >= 0x02 && scancode <= 0x0B) c = "1234567890"[scancode-0x02];
                else if (scancode >= 0x10 && scancode <= 0x19) c = "qwertyuiop"[scancode-0x10];
                else if (scancode >= 0x1E && scancode <= 0x26) c = "asdfghjkl"[scancode-0x1E];
                else if (scancode >= 0x2C && scancode <= 0x32) c = "zxcvbnm"[scancode-0x2C];
                else if (scancode == 0x39) c = ' ';
                else if (scancode == 0x1C) c = '\n';
                else if (scancode == 0x0C) c = '-';
                else if (scancode == 0x0D) c = '=';
                else if (scancode == 0x33) c = ',';
                else if (scancode == 0x34) c = '.';
                else if (scancode == 0x35) c = '/';
                if (c) {
                    keyboard_buffer[kb_tail] = c;
                    kb_tail = (kb_tail + 1) % 256;
                    if (kb_tail == kb_head) kb_head = (kb_head + 1) % 256;
                }
            }
        }
        if (r->int_no >= 40) outb(0xA0, 0x20);
        outb(0x20, 0x20);
    }
}

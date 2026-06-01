.section .multiboot, "a"
.align 8

multiboot_header_start:
    .long 0xe85250d6
    .long 0
    .long multiboot_header_end - multiboot_header_start
    .long -(0xe85250d6 + 0 + (multiboot_header_end - multiboot_header_start))
    .word 0
    .word 0
    .long 8
multiboot_header_end:

.section .text
.code32
.global _start
.extern kernel_main

_start:
    movl $stack_top, %esp

    /* === Enable Long Mode === */

    /* 1. Enable PAE in CR4 */
    movl %cr4, %eax
    orl  $(1 << 5), %eax          /* CR4.PAE */
    movl %eax, %cr4

    /* 2. Set up a minimal PML4 for early 64-bit (identity map first 4 GiB using 2 MiB pages) */
    movl $pml4, %edi
    movl %edi, %cr3

    /* Clear the three tables we need (PML4 + PDPT + single PD) */
    xorl %eax, %eax
    movl $pml4, %edi
    movl $12288, %ecx          /* 3 pages */
    rep stosl

    /* PML4[0] -> PDPT */
    movl $pdpt, %eax
    orl  $0x3, %eax
    movl %eax, pml4

    /* PDPT[0] -> PD (we only map a safe low region for the kernel + early data) */
    movl $pd, %eax
    orl  $0x3, %eax
    movl %eax, pdpt

    /* Fill one PD with 2 MiB identity pages for the first 1 GiB (512 entries * 2 MiB).
     * This is more than enough for the kernel (loaded at 1 MiB), stacks, GDT, IDT,
     * early 4K tables, and the 64 MiB demand pool.
     *
     * CRITICAL: PAE / 4-level PDEs are 64-bit. Flags + PS + P + low phys bits MUST be in
     * the low 32 bits of the entry. The previous code put 0x83 in the high dword only,
     * leaving P=0 in low → instant instruction-fetch #PF on the first fetch after CR0.PG.
     * That was the exact cause of every 0x0e @ 0x100099 → 0x08 → triple fault.
     */
    movl $pd, %edi
    movl $0x00000000, %ebx
    movl $512, %ecx            /* 512 * 2 MiB = 1 GiB, fits in one 4 KiB PD */

1:
    /* Build a correct 2 MiB PDE in EAX:EDX then store as 64-bit */
    movl %ebx, %eax
    andl $0xFFE00000, %eax     /* 2 MiB aligned phys base in bits 31:21 */
    orl  $0x00000083, %eax     /* P | R/W | PS (2 MiB) + other flags as needed */
    movl $0x00000000, %edx     /* high 32 = 0 (phys < 4 GiB) */
    movl %eax, 0(%edi)
    movl %edx, 4(%edi)
    addl $0x200000, %ebx
    addl $8, %edi
    loop 1b

    /* 3. Enable Long Mode in EFER */
    movl $0xC0000080, %ecx        /* EFER MSR */
    rdmsr
    orl  $(1 << 8), %eax          /* EFER.LME */
    wrmsr

    /* 4. Enable Paging (CR0.PG) */
    movl %cr0, %eax
    orl  $(1 << 31), %eax         /* CR0.PG */
    movl %eax, %cr0

    /* Load the 64-bit GDT (with L-bit code descriptor) now that paging is on and
     * our early 4-level tables are live and stable. */
    lgdt gdt64_ptr32

    /* 5. Far jump to 64-bit code segment using the 64-bit code selector
     * from the GDT we just loaded. */
    ljmp $0x08, $long_mode_entry

.section .text
.code64
long_mode_entry:
    lgdt (gdt64_ptr)

    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    movabs $stack_top, %rsp

    movw $0x3f8, %dx
    movb $'6', %al; outb %al, %dx
    movb $'4', %al; outb %al, %dx
    movb $'\r', %al; outb %al, %dx
    movb $'\n', %al; outb %al, %dx

    /* Enable SSE (required because gcc -O2 vectorizes loops with movaps/movdqa etc.
     * Without CR4.OSFXSR, any SSE instruction in long mode raises #UD.
     * This was the cause of the new triple fault (vector 6) during paging_init. */
    movq %cr4, %rax
    orq  $(1 << 9), %rax      /* CR4.OSFXSR */
    movq %rax, %cr4

    movq %cr0, %rax
    andq $~(1 << 2), %rax     /* clear CR0.EM */
    orq  $(1 << 1), %rax      /* set CR0.MP */
    movq %rax, %cr0

    fninit                    /* clean FPU/SSE state */

    cli
    call kernel_main

    cli
    hlt

/* Full early 64-bit environment setup - guarantees no double-fault loops */
.section .text
.code64
setup_full_early_64bit_env:
    /* TSS + IST1 */
    lea ist1_stack_top(%rip), %rax
    movq %rax, tss64 + 36

    /* TSS descriptor in GDT */
    lea gdt64_start(%rip), %rdi
    lea tss64(%rip), %rax
    movw %ax, 24(%rdi)
    shrq $16, %rax
    movb %al, 28(%rdi)
    movb %ah, 29(%rdi)
    shrq $16, %rax
    movb %al, 32(%rdi)
    movl %eax, 33(%rdi)
    movw $104, 26(%rdi)
    movb $0x89, 30(%rdi)
    movb $0x00, 31(%rdi)

    movw $0x18, %ax
    ltr %ax

    /* Full IDT 0-31 - all vectors valid, critical on IST1 */
    lea early_idt64_table(%rip), %rdi
    lea early_page_fault64(%rip), %rax
    lea early_generic_halt64(%rip), %rbx

    mov $0, %rcx
1:
    cmp $32, %rcx
    jge 2f

    movq %rbx, %rdx
    movb $1, %r8b

    cmp $14, %rcx
    jne 3f
    movq %rax, %rdx
3:
    movw %dx, 0(%rdi)
    movw $0x08, 2(%rdi)
    movb %r8b, 4(%rdi)
    movb $0x8E, 5(%rdi)
    shrq $16, %rdx
    movw %dx, 6(%rdi)
    shrq $16, %rdx
    movl %edx, 8(%rdi)
    movl $0, 12(%rdi)

    add $16, %rdi
    inc %rcx
    jmp 1b
2:
    lea early_idt64_ptr(%rip), %rax
    lidt (%rax)
    ret

.section .data
.align 16
early_idt64_table:
    .skip 32 * 16          /* Full coverage for vectors 0-31 to prevent any double-fault loops */

early_idt64_ptr:
    .word (32 * 16) - 1
    .quad early_idt64_table

/* Generic halt handler for any unhandled early exception */
.global early_generic_halt64
early_generic_halt64:
    cli
    hlt
    jmp .

/* Full early 64-bit GDT + TSS with IST for security/stability
 * ISTs ensure critical exception handlers (PF, DF, GP, etc.) run on
 * dedicated stacks, preventing stack-based attacks or double faults
 * during exception handling (e.g., #PF on the kernel stack itself).
 */
.section .data
.align 16
gdt64_start:
    .quad 0x0000000000000000          /* Null */
    /* 64-bit code segment (base=0, limit=0, L=1 for long mode, P=1, DPL=0) */
    .quad 0x00209A0000000000
    /* 64-bit data segment */
    .quad 0x0000920000000000
    .quad 0x0000000000000000          /* TSS low (filled later) */
    .quad 0x0000000000000000          /* TSS high */
gdt64_end:

/* 64-bit GDT pointer (for use after entering long mode) */
gdt64_ptr:
    .word gdt64_end - gdt64_start - 1
    .quad gdt64_start

/* 32-bit GDT pointer (for lgdt while still in 32-bit protected mode) */
gdt64_ptr32:
    .word gdt64_end - gdt64_start - 1
    .long gdt64_start   /* 32-bit base is sufficient for the early GDT which is in low memory */

/* TSS with IST stacks for security */
.align 16
tss64:
    .long 0, 0                        /* reserved */
    .quad 0                           /* rsp0 */
    .quad 0, 0, 0                     /* rsp1-2 */
    .quad 0, 0, 0, 0, 0, 0, 0         /* ist1-7 (we'll set ist1) */
    .quad 0                           /* reserved */
    .word 0                           /* iomap base (none) */
    .word 0

/* IST1 stack for critical exceptions (PF, DF, etc.) - security measure */
.align 16
ist1_stack_bottom:
    .space 4096
ist1_stack_top:

.section .bss
.align 16
stack_bottom:
    .space 16384
stack_top:

    /* Small safe stack for early exception handlers (to avoid using potentially bad fault stack) */
    .align 16
early_handler_stack_bottom:
    .space 4096
.global early_handler_stack_top
early_handler_stack_top:

.align 4096
pml4:
    .space 4096
pdpt:
    .space 4096
pd:
    .space 4096
/* 64-bit long mode entry point for Horus (work in progress)
 *
 * This is the foundation for the full 64-bit transition.
 * Currently a skeleton — the real long mode switch, PML4 setup,
 * and jump to kernel_main will be completed in follow-up work.
 */

.code32
.section .text

.global _start64
_start64:
    /* This will eventually contain:
     *   - Check for long mode support
     *   - Set up initial 4-level paging (PML4)
     *   - Enable PAE + EFER.LME
     *   - Load CR3
     *   - Enable paging (CR0.PG)
     *   - Far jump to 64-bit code segment
     *   - Set up 64-bit GDT/TSS
     *   - Call kernel_main (now 64-bit)
     */

    /* For now: just halt if we somehow reach here in 32-bit */
    cli
    hlt
    jmp .
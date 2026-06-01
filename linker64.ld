/* 64-bit linker script for Horus microkernel */
ENTRY(_start)

SECTIONS
{
    . = 0x100000;   /* Start at 1 MiB (standard for multiboot) */

    .text : ALIGN(4K)
    {
        *(.multiboot)
        *(.text)
        *(.text.*)
    }

    .rodata : ALIGN(4K)
    {
        *(.rodata)
        *(.rodata.*)
    }

    .data : ALIGN(4K)
    {
        *(.data)
        *(.data.*)
    }

    .bss : ALIGN(4K)
    {
        *(COMMON)
        *(.bss)
        *(.bss.*)
    }

    /DISCARD/ : { *(.comment) *(.note.*) }
}
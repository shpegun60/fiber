ENTRY(Reset_Handler)
SECTIONS
{
    . = 0x10000000;
    .vectors : { KEEP(*(.vectors)) }
    .text : { *(.text*) *(.rodata*) }
    .gnu.sgstubs 0x10008000 : ALIGN(32) { *(.gnu.sgstubs*) }
    . = 0x30000000;
    .bss (NOLOAD) : { __bss_start = .; *(.bss*) *(COMMON) __bss_end = .; }
    .fiber_secure_context_pool 0x30001000 (NOLOAD) : ALIGN(8) {
        KEEP(*(.fiber_secure_context_pool))
    }
    /DISCARD/ : { *(.comment) *(.ARM.exidx*) *(.ARM.extab*) }
}
ASSERT(SIZEOF(.text) < 0x7f00, "Secure fixture overlaps NSC")
ASSERT(SIZEOF(.gnu.sgstubs) <= 0x1000, "Secure veneers overflow SAU NSC region")
ASSERT(__bss_end < 0x30001000, "Secure BSS overlaps pool")
ASSERT(SIZEOF(.fiber_secure_context_pool) < 0x800, "Pool overlaps stacks")

SECTIONS
{
    . = 0x10000100;
    .text : { *(.text*) *(.rodata*) }
    .gnu.sgstubs 0x10008000 : ALIGN(32) { KEEP(*(.gnu.sgstubs*)) }
    .bss 0x30000000 (NOLOAD) : ALIGN(8) { *(.bss*) *(COMMON) }
    .fiber_secure_context_pool 0x30002000 (NOLOAD) : ALIGN(8) { KEEP(*(.fiber_secure_context_pool)) }
    .data : { *(.data*) }
    .init_array : { *(.init_array*) *(.fini_array*) *(.ctors*) *(.dtors*) }
    ASSERT(SIZEOF(.text) < 0x7e00, "hostile text exceeds Secure range")
    ASSERT(SIZEOF(.gnu.sgstubs) <= 0x1000, "hostile NSC range")
    ASSERT(SIZEOF(.bss) == 8, "only the two four-byte lifecycle markers")
    ASSERT(SIZEOF(.fiber_secure_context_pool) == 480, "unchanged private pool geometry")
    ASSERT(SIZEOF(.data) == 0, "no writable data/counters")
    ASSERT(SIZEOF(.init_array) == 0, "no compiler initialization dependency")
    /DISCARD/ : { *(.comment*) *(.ARM.exidx*) *(.ARM.extab*) *(.note*) }
}

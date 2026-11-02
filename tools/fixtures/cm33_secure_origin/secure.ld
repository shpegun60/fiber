ENTRY(Reset_Handler)
SECTIONS {
    . = 0x10000000;
    .vectors : { KEEP(*(.vectors)) }
    .text : { *(.text*) *(.rodata*) }
    .gnu.sgstubs 0x10008000 : ALIGN(32) { *(.gnu.sgstubs*) }
    . = 0x30000000;
    .bss (NOLOAD) : ALIGN(8) { __bss_start = .; *(.bss*) *(COMMON) . = ALIGN(8); __bss_end = .; }
    .fiber_secure_context_pool 0x30001000 (NOLOAD) : ALIGN(8) {
        __pool_start = .; KEEP(*(.fiber_secure_context_pool)) __pool_end = .;
    }
    .data : { *(.data*) }
    ASSERT(SIZEOF(.vectors) == 64, "Secure vectors")
    ASSERT(SIZEOF(.text) < 0x7f00, "Secure text overlaps NSC")
    ASSERT(SIZEOF(.gnu.sgstubs) <= 0x1000, "NSC extent")
    ASSERT(__bss_end < 0x30001000, "Secure BSS overlaps pool")
    ASSERT(SIZEOF(.fiber_secure_context_pool) == 3172 || SIZEOF(.fiber_secure_context_pool) == 3176, "Records, stacks, marker and permitted alignment gap")
    ASSERT(__pool_end <= 0x30003000, "Pool overlaps Secure MSP")
    ASSERT(SIZEOF(.data) == 0, "No initialized RAM image")
    /DISCARD/ : { *(.comment*) *(.ARM.exidx*) *(.ARM.extab*) *(.note*) }
}

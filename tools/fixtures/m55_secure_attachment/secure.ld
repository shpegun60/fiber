ENTRY(Reset_Handler)
SECTIONS
{
    . = 0;
    .vectors : { KEEP(*(.vectors)) }
    . = 0x10000100;
    .text : { *(.text*) *(.rodata*) }
    .gnu.sgstubs 0x10008000 : ALIGN(32) { KEEP(*(.gnu.sgstubs*)) }
    . = 0x30000000;
    .bss (NOLOAD) : ALIGN(8) { __bss_start = .; *(.bss*) *(COMMON) . = ALIGN(8); __bss_end = .; }
    .fiber_secure_context_pool 0x30002000 (NOLOAD) : ALIGN(8) {
        __pool_start = .; KEEP(*(.fiber_secure_context_pool)) __pool_end = .;
    }
    .data : { *(.data*) }
    ASSERT(SIZEOF(.vectors) == 64, "Secure core vectors")
    ASSERT(SIZEOF(.text) < 0x7e00, "Secure text overlaps veneers")
    ASSERT(SIZEOF(.gnu.sgstubs) <= 0x1000, "NSC range exceeded")
    ASSERT(__bss_end < 0x30002000, "BSS overlaps pool")
    ASSERT(SIZEOF(.fiber_secure_context_pool) == 480, "three private 128-byte slots")
    ASSERT(SIZEOF(.data) == 0, "no RAM load image")
    /DISCARD/ : { *(.comment*) *(.ARM.exidx*) *(.ARM.extab*) *(.note*) }
}

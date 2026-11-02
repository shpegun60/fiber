ENTRY(Reset_Handler)
SECTIONS {
    . = 0x10000000;
    .vectors : { KEEP(*(.vectors)) }
    .text : { *(.text*) }
    .rodata : { *(.rodata*) }
    .gnu.sgstubs 0x10008000 : ALIGN(32) { *(.gnu.sgstubs*) }
    . = 0x30000000;
    .bss (NOLOAD) : { __bss_start = .; *(.bss*) *(COMMON) . = ALIGN(4); __bss_end = .; }
    .fiber_secure_context_pool (NOLOAD) : ALIGN(8) {
        __pool_start = .; *(.fiber_secure_context_pool) __pool_end = .;
    }
    .data : { *(.data*) }
    /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment*) *(.note*) }
}
ASSERT(SIZEOF(.vectors)==64,"Secure vectors")
ASSERT(SIZEOF(.text)+SIZEOF(.rodata)<0x7f00,"Secure text exceeds synthetic flash")
ASSERT(SIZEOF(.gnu.sgstubs)==96,"nine actual SG veneers plus alignment")
ASSERT(SIZEOF(.bss)==8,"two normal BSS markers")
ASSERT(SIZEOF(.fiber_secure_context_pool)==864,"real 3x256 static backing")
ASSERT(__pool_end<0x30001000,"Secure fixture exception stack starts at 0x30001000")
ASSERT(SIZEOF(.data)==0,"no hidden RAM copy startup")

ENTRY(m55_pool_cpp_initialize)
MEMORY
{
    FLASH (rx) : ORIGIN = 0x0C000000, LENGTH = 128K
    RAM (rw) : ORIGIN = 0x30000000, LENGTH = 64K
}
SECTIONS
{
    .text : { *(.text*) *(.rodata*) } > FLASH
    .fiber_secure_context_pool 0x30000040 (NOLOAD) : ALIGN(8)
    {
        KEEP(*(.fiber_secure_context_pool))
    } > RAM
    ASSERT(SIZEOF(.fiber_secure_context_pool) < 0x7000, "pool fixture overflow")
    .bss 0x30008000 (NOLOAD) : ALIGN(4)
    {
        *(.bss*) *(COMMON)
    } > RAM
    .data : { *(.data*) } > RAM AT > FLASH
    ASSERT(SIZEOF(.data) == 0, "pool must not acquire initialized RAM")
    /DISCARD/ : { *(.comment*) *(.ARM.exidx*) *(.ARM.extab*) }
}

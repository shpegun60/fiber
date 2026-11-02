ENTRY(NS_Reset_Handler)
SECTIONS
{
    . = 0x10000;
    .vectors : { __fiber_c55s_ns_vector_start__ = .; KEEP(*(.vectors)) __fiber_c55s_ns_vector_end__ = .; }
    .fixture_case : { KEEP(*(.fixture_case)) }
    .text : { __fiber_c55s_ns_start_code_start__ = .; *(.text*) *(.rodata*) . = ALIGN(2); __fiber_c55s_ns_start_code_end__ = .; }
    . = 0x20010000;
    .bss (NOLOAD) : ALIGN(8) { __bss_start = .; *(.bss*) *(COMMON) . = ALIGN(8); __bss_end = .; }
    .data : { *(.data*) }
    __fiber_c55s_ns_msp_stack_start__ = 0x20018000;
    __fiber_c55s_ns_msp_stack_end__ = 0x20020000;
    ASSERT(SIZEOF(.vectors) == 64, "NS vectors")
    ASSERT(SIZEOF(.fixture_case) == 4, "one case word")
    ASSERT(SIZEOF(.text) < 0xff00, "NS text extent")
    ASSERT(__bss_end <= __fiber_c55s_ns_msp_stack_start__, "BSS overlaps reserved MSP")
    ASSERT(SIZEOF(.data) == 0, "no initialized RAM image")
    /DISCARD/ : { *(.comment*) *(.ARM.exidx*) *(.ARM.extab*) *(.note*) }
}

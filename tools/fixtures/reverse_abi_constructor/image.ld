/* Link-only image: KEEP the documented caller-storage expectation, not start
 * code, reverse data, vectors, or whole archive members. */
ENTRY(Reset_Handler)
SECTIONS
{
    . = 0x08000000;
    .text : { *(.text*) *(.rodata*) }
    .fiber_port_context_cohort_expectation : ALIGN(4)
    { KEEP(*(.fiber_port_context_cohort_expectation)) }
    . = 0x24000000;
    .data : { *(.data*) }
    .bss (NOLOAD) : { *(.bss*) *(COMMON) }
    /DISCARD/ : { *(.comment*) *(.note*) }
}

/* Same real engine/consumer inputs; only RAM capacity makes this link invalid. */
ENTRY(Reset_Handler)
MEMORY
{
    FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 1M
    RAM (rw) : ORIGIN = 0x20000000, LENGTH = 256
}
PHDRS { flash PT_LOAD FLAGS(5); ram PT_LOAD FLAGS(6); }
SECTIONS
{
    .isr_vector : { KEEP(*(.isr_vector)) } >FLASH :flash
    .text : { *(.text*) *(.rodata*) } >FLASH :flash
    .fiber_port_context_cohort_expectation :
    { KEEP(*(.fiber_port_context_cohort_expectation)) } >FLASH :flash
    .ARM.extab : { *(.ARM.extab*) } >FLASH :flash
    .ARM.exidx : { *(.ARM.exidx*) } >FLASH :flash
    .data : { *(.data*) } >RAM :ram
    .bss (NOLOAD) : { *(.bss*) *(COMMON) } >RAM :ram
    /DISCARD/ : { *(.comment*) *(.note*) }
}

ENTRY(Reset_Handler)
PHDRS { flash PT_LOAD FLAGS(5); ram PT_LOAD FLAGS(6); }
SECTIONS
{
    .isr_vector 0x08000000 : { KEEP(*(.isr_vector)) } :flash
    .thread_functions : { *(.text.fiber_runtime_thread_functions) } :flash
    .privileged_text : { *(.text*) *(.rodata*) } :flash
    .fixture_legacy_public : { KEEP(*(.fixture_legacy_public)) } :flash
    .fiber_port_context_cohort_expectation :
    { KEEP(*(.fiber_port_context_cohort_expectation)) } :flash
    .ARM.extab : { *(.ARM.extab*) } :flash
    .ARM.exidx : { *(.ARM.exidx*) } :flash
    .data 0x20000000 : { *(.data*) } :ram
    .bss (NOLOAD) : { *(.bss*) *(COMMON) } :ram
    /DISCARD/ : { *(.comment*) *(.note*) }
}

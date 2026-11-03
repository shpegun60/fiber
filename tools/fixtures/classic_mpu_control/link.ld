ENTRY(control_cohort_entry)
SECTIONS
{
    . = 0x08000000;
    .text : { *(.text*) *(.fiber_port_privileged_functions*) *(.fiber_port_unprivileged_functions*) }
    .rodata : { *(.rodata*) }
    .data : { *(.data*) }
    .bss (NOLOAD) : { *(.bss*) *(COMMON) }
    /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment) *(.note*) }
}

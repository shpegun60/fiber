ENTRY(Reset_Handler)
SECTIONS
{
    .vectors 0x00000000 : { KEEP(*(.vectors)) }
    .text 0x00000800 : { *(.text*) *(.rodata*) KEEP(*(.fiber_port_context_cohort_expectation)) }
    .portable_policy : { KEEP(*(.portable_policy)) }
    .data 0x20000000 : { *(.data*) }
    .bss 0x20000000 (NOLOAD) : { __bss_start = .; *(.bss*) *(COMMON) __bss_end = .; }
    /DISCARD/ : { *(.comment*) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
ASSERT(SIZEOF(.vectors) == 2048, "Full Secure vector span")
ASSERT(ADDR(.portable_policy) + SIZEOF(.portable_policy) < 0x00020000, "Code outside fixture Secure flash")
ASSERT(SIZEOF(.portable_policy) == 28, "Exact generated default policy")
ASSERT(SIZEOF(.data) == 0, "No initialized RAM copy support")
ASSERT(__bss_end < 0x20002000, "Portable storage overlaps integration MSP reserve")

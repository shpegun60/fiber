ENTRY(Reset_Handler)
SECTIONS
{
    .vectors 0x10000000 : { KEEP(*(.vectors)) }
    .text 0x10000800 : { *(.text*) *(.rodata*) KEEP(*(.fiber_port_context_cohort_expectation)) }
    .data 0x30000000 : { *(.data*) }
    .bss 0x30000000 (NOLOAD) : { __bss_start = .; *(.bss*) *(COMMON) __bss_end = .; }
    .stack_a 0x30004000 (NOLOAD) : { KEEP(*(.fixture_stack_a)) }
    .stack_b 0x30006000 (NOLOAD) : { KEEP(*(.fixture_stack_b)) }
    /DISCARD/ : { *(.comment*) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
ASSERT(SIZEOF(.vectors)==2048,"Full Secure vector span")
ASSERT(ADDR(.text)+SIZEOF(.text)<0x10020000,"Code outside fixture Secure flash")
ASSERT(SIZEOF(.data)==0,"No initialized RAM copy support")
ASSERT(__bss_end<0x30002000,"Globals overlap integration MSP reserve")
ASSERT(SIZEOF(.stack_a)==8192 && SIZEOF(.stack_b)==8192,"Exact task stack geometry")

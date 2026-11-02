ENTRY(Reset_Handler)
MEMORY { FLASH (rx) : ORIGIN = 0x10000, LENGTH = 64K
         RAM (rw) : ORIGIN = 0x20010000, LENGTH = 64K }
SECTIONS {
 .vectors : { __fiber_c55s_ns_vector_start__ = .;
   KEEP(*(.vectors)) __fiber_c55s_ns_vector_end__ = .; } > FLASH
 .text : { __fiber_c55s_ns_start_code_start__ = .;
   *(.text*) *(.rodata*) KEEP(*(.proof_roots))
   . = ALIGN(2); __fiber_c55s_ns_start_code_end__ = .; } > FLASH
 .fiber_port_context_cohort_expectation : {
   KEEP(*(.fiber_port_context_cohort_expectation))
 } > FLASH
 .data : { *(.data*) } > RAM AT> FLASH
 .bss (NOLOAD) : { *(.bss*) *(COMMON) } > RAM
 __fiber_c55s_ns_msp_stack_start__ = 0x20018000;
 __fiber_c55s_ns_msp_stack_end__ = 0x20020000;
 /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment*) *(.note*) }
}

ENTRY(NS_Reset_Handler)
MEMORY { FLASH (rx) : ORIGIN = 0x00010000, LENGTH = 128K
         RAM (rwx) : ORIGIN = 0x20004000, LENGTH = 16K }
SECTIONS {
 .vectors : { KEEP(*(.vectors)) } > FLASH
 .text : { *(.text*) *(.rodata*) KEEP(*(.proof_roots)) } > FLASH
 .fiber_port_context_cohort_expectation : {
   KEEP(*(.fiber_port_context_cohort_expectation))
 } > FLASH
 .data : { __data_start = .; *(.data*) __data_end = .; } > RAM AT> FLASH
 __data_load = LOADADDR(.data);
 .bss (NOLOAD) : { __bss_start = .; *(.bss*) *(COMMON) __bss_end = .; } > RAM
 ASSERT(__bss_end < 0x20007400, "fixture leaves at least 3K MSP")
 /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment) }
}

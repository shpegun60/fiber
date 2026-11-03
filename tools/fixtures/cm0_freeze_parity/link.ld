ENTRY(Reset_Handler)
MEMORY { FLASH (rx) : ORIGIN = 0, LENGTH = 256K
         RAM (rw) : ORIGIN = 0x20000000, LENGTH = 16K }
__StackTop = ORIGIN(RAM) + LENGTH(RAM);
__StackLimit = __StackTop - 2048;
__freeze_ram_begin = ORIGIN(RAM);
__freeze_ram_end = ORIGIN(RAM) + LENGTH(RAM);
SECTIONS {
    .isr_vector : { KEEP(*(.isr_vector)) } > FLASH
    .text : { __freeze_text_begin = .; *(.text*) __freeze_text_end = .; } > FLASH
    .rodata : { *(.rodata*) } > FLASH
    .freeze_roots : { KEEP(*(.freeze_roots)) } > FLASH
    .reference_contract : { KEEP(*(.reference_contract)) } > FLASH
    .fiber_port_context_cohort_expectation : {
        KEEP(*(.fiber_port_context_cohort_expectation))
        KEEP(*(.fiber_port_storage_cohort_expectation))
    } > FLASH
    .ARM.extab : { *(.ARM.extab*) } > FLASH
    .ARM.exidx : { *(.ARM.exidx*) } > FLASH
    .data : { *(.data*) } > RAM AT > FLASH
    .bss (NOLOAD) : { *(.bss*) *(COMMON) } > RAM
    ASSERT(. <= __StackLimit, "freeze RAM overlaps reserved MSP")
    /DISCARD/ : { *(.comment) }
}

ENTRY(Reset_Handler)
MEMORY {
    FLASH (rx) : ORIGIN = 0, LENGTH = 512K
    RAM (rw) : ORIGIN = 0x20000000, LENGTH = 64K
}
__pilot_ram_begin = ORIGIN(RAM);
__pilot_ram_end = ORIGIN(RAM) + LENGTH(RAM);
__StackTop = __pilot_ram_end;
__StackLimit = __StackTop - 8192;
SECTIONS {
    .isr_vector : ALIGN(1024) { KEEP(*(.isr_vector)) } > FLASH
    .text : ALIGN(4) {
        __pilot_text_begin = .;
        KEEP(*(.text.pilot_origin_padding))
        *(.text .text.*)
        __pilot_text_end = .;
    } > FLASH
    .rodata : ALIGN(4) { *(.rodata .rodata.*) } > FLASH
    .pilot_roots (READONLY) : ALIGN(4) { KEEP(*(.pilot_roots)) } > FLASH
    .fiber_port_context_cohort_expectation (READONLY) : ALIGN(4) {
        KEEP(*(.fiber_port_context_cohort_expectation))
        KEEP(*(.fiber_port_context_cohort_expectation.*))
    } > FLASH
    .ARM.extab : ALIGN(4) { *(.ARM.extab*) } > FLASH
    .ARM.exidx : ALIGN(4) { *(.ARM.exidx*) } > FLASH
    .data : ALIGN(8) {
        __data_start__ = .;
        *(.data .data.*)
        . = ALIGN(4);
        __data_end__ = .;
    } > RAM AT> FLASH
    __data_load__ = LOADADDR(.data);
    .bss (NOLOAD) : ALIGN(8) {
        __bss_start__ = .;
        *(.bss .bss.* COMMON)
        . = ALIGN(8);
        __bss_end__ = .;
    } > RAM
    .msp __StackLimit (NOLOAD) : { . = . + 8192; } > RAM
    /DISCARD/ : { *(.comment) *(.note*) }
}
ASSERT(SIZEOF(.isr_vector) == 1024, "pilot vector span")
ASSERT(SIZEOF(.pilot_roots) == 20, "five typed Context roots")
ASSERT(SIZEOF(.fiber_port_context_cohort_expectation) == 8, "private/storage expectations")
ASSERT(__bss_end__ <= __StackLimit, "pilot objects overlap MSP")
ASSERT((__StackTop & 7) == 0, "pilot MSP alignment")

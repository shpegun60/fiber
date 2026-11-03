ENTRY(Reset_Handler)
/* Bounded subsets of AN500's code/RAM mappings, not an STM32 memory map. */
MEMORY
{
    FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 512K
    RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 64K
}
__fixture_ram_start = ORIGIN(RAM);
__fixture_ram_end = ORIGIN(RAM) + LENGTH(RAM);
__StackTop = __fixture_ram_end;
__StackLimit = __StackTop - 8192;
SECTIONS
{
    .isr_vector ORIGIN(FLASH) : ALIGN(1024)
    {
        KEEP(*(.isr_vector))
    } > FLASH
    .text : ALIGN(4)
    {
        __fixture_text_begin = .;
        *(.text .text.*)
        __fixture_text_end = .;
    } > FLASH
    .rodata : ALIGN(4) { *(.rodata .rodata.*) } > FLASH
    .fiber_port_context_cohort_expectation (READONLY) : ALIGN(4)
    {
        KEEP(*(.fiber_port_context_cohort_expectation))
        KEEP(*(.fiber_port_context_cohort_expectation.*))
    } > FLASH
    .ARM.extab : ALIGN(4) { *(.ARM.extab*) } > FLASH
    .ARM.exidx : ALIGN(4) { *(.ARM.exidx*) } > FLASH
    .data : ALIGN(8)
    {
        __data_start__ = .;
        *(.data .data.*)
        . = ALIGN(4);
        __data_end__ = .;
    } > RAM AT> FLASH
    __data_load__ = LOADADDR(.data);
    .bss (NOLOAD) : ALIGN(8)
    {
        __bss_start__ = .;
        *(.bss .bss.* COMMON)
        . = ALIGN(8);
        __bss_end__ = .;
    } > RAM
    .msp __StackLimit (NOLOAD) : { . = . + 8192; } > RAM
    /DISCARD/ : { *(.comment) *(.note*) }
}
ASSERT(SIZEOF(.isr_vector) == 1024, "CM7F fixture vector inventory")
ASSERT(__bss_end__ <= __StackLimit, "CM7F fixture overlaps reserved MSP")
ASSERT(ADDR(.msp) + SIZEOF(.msp) == __StackTop, "CM7F fixture MSP reservation")
ASSERT((__StackTop & 7) == 0, "CM7F fixture MSP alignment")

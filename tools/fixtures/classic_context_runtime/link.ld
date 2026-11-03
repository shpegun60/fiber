ENTRY(Reset_Handler)
MEMORY
{
    FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 256K
    RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 16K
}

__fixture_ram_start = ORIGIN(RAM);
__fixture_ram_end = ORIGIN(RAM) + LENGTH(RAM);
__StackTop = __fixture_ram_end;
__StackLimit = __StackTop - 4096;

SECTIONS
{
    .isr_vector ORIGIN(FLASH) : ALIGN(256)
    {
        KEEP(*(.isr_vector))
    } > FLASH
    .text : ALIGN(4)
    {
        __fixture_text_begin = .;
        *(.text .text.*)
        __fixture_text_end = .;
    } > FLASH
    .rodata : ALIGN(4)
    {
        *(.rodata .rodata.*)
    } > FLASH
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
    .msp __StackLimit (NOLOAD) :
    {
        . = . + 4096;
    } > RAM
    /DISCARD/ : { *(.comment) *(.note*) }
}
ASSERT(SIZEOF(.isr_vector) == 192, "CM0 fixture requires all 48 vector entries")
ASSERT(__bss_end__ <= __StackLimit, "CM0 fixture objects overlap reserved MSP")
ASSERT(ADDR(.msp) + SIZEOF(.msp) == __StackTop, "CM0 fixture MSP reservation mismatch")
ASSERT((__StackTop & 7) == 0, "CM0 fixture MSP must be eight-byte aligned")

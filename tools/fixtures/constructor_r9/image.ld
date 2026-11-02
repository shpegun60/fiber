ENTRY(r9_call_init)
MEMORY {
    FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 256K
    RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 32K
}
SECTIONS {
    .text : {
        *(.text*) *(.rodata*)
    } > FLASH
    .data : { *(.data*) } > RAM
    .bss (NOLOAD) : { *(.bss*) *(COMMON) } > RAM
    /DISCARD/ : { *(.init_array*) *(.fini_array*) *(.ARM.exidx*) *(.ARM.extab*) }
}

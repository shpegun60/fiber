ENTRY(Reset_Handler)
MEMORY { FLASH (rx) : ORIGIN = 0x10000000, LENGTH = 64K
         RAM (rwx) : ORIGIN = 0x30000000, LENGTH = 16K }
SECTIONS {
 .vectors : { KEEP(*(.vectors)) } > FLASH
 .text : { *(.text*) *(.rodata*) } > FLASH
 .bss (NOLOAD) : { __bss_start = .; *(.bss*) *(COMMON) __bss_end = .; } > RAM
 /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment) }
}

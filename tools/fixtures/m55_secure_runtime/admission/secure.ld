ENTRY(Secure_Reset_Handler)
MEMORY { FLASH (rx) : ORIGIN = 0x10000000, LENGTH = 64K
         RAM (rw) : ORIGIN = 0x30004000, LENGTH = 16K }
SECTIONS {
 .text : { *(.text*) *(.rodata*) KEEP(*(.proof_roots)) } > FLASH
 .gnu.sgstubs 0x10008000 : ALIGN(32) { KEEP(*(.gnu.sgstubs*)) } > FLASH
 .data : { *(.data*) } > RAM AT> FLASH
 .bss (NOLOAD) : { *(.bss*) *(COMMON) } > RAM
 .fiber_secure_context_pool (NOLOAD) : ALIGN(8) { KEEP(*(.fiber_secure_context_pool)) } > RAM
 /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment*) *(.note*) }
}

ENTRY(reference_reset_handler)
MEMORY { FLASH (rx) : ORIGIN = 0, LENGTH = 256K
         RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 64K }
SECTIONS {
 .isr_vector : { KEEP(*(.isr_vector)) } > FLASH
 .reference_roots : { KEEP(*(.reference_roots)) } > FLASH
 .reference_contract : { KEEP(*(.reference_contract)) } > FLASH
 .privileged_functions : {
   __privileged_functions_start__ = .;
   *(privileged_functions)
   __privileged_functions_end__ = .;
 } > FLASH
 .text : { *(.text*) *(.rodata*) } > FLASH
 .syscalls : {
   __syscalls_flash_start__ = .;
   *(freertos_system_calls)
   __syscalls_flash_end__ = .;
 } > FLASH
 .data : { __privileged_data_start__ = .; *(privileged_data) *(.data*)
           __privileged_data_end__ = .; } > RAM AT> FLASH
 .bss (NOLOAD) : { *(.bss*) *(COMMON) } > RAM
 /DISCARD/ : { *(.comment) *(.note*) }
 __FLASH_segment_start__ = ORIGIN(FLASH);
 __FLASH_segment_end__ = ORIGIN(FLASH) + LENGTH(FLASH);
 __SRAM_segment_start__ = ORIGIN(RAM);
 __SRAM_segment_end__ = ORIGIN(RAM) + LENGTH(RAM);
 __reference_msp_top = ORIGIN(RAM) + LENGTH(RAM);
 ASSERT(. < __reference_msp_top - 0x1000, "Reference boundary data overlaps MSP")
}

ENTRY(vStartFirstTask)
__privileged_functions_start__ = 0x08000000;
__privileged_functions_end__ = 0x08010000;
__unprivileged_flash_start__ = 0x08010000;
__unprivileged_flash_end__ = 0x08020000;
__syscalls_flash_start__ = 0x08020000;
__syscalls_flash_end__ = 0x08021000;
__privileged_sram_start__ = 0x30000000;
__privileged_sram_end__ = 0x30010000;
__sram_start__ = 0x24000000;
__sram_end__ = 0x24010000;
SECTIONS
{
    .text 0x08000000 :
    {
        KEEP(*(.proof_roots)) KEEP(*(.proof_geometry))
        *(privileged_functions) *(.text*) *(.rodata*)
    }
    .ARM.extab : { *(.ARM.extab*) }
    .ARM.exidx : { *(.ARM.exidx*) }
    .data 0x30000000 : { *(privileged_data) *(.data*) *(.bss*) *(COMMON) }
    /DISCARD/ : { *(.comment*) *(.note*) }
}

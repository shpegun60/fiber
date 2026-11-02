ENTRY(fiber_secure_gateway_c3fs_v1_abi_version)
MEMORY {
    FLASH(rx) : ORIGIN = 0x10000000, LENGTH = 128K
    NSC(rx) : ORIGIN = 0x10020000, LENGTH = 1K
    RAM(rw) : ORIGIN = 0x30000000, LENGTH = 16K
}
SECTIONS {
    .text : { *(.text*) } > FLASH
    .rodata : { *(.rodata*) } > FLASH
    .gnu.sgstubs 0x10020000 : { *(.gnu.sgstubs*) } > NSC
    .data : { *(.data*) } > RAM
    .bss (NOLOAD) : { *(.bss*) *(COMMON) } > RAM
    /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment*) *(.note*) }
}
ASSERT(SIZEOF(.gnu.sgstubs) == 64, "eight actual C3FS SG entries required")
ASSERT(SIZEOF(.bss) == 0, "staged companion must not allocate a pool or marker")

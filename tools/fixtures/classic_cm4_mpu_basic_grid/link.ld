ENTRY(Reset_Handler)
__fiber_mpu_privileged_code_start__ = 0x00000000;
__fiber_mpu_privileged_code_end__ = 0x00010000;
__fiber_mpu_unprivileged_code_start__ = 0x00010000;
__fiber_mpu_unprivileged_code_end__ = 0x00020000;
__fiber_mpu_current_context_slot_start__ = 0x20000000;
__fiber_mpu_current_context_slot_end__ = 0x20000020;
__fiber_mpu_privileged_data_start__ = 0x20008000;
__fiber_mpu_privileged_data_end__ = 0x20010000;
__fiber_mpu_unprivileged_ram_start__ = 0x20002000;
__fiber_mpu_unprivileged_ram_end__ = 0x20006000;
__StackTop = 0x20010000;
__StackLimit = 0x2000e000;
SECTIONS
{
    .boot_vectors 0x00000000 : { KEEP(*(.boot_vectors)) }
    .isr_vector 0x00000400 : { KEEP(*(.isr_vector)) }
    .user_code 0x00010000 : {
        __user_begin = .;
        KEEP(*(.fixture_user_functions))
        KEEP(*(.fixture_user_rodata))
        KEEP(*(.fiber_port_unprivileged_functions))
        KEEP(*(.text.fiber_runtime_thread_functions))
        __user_end = .;
    }
    .privileged_code 0x00000800 : {
        KEEP(*(.fiber_port_privileged_functions))
        KEEP(*(.fixture_api_roots))
        *(.text .text.*)
        *(.rodata .rodata.*)
    }
    .fiber_port_context_cohort_expectation (READONLY) : ALIGN(4) {
        KEEP(*(.fiber_port_context_cohort_expectation))
    }
    .ARM.extab : { *(.ARM.extab*) }
    .ARM.exidx : { *(.ARM.exidx*) }
    __code_end = .;
    .current_slot 0x20000000 (NOLOAD) : {
        __slot_start__ = .;
        KEEP(*(.bss.fiber_runtime_current_context_slot))
        . = __slot_start__ + 32;
        __slot_end__ = .;
    }
    .data 0x20008000 : AT(__code_end) {
        __data_start__ = .;
        *(.data .data.*)
        . = ALIGN(4);
        __data_end__ = .;
    }
    __data_load__ = LOADADDR(.data);
    .bss (NOLOAD) : ALIGN(8) {
        __bss_start__ = .;
        *(.fiber_port_privileged_data)
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(8);
        __bss_end__ = .;
    }
    .stack0 0x20002000 (NOLOAD) : { __stack0_start = .; . += 4096; __stack0_end = .; }
    .stack1 0x20004000 (NOLOAD) : { __stack1_start = .; . += 4096; __stack1_end = .; }
    .msp __StackLimit (NOLOAD) : { . += 8192; }
    /DISCARD/ : { *(.comment) *(.note*) }
}
ASSERT(ADDR(.boot_vectors) == 0 && SIZEOF(.boot_vectors) == 8, "pilot reset words")
ASSERT(fixture_boot_vectors == ADDR(.boot_vectors), "pilot reset vector symbol")
ASSERT(ADDR(.isr_vector) == 0x400 && SIZEOF(.isr_vector) == 1024, "pilot active vectors")
ASSERT(fixture_vectors == ADDR(.isr_vector), "pilot active vector symbol")
ASSERT(ADDR(.privileged_code) == 0x800, "pilot privileged code placement")
ASSERT(__code_end <= 0x10000, "pilot privileged code overflow")
ASSERT(__user_end <= 0x20000, "pilot user code overflow")
ASSERT(__bss_end__ <= __StackLimit, "pilot privileged data/MSP overlap")
ASSERT(SIZEOF(.current_slot) == 32, "pilot aperture")

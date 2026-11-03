.syntax unified
.cpu cortex-m4
.thumb
.section .boot_vectors,"a",%progbits
.global fixture_boot_vectors
.type fixture_boot_vectors,%object
fixture_boot_vectors:
    .word __StackTop
    .word Reset_Handler
.size fixture_boot_vectors,.-fixture_boot_vectors
.section .isr_vector,"a",%progbits
.balign 1024
.global fixture_vectors
.type fixture_vectors,%object
fixture_vectors:
    .word __StackTop
    .word Reset_Handler
    .word fixture_unexpected
    .word fixture_unexpected
    .word MemManage_Handler
    .rept 6
    .word fixture_unexpected
    .endr
#if PILOT_MODEL_PROBE
    .word fixture_unexpected
#else
    .word SVC_Handler
#endif
    .word fixture_unexpected
    .word 0
#if PILOT_MODEL_PROBE
    .word fixture_unexpected
#else
    .word PendSV_Handler
#endif
    .word fixture_unexpected
    .rept 240
    .word fixture_unexpected
    .endr
.size fixture_vectors,.-fixture_vectors
.section .text.Reset_Handler,"ax",%progbits
.global Reset_Handler
.type Reset_Handler,%function
.thumb_func
Reset_Handler:
    ldr r0,=__data_load__
    ldr r1,=__data_start__
    ldr r2,=__data_end__
1:  cmp r1,r2
    bhs 2f
    ldr r3,[r0],#4
    str r3,[r1],#4
    b 1b
2:  ldr r1,=__bss_start__
    ldr r2,=__bss_end__
    movs r3,#0
3:  cmp r1,r2
    bhs 4f
    str r3,[r1],#4
    b 3b
4:  ldr r1,=__slot_start__
    ldr r2,=__slot_end__
5:  cmp r1,r2
    bhs 6f
    str r3,[r1],#4
    b 5b
6:  ldr r0,=fixture_vectors
    ldr r1,=0xe000ed08
    str r0,[r1]
    dsb
    isb
    bl fixture_main
    udf #1
    b .
.ltorg
.size Reset_Handler,.-Reset_Handler
.section .text.MemManage_Handler,"ax",%progbits
.global MemManage_Handler
.type MemManage_Handler,%function
.thumb_func
MemManage_Handler:
    tst lr,#4
    ite eq
    mrseq r0,msp
    mrsne r0,psp
    mov r1,lr
    mrs r2,ipsr
    b fixture_fault_record
.size MemManage_Handler,.-MemManage_Handler
.section .note.GNU-stack,"",%progbits

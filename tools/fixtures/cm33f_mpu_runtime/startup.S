.syntax unified
.thumb
#if EXEC_WEAK_STARTUP
.weak SVC_Handler
.thumb_set SVC_Handler,fixture_fault_handler
.weak PendSV_Handler
.thumb_set PendSV_Handler,fixture_fault_handler
#endif
.section .vectors,"a",%progbits
.balign 2048
.global fixture_vectors
fixture_vectors:
    .word 0x20006000
    .word NS_Reset_Handler
    .rept 9
    .word fixture_fault_handler
    .endr
    .word SVC_Handler
    .rept 2
    .word fixture_fault_handler
    .endr
    .word PendSV_Handler
    .rept 497
    .word fixture_fault_handler
    .endr
.section .text.startup,"ax",%progbits
.global NS_Reset_Handler
.type NS_Reset_Handler,%function
.thumb_func
NS_Reset_Handler:
    ldr r0,=__bss_start
    ldr r1,=__bss_end
    movs r2,#0
1:  cmp r0,r1
    bhs 2f
    str r2,[r0],#4
    b 1b
2:  ldr r0,=__slot_zero_start
    ldr r1,=__slot_zero_end
3:  cmp r0,r1
    bhs 4f
    str r2,[r0],#4
    b 3b
4:  bl fixture_ns_main
    udf #1
.global fixture_fault_handler
.type fixture_fault_handler,%function
.thumb_func
fixture_fault_handler:
    mov r1,lr
    tst lr,#4
    ite eq
    mrseq r0,msp
    mrsne r0,psp
    b fixture_fault_report

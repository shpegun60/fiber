.syntax unified
.arch armv8.1-m.main
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
    .word 0x20004000
    .word Reset_Handler
    .rept 9
    .word fixture_fault_handler
    .endr
#if defined(EXEC_INIT_ONLY)
    .word fixture_fault_handler
#else
    .word SVC_Handler
#endif
    .rept 2
    .word fixture_fault_handler
    .endr
#if defined(EXEC_INIT_ONLY)
    .word fixture_fault_handler
#else
    .word PendSV_Handler
#endif
    .rept 497
    .word fixture_fault_handler
    .endr
.section .text.startup,"ax",%progbits
.global Reset_Handler
.type Reset_Handler,%function
.thumb_func
Reset_Handler:
    ldr r0,=__bss_start
    ldr r1,=__bss_end
    movs r2,#0
1:  cmp r0,r1
    bhs 2f
    str r2,[r0],#4
    b 1b
2:  bl fixture_main
    udf #1
.size Reset_Handler,.-Reset_Handler
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
.size fixture_fault_handler,.-fixture_fault_handler

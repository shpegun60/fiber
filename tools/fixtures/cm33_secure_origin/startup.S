.syntax unified
.thumb
.section .vectors,"a",%progbits
.balign 128
#ifdef ORIGIN_SECURE
.word 0x30004000
.word Reset_Handler
.rept 14
.word origin_fault_handler
.endr
#else
.word 0x20008000
.word NS_Reset_Handler
.rept 9
.word origin_fault_handler
.endr
.word SVC_Handler
.rept 2
.word origin_fault_handler
.endr
.word PendSV_Handler
.word origin_fault_handler
#endif
.section .text.startup,"ax",%progbits
#ifdef ORIGIN_SECURE
.global Reset_Handler
.type Reset_Handler,%function
.thumb_func
Reset_Handler:
#else
.global NS_Reset_Handler
.type NS_Reset_Handler,%function
.thumb_func
NS_Reset_Handler:
#endif
    ldr r0,=__bss_start
    ldr r1,=__bss_end
    movs r2,#0
1:  cmp r0,r1
    bhs 2f
    str r2,[r0],#4
    b 1b
2:
#ifdef ORIGIN_SECURE
    bl origin_secure_main
#else
    bl origin_ns_main
#endif
    udf #0
.ltorg
.section .text.origin_fault_handler,"ax",%progbits
.global origin_fault_handler
.type origin_fault_handler,%function
.thumb_func
origin_fault_handler:
    tst lr,#8
    beq 3f
    tst lr,#4
    ite eq
    mrseq r0,msp
    mrsne r0,psp
    b 4f
3:  mrs r0,msp
4:  mov r1,lr
    b origin_fault_report

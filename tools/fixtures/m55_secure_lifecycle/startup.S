.syntax unified
.thumb
.section .vectors,"a",%progbits
.balign 128
#ifdef LIFE_SECURE
.word 0x30010000
.word Reset_Handler
.rept 9
.word lifecycle_fault_handler
.endr
.word lifecycle_secure_svc
.rept 4
.word lifecycle_fault_handler
.endr
#else
.word 0x20020000
.word NS_Reset_Handler
.rept 9
.word lifecycle_fault_handler
.endr
.word lifecycle_ns_svc
.word lifecycle_fault_handler
.word lifecycle_fault_handler
.word lifecycle_ns_pendsv
.word lifecycle_ns_systick
#endif
.section .text.startup,"ax",%progbits
#ifdef LIFE_SECURE
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
    ldr r0, =__bss_start
    ldr r1, =__bss_end
    movs r2, #0
1:  cmp r0,r1
    bhs 2f
    str r2,[r0],#4
    b 1b
2:
#ifdef LIFE_SECURE
    bl lifecycle_secure_main
#else
    bl lifecycle_ns_main
#endif
    b .
.section .text.lifecycle_fault_handler,"ax",%progbits
.global lifecycle_fault_handler
.type lifecycle_fault_handler,%function
.thumb_func
lifecycle_fault_handler:
    /* Handler uses MSP even when its saved Thread SPSEL is one. */
    tst lr,#8
    beq 3f
    tst lr,#4
    ite eq
    mrseq r0,msp
    mrsne r0,psp
    b 4f
3:  mrs r0,msp
4:  mov r1,lr
    b lifecycle_fault_report
.size lifecycle_fault_handler,.-lifecycle_fault_handler

.syntax unified
.thumb
.section .vectors,"a",%progbits
.balign 128
#ifdef INIT_SECURE
.word 0x30010000
.word Reset_Handler
.rept 9
.word init_fault_handler
.endr
.word init_secure_svc
.rept 4
.word init_fault_handler
.endr
#else
.word 0x20020000
.word NS_Reset_Handler
.rept 9
.word init_fault_handler
.endr
.word init_ns_svc
.word init_fault_handler
.word init_fault_handler
.word init_ns_pendsv
.word init_ns_systick
#endif
.section .text.startup,"ax",%progbits
#ifdef INIT_SECURE
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
1:  cmp r0, r1
    bhs 2f
    str r2, [r0], #4
    b 1b
2:
#ifdef INIT_SECURE
    bl init_secure_main
#else
    bl init_ns_main
#endif
    b .

.section .text.init_fault_handler,"ax",%progbits
.global init_fault_handler
.type init_fault_handler,%function
.thumb_func
init_fault_handler:
    /* A fault interrupting Handler mode stacks on MSP even when the retained
     * Thread SPSEL bit is one. Consult EXC_RETURN.Mode before SPSEL. */
    tst lr, #8
    beq 3f
    tst lr, #4
    ite eq
    mrseq r0, msp
    mrsne r0, psp
    b 4f
3:  mrs r0, msp
4:
    mov r1, lr
    b init_fault_report
.size init_fault_handler, .-init_fault_handler

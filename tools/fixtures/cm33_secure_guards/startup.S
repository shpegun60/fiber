.syntax unified
.thumb
.section .vectors,"a",%progbits
#ifdef GUARD_SECURE
.word 0x30003000
.word Reset_Handler
.rept 14
.word control_fault
.endr
#else
.word 0x20007000
.word NS_Reset_Handler
.rept 9
.word control_fault
.endr
.word ns_svc
.word control_fault
.word control_fault
.word ns_pendsv
.word control_fault
#endif

.section .text.startup,"ax",%progbits
#ifdef GUARD_SECURE
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
#ifdef GUARD_SECURE
    bl guard_secure_setup
    movs r0, #0
    msr psp, r0
    msr psplim, r0
    msr control_ns, r0
    ldr r0, =0x00010000
    ldr r1, [r0]
    msr msp_ns, r1
    ldr r0, [r0, #4]
    bic r0, r0, #1
    bxns r0
#else
    bl ns_main
    b .
#endif

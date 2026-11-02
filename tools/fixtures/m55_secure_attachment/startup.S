.syntax unified
.thumb
.section .vectors,"a",%progbits
.balign 128
#ifdef ATTACH_SECURE
.word 0x30010000
.word Reset_Handler
.rept 14
.word attachment_fault
.endr
#else
.word 0x20020000
.word NS_Reset_Handler
.rept 9
.word attachment_fault
.endr
.word attachment_svc
.rept 4
.word attachment_fault
.endr
#endif
.section .text.startup,"ax",%progbits
#ifdef ATTACH_SECURE
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
#ifdef ATTACH_SECURE
    bl attachment_secure_main
#else
    bl attachment_ns_main
#endif
    b .

.section .text.attachment_fault,"ax",%progbits
.global attachment_fault
.type attachment_fault,%function
.thumb_func
attachment_fault:
    mov r0, lr
    mrs r1, ipsr
    b attachment_fault_report
.size attachment_fault, .-attachment_fault

#ifndef ATTACH_SECURE
.section .text.fixture_construct,"ax",%progbits
.global fixture_construct
.type fixture_construct,%function
.thumb_func
fixture_construct:
    push {r4, r9, lr}
    ldr r4, [sp, #12]
    sub sp, #4
    str r4, [sp]
    ldr r9, =0x91a2b3c4
    bl fiber_port_context_init
    add sp, #4
    pop {r4, r9, pc}
.size fixture_construct, .-fixture_construct

/* Deliberately terminal test-only injections, never scheduler handlers.
 * IPSR injection uses real SVC entry and resumes the interrupted call chain
 * on Handler MSP without exception return. The case must terminate at panic. */
.section .text.fixture_disturb,"ax",%progbits
.global fixture_disturb
.type fixture_disturb,%function
.thumb_func
fixture_disturb:
    cmp r0, #0
    bne 3f
    svc #77
    bx lr
3:  cmp r0, #1
    bne 4f
    movs r1, #1
    msr primask, r1
    bx lr
4:  cmp r0, #2
    bne 5f
    movs r1, #128
    msr basepri, r1
    bx lr
5:  cmp r0, #3
    bne 6f
    movs r1, #1
    msr faultmask, r1
    bx lr
6:  cmp r0, #4
    bne 7f
    mov r1, sp
    msr psp, r1
    movs r1, #2
    msr control, r1
    isb
    bx lr
7:  ldr r1, =0x20010000
    msr psplim, r1
    bx lr
.size fixture_disturb, .-fixture_disturb

.section .text.attachment_svc,"ax",%progbits
.global attachment_svc
.type attachment_svc,%function
.thumb_func
attachment_svc:
    /* All fixture SVC calls originate on MSP, no FP frame, 8-byte alignment. */
    ldr r0, [sp, #24]
    ldr lr, [sp, #20]
    add sp, #32
    orr r0, r0, #1
    bx r0
.size attachment_svc, .-attachment_svc
#endif

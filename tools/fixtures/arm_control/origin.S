.syntax unified
.thumb
.macro origin_sample offset, special
    mrs r1, \special
    str r1, [r0, #\offset]
.endm

.section .vectors,"a",%progbits
.word 0x30003000
.word Reset_Handler
.rept 14
.word control_fault
.endr

.section .text.Reset_Handler,"ax",%progbits
.global Reset_Handler
.type Reset_Handler,%function
.thumb_func
Reset_Handler:
    bl origin_setup
    ldr r0, =0x30002000
    msr psp, r0
    ldr r0, =0x20007000
    msr msp_ns, r0
    ldr r0, =0x20006000
    msr psp_ns, r0
    movs r0, #2
    msr control_ns, r0
    msr control, r0
    isb
    ldr r0, =Origin_NS_Reset
    bic r0, r0, #1
    bxns r0
.size Reset_Handler, .-Reset_Handler

.section .nsc,"ax",%progbits
.balign 32
.global Origin_Gateway
.type Origin_Gateway,%function
.thumb_func
Origin_Gateway:
    sg
    b.w Origin_Secure_Body
.global Origin_Finish
.type Origin_Finish,%function
.thumb_func
Origin_Finish:
    sg
    b.w origin_evaluate

.section .text.Origin_Secure_Body,"ax",%progbits
.type Origin_Secure_Body,%function
.thumb_func
Origin_Secure_Body:
    ldr r0, =origin_results
    origin_sample 0, psp
    origin_sample 4, psp_ns
    origin_sample 8, control
    origin_sample 12, control_ns
    ldr r4, =0x44000000
    adds r5, r4, #1
    adds r6, r4, #2
    adds r7, r4, #3
    add r8, r4, #4
    add r9, r4, #5
    add r10, r4, #6
    add r11, r4, #7
    ldr r1, =0xe002ed04
    mov r2, #0x10000000
#ifndef ORIGIN_DROP_PENDSV
    str r2, [r1]
#endif
    dsb
    isb
    ldr r0, =origin_results
    add r1, r0, #48
    stmia r1!, {r4-r11}
    origin_sample 40, psp
    origin_sample 44, psp_ns
    origin_sample 88, control
    origin_sample 92, control_ns
    bxns lr
.size Origin_Secure_Body, .-Origin_Secure_Body

.section .ns.vectors,"a",%progbits
.word 0x20007000
.word Origin_NS_Reset
.rept 12
.word Origin_NS_Fault
.endr
.word Origin_NS_PendSV
.word Origin_NS_Fault

.section .ns.text,"ax",%progbits
.type Origin_NS_Reset,%function
.thumb_func
Origin_NS_Reset:
    ldr r3, =Origin_Gateway
    blx r3
    ldr r0, =origin_results
    origin_sample 80, control
    mov r1, sp
    str r1, [r0, #84]
    ldr r3, =Origin_Finish
    blx r3
    b .
.size Origin_NS_Reset, .-Origin_NS_Reset

.type Origin_NS_PendSV,%function
.thumb_func
Origin_NS_PendSV:
    ldr r0, =origin_results
    str lr, [r0, #16]
    origin_sample 20, psp
    origin_sample 24, control
    origin_sample 28, ipsr
    mov r1, sp
    str r1, [r0, #32]
    origin_sample 36, msp
#ifndef ORIGIN_KEEP_SECURE_GPRS
    movs r4, #0x24
    movs r5, #0x25
    movs r6, #0x26
    movs r7, #0x27
    movs r0, #0x28
    mov r8, r0
    mov r9, r0
    mov r10, r0
    mov r11, r0
#endif
    ldr r0, =origin_results
    add r0, r0, #96
    stmia r0!, {r4-r11}
    bx lr
.size Origin_NS_PendSV, .-Origin_NS_PendSV

.type Origin_NS_Fault,%function
.thumb_func
Origin_NS_Fault:
    movs r0, #0x20
    ldr r1, =origin_ns_fault_exit
    bkpt 0xab
    b .
.size Origin_NS_Fault, .-Origin_NS_Fault
.section .ns.rodata,"a",%progbits
.balign 4
origin_ns_fault_exit: .word 0x20026, 91

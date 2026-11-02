.syntax unified
.thumb

.macro sample offset, special
    mrs r1, \special
    str r1, [r0, #\offset]
.endm

.section .vectors,"a",%progbits
.word 0x30003000
.word Reset_Handler
.rept 12
.word control_fault
.endr
.word Secure_PendSV
.word control_fault

.section .text.Reset_Handler,"ax",%progbits
.global Reset_Handler
.type Reset_Handler,%function
.thumb_func
Reset_Handler:
    ldr r0, =__bss_start
    ldr r1, =__bss_end
    movs r2, #0
1:  cmp r0, r1
    bhs 2f
    str r2, [r0], #4
    b 1b
2:  bl bank_setup
    ldr r0, =0x30002000
    msr psp, r0
    ldr r0, =0x20007000
    msr msp_ns, r0
    ldr r0, =0x20006000
    msr psp_ns, r0
    movs r0, #0
    msr control_ns, r0
    movs r0, #2
    msr control, r0
    isb
    ldr r0, =NS_Reset_Handler
    bic r0, r0, #1
    bxns r0
.size Reset_Handler, .-Reset_Handler

.section .nsc,"ax",%progbits
.balign 32
.global Bank_Gateway
.type Bank_Gateway,%function
.thumb_func
Bank_Gateway:
    sg
    b.w Secure_Gateway_Body
.global Bank_Finish
.type Bank_Finish,%function
.thumb_func
Bank_Finish:
    sg
    b.w Secure_Finish_Body

.section .text.Secure_Gateway_Body,"ax",%progbits
.type Secure_Gateway_Body,%function
.thumb_func
Secure_Gateway_Body:
    ldr r0, =bank_results
    sample 16, control
    sample 20, control_ns
    sample 24, ipsr
    mov r1, sp
    str r1, [r0, #28]
    sample 32, msp
    sample 100, psp
    movs r1, #3
    msr control, r1
    isb
    sample 36, control
    mov r1, sp
    str r1, [r0, #40]

    @ Secure PendSV preempts NS SVC while it is executing Secure code.
    @ This must clear S.SPSEL, preserve NS.CONTROL, and then restore
    @ the transitory S.SPSEL=1 when returning to this Secure Handler.
    ldr r1, =0xe000ed04
    mov r2, #0x10000000
    str r2, [r1]
    dsb
    isb
    sample 68, control
    movs r1, #2
    msr control, r1
    isb
    bxns lr
.size Secure_Gateway_Body, .-Secure_Gateway_Body

.section .text.Secure_PendSV,"ax",%progbits
.global Secure_PendSV
.type Secure_PendSV,%function
.thumb_func
Secure_PendSV:
    ldr r0, =bank_results
    sample 44, control
    sample 48, control_ns
    sample 52, ipsr
    mov r1, sp
    str r1, [r0, #56]
    sample 60, msp
    ldr r1, [r0, #64]
    adds r1, #1
    str r1, [r0, #64]
    str lr, [r0, #112]
    bx lr
.size Secure_PendSV, .-Secure_PendSV

.section .text.Secure_Finish_Body,"ax",%progbits
.type Secure_Finish_Body,%function
.thumb_func
Secure_Finish_Body:
    ldr r0, =bank_results
    sample 92, control
    sample 96, control_ns
    b bank_evaluate
.size Secure_Finish_Body, .-Secure_Finish_Body

.section .ns.vectors,"a",%progbits
.word 0x20007000
.word NS_Reset_Handler
.rept 9
.word NS_Fault_Handler
.endr
.word NS_SVC_Handler
.rept 4
.word NS_Fault_Handler
.endr

.section .ns.text,"ax",%progbits
.type NS_Reset_Handler,%function
.thumb_func
NS_Reset_Handler:
    movs r0, #2
    msr control, r0
    isb
    ldr r0, =bank_results
    sample 104, control
    svc #0
    ldr r0, =bank_results
    sample 84, control
    mov r1, sp
    str r1, [r0, #88]
    ldr r3, =Bank_Finish
    blx r3
    b .
.size NS_Reset_Handler, .-NS_Reset_Handler

.type NS_SVC_Handler,%function
.thumb_func
NS_SVC_Handler:
    ldr r0, =bank_results
    sample 0, control
    sample 4, ipsr
    mov r1, sp
    str r1, [r0, #8]
    sample 12, msp
    str lr, [r0, #108]
    push {r4, lr}
    ldr r3, =Bank_Gateway
    blx r3
    pop {r4, lr}
    ldr r0, =bank_results
    sample 72, control
    movs r1, #3
    msr control, r1
    isb
    sample 76, control
    mov r1, sp
    str r1, [r0, #80]
    movs r1, #0
    msr control, r1
    isb
    bx lr
.size NS_SVC_Handler, .-NS_SVC_Handler

.type NS_Fault_Handler,%function
.thumb_func
NS_Fault_Handler:
    movs r0, #0x20
    ldr r1, =ns_fault_exit
    bkpt 0xab
    b .
.size NS_Fault_Handler, .-NS_Fault_Handler
.section .ns.rodata,"a",%progbits
.balign 4
ns_fault_exit: .word 0x20026, 91

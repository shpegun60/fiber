.syntax unified
.thumb

.section .vectors,"a",%progbits
.word __msp_top
.word Reset_Handler
.rept 9
.word Fault_Handler
.endr
.word SVC_Handler
.rept 4
.word Fault_Handler
.endr

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
2:  ldr r0, =__psp_top
    msr psp, r0
    movs r0, #0
    msr control, r0
    isb

    @ MSP Thread -> Handler: Handler leaves SPSEL=1/nPRIV=1, but
    @ EXC_RETURN restores Thread MSP selection (and retains nPRIV).
    svc #0
    ldr r0, =control_results
    mrs r1, control
    str r1, [r0, #40]
    mov r1, sp
    str r1, [r0, #44]
    ldr r0, =control_phase
    movs r1, #2
    str r1, [r0]
    svc #1

    @ PSP Thread -> Handler: exception entry must clear SPSEL. The
    @ Handler leaves CONTROL=0; EXC_RETURN must restore PSP selection.
    ldr r0, =control_phase
    movs r1, #1
    str r1, [r0]
    movs r0, #2
    msr control, r0
    isb
    svc #0
    ldr r0, =control_results + 48
    mrs r1, control
    str r1, [r0, #40]
    mov r1, sp
    str r1, [r0, #44]
    movs r0, #0
    msr control, r0
    isb
    bl control_evaluate
    b .
.size Reset_Handler, .-Reset_Handler

.section .text.SVC_Handler,"ax",%progbits
.global SVC_Handler
.type SVC_Handler,%function
.thumb_func
SVC_Handler:
    ldr r0, =control_phase
    ldr r0, [r0]
    cmp r0, #2
    beq 3f
    movs r1, #48
    mul r0, r1
    ldr r1, =control_results
    add r0, r1
    mrs r1, control
    str r1, [r0, #0]
    mrs r1, ipsr
    str r1, [r0, #4]
    str lr, [r0, #8]
    mov r1, sp
    str r1, [r0, #12]
    mrs r1, msp
    str r1, [r0, #16]
    mrs r1, psp
    str r1, [r0, #20]

    movs r1, #2
    msr control, r1
    isb
    mrs r1, control
    str r1, [r0, #24]
    mov r1, sp
    str r1, [r0, #28]
    movs r1, #3
    msr control, r1
    isb
    mrs r1, control
    str r1, [r0, #32]
    mov r1, sp
    str r1, [r0, #36]

    ldr r1, =control_phase
    ldr r1, [r1]
    cmp r1, #0
    beq 4f
3:  movs r1, #0
    msr control, r1
    isb
4:  bx lr
.size SVC_Handler, .-SVC_Handler

.section .text.Fault_Handler,"ax",%progbits
.global Fault_Handler
.type Fault_Handler,%function
.thumb_func
Fault_Handler:
    b control_fault
.size Fault_Handler, .-Fault_Handler

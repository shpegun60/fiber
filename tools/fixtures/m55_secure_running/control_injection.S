.syntax unified
.thumb
.section .text.running_control_injection,"ax",%progbits
.global running_control_injection
.type running_control_injection,%function
.thumb_func
running_control_injection:
    push {r0-r3,r12,lr}
    sub sp,sp,#8
    mrs r0,apsr
    str r0,[sp]
    ldr r0,running_control_register
    ldr r1,running_control_value
    cmp r0,#0
    bne 1f
    msr control,r1
    b 7f
1:  cmp r0,#1
    bne 2f
    msr primask,r1
    b 7f
2:  cmp r0,#2
    bne 3f
    msr basepri,r1
    b 7f
3:  cmp r0,#3
    bne 4f
    msr faultmask,r1
    b 7f
4:  cmp r0,#4
    bne 5f
    msr psplim,r1
    b 7f
5:  cmp r0,#5
    bne 6f
    msr psp,r1
    b 7f
6:
#ifdef RUNNING_SECURE
    cmp r0,#6
    bne 8f
    msr control_ns,r1
    b 7f
8:  cmp r0,#7
    bne 9f
    msr primask_ns,r1
    b 7f
9:  cmp r0,#8
    bne 10f
    msr basepri_ns,r1
    b 7f
10: cmp r0,#9
    bne 11f
    msr faultmask_ns,r1
    b 7f
11: cmp r0,#10
    bne 12f
    msr psplim_ns,r1
    b 7f
12: cmp r0,#11
    bne 13f
    msr psp_ns,r1
    b 7f
13:
#endif
    udf #0
7:
    dsb
    isb
    ldr r0,[sp]
    msr APSR_nzcvq,r0
    add sp,sp,#8
    pop {r0-r3,r12,lr}
.global running_control_done
running_control_done:
    nop
    ldr.w pc,running_control_return
.balign 4
.global running_control_return
running_control_return:
    .word 0
.global running_control_value
running_control_value:
    .word 0
.global running_control_register
running_control_register:
    .word 0
.size running_control_injection,.-running_control_injection

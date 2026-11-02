.syntax unified
.thumb
.section .text.runtime_control_injection,"ax",%progbits
.global runtime_control_injection
.type runtime_control_injection,%function
.thumb_func
runtime_control_injection:
    push {r0-r12,lr}
    mrs r0,apsr
    push {r0,r1}
    mov r1,sp
    ldr r0,=runtime_control_saved_sp
    str r1,[r0]
    add sp,sp,#64
    ldr r0,runtime_control_register
    ldr r1,runtime_control_value
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
#ifdef RUNTIME_SECURE
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
    ldr r0,=runtime_control_saved_sp
    ldr r0,[r0]
    ldr r1,[r0]
    msr APSR_nzcvq,r1
    add.w r0,r0,#8
    ldmia.w r0,{r0-r12,lr}
.global runtime_control_done
runtime_control_done:
    nop
    ldr.w pc,runtime_control_return
.balign 4
.global runtime_control_return
runtime_control_return:
    .word 0
.global runtime_control_value
runtime_control_value:
    .word 0
.global runtime_control_register
runtime_control_register:
    .word 0
.size runtime_control_injection,.-runtime_control_injection
.section .bss.runtime_control_saved_sp,"aw",%nobits
.balign 4
.global runtime_control_saved_sp
runtime_control_saved_sp:
    .space 4

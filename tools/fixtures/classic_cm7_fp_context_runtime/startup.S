.syntax unified
.cpu cortex-m7
.thumb
.section .isr_vector,"a",%progbits
.balign 1024
.global fixture_vectors
.type fixture_vectors,%object
fixture_vectors:
    .word __StackTop
    .word Reset_Handler
    .rept 5
    .word fixture_fault
    .endr
    .rept 4
    .word 0
    .endr
    .word SVC_Handler
    .word fixture_fault
    .word 0
    .word PendSV_Handler
    .word fixture_fault
    .rept 240
    .word fixture_fault
    .endr
.size fixture_vectors, .-fixture_vectors

.section .text.Reset_Handler,"ax",%progbits
.balign 2
.global Reset_Handler
.type Reset_Handler,%function
.thumb_func
Reset_Handler:
    ldr r0, =__data_load__
    ldr r1, =__data_start__
    ldr r2, =__data_end__
1:
    cmp r1, r2
    bhs 2f
    ldr r3, [r0], #4
    str r3, [r1], #4
    b 1b
2:
    ldr r1, =__bss_start__
    ldr r2, =__bss_end__
    movs r3, #0
3:
    cmp r1, r2
    bhs 4f
    str r3, [r1], #4
    b 3b
4:
    ldr r0, =fixture_vectors
    ldr r1, =0xE000ED08
    str r0, [r1]
    dsb
    isb
    /* The real selected port, not this reset code, grants/configures FP. */
    bl fixture_main
    udf #0
    b .
.ltorg
.size Reset_Handler, .-Reset_Handler

.section .text.Default_Handler,"ax",%progbits
.balign 2
.global Default_Handler
.type Default_Handler,%function
.thumb_func
Default_Handler:
    ldr r0, =fixture_fault
    bx r0
.ltorg
.size Default_Handler, .-Default_Handler
/* Public operations must naturally extract the real mandatory port object. */
.weak SVC_Handler
.thumb_set SVC_Handler, Default_Handler
.weak PendSV_Handler
.thumb_set PendSV_Handler, Default_Handler

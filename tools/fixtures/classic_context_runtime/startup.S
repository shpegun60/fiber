.syntax unified
.cpu cortex-m0
.thumb

.section .isr_vector,"a",%progbits
.balign 256
.global fixture_vectors
.type fixture_vectors,%object
fixture_vectors:
    .word __StackTop
    .word Reset_Handler
    .word fixture_fault
    .word fixture_fault
    .rept 7
    .word 0
    .endr
    .word SVC_Handler
    .word 0
    .word 0
    .word PendSV_Handler
    .word fixture_fault
    .rept 32
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
    ldr r3, [r0]
    str r3, [r1]
    adds r0, #4
    adds r1, #4
    b 1b
2:
    ldr r1, =__bss_start__
    ldr r2, =__bss_end__
    movs r3, #0
3:
    cmp r1, r2
    bhs 4f
    str r3, [r1]
    adds r1, #4
    b 3b
4:
    bl fixture_main
    udf #0
    b .
.ltorg
.size Reset_Handler, .-Reset_Handler

/* These deliberately do not force handler extraction. The genuine public
 * start chain must extract the mandatory port object, whose strong SVC and
 * PendSV definitions must win in the final ELF and in slots 11 and 14. */
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
.weak SVC_Handler
.thumb_set SVC_Handler, Default_Handler
.weak PendSV_Handler
.thumb_set PendSV_Handler, Default_Handler

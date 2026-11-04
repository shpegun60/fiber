.syntax unified
.cpu cortex-m4
.thumb
.section .isr_vector,"a",%progbits
.balign 1024
.global pilot_vectors
.type pilot_vectors,%object
pilot_vectors:
    .word __StackTop
    .word Reset_Handler
    .rept 5
    .word pilot_fault
    .endr
    .rept 4
    .word 0
    .endr
    .word SVC_Handler
    .word pilot_fault
    .word 0
    .word PendSV_Handler
    .word pilot_fault
    .rept 240
    .word pilot_fault
    .endr
.size pilot_vectors, .-pilot_vectors

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
    ldr r0, =pilot_vectors
    ldr r1, =0xE000ED08
    str r0, [r1]
    dsb
    isb
    bl pilot_main
    udf #90
    b .
    .ltorg
.size Reset_Handler, .-Reset_Handler
.section .note.GNU-stack,"",%progbits

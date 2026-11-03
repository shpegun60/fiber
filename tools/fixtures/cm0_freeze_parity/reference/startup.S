.syntax unified
.thumb
.section .isr_vector,"a",%progbits
.balign 256
.global reference_vectors
.type reference_vectors,%object
reference_vectors:
    .word __StackTop
    .word Reset_Handler
    .word reference_fault_forbidden
    .word reference_fault_forbidden
    .rept 7
    .word 0
    .endr
    .word SVC_Handler
    .word 0
    .word 0
    .word PendSV_Handler
    .word SysTick_Handler
    .rept 32
    .word reference_fault_forbidden
    .endr
.size reference_vectors,.-reference_vectors
.section .text.Reset_Handler,"ax",%progbits
.thumb_func
.global Reset_Handler
.type Reset_Handler,%function
Reset_Handler:
    ldr r0, =reference_reset_forbidden
    bx r0
    .ltorg
.size Reset_Handler,.-Reset_Handler
.section .note.GNU-stack,"",%progbits

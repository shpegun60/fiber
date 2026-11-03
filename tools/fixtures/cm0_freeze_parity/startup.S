.syntax unified
.thumb
.section .isr_vector,"a",%progbits
.balign 256
.global freeze_vectors
.type freeze_vectors,%object
freeze_vectors:
    .word __StackTop
    .word Reset_Handler
    .word freeze_fault_forbidden
    .word freeze_fault_forbidden
    .rept 7
    .word 0
    .endr
    .word SVC_Handler
    .word 0
    .word 0
    .word PendSV_Handler
    .word freeze_fault_forbidden
    .rept 32
    .word freeze_fault_forbidden
    .endr
.size freeze_vectors,.-freeze_vectors
.section .text.Reset_Handler,"ax",%progbits
.thumb_func
.global Reset_Handler
.type Reset_Handler,%function
Reset_Handler:
    ldr r0, =freeze_reset_forbidden
    bx r0
    .ltorg
.size Reset_Handler,.-Reset_Handler
.section .note.GNU-stack,"",%progbits

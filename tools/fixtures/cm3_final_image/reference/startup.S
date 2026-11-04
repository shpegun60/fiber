.syntax unified
.thumb
.section .isr_vector,"a",%progbits
.balign 1024
.global reference_vector_table
.type reference_vector_table,%object
reference_vector_table:
    .word __reference_stack_top
    .word reference_reset_handler
    .rept 5
    .word reference_fault_forbidden
    .endr
    .word 0, 0, 0, 0
    .word vPortSVCHandler
    .word reference_fault_forbidden
    .word 0
    .word xPortPendSVHandler
    .word xPortSysTickHandler
    .rept 240
    .word reference_fault_forbidden
    .endr
.size reference_vector_table, .-reference_vector_table

.section .text.reference_reset_handler,"ax",%progbits
.balign 2
.global reference_reset_handler
.type reference_reset_handler,%function
.thumb_func
reference_reset_handler:
    cpsid i
    bl reference_reset_forbidden
    udf #90
    b .
.size reference_reset_handler, .-reference_reset_handler

/* Unowned executable padding for a later independent origin mutant. */
.section .text.reference_origin_padding,"ax",%progbits
.balign 2
    nop
    nop
.section .note.GNU-stack,"",%progbits

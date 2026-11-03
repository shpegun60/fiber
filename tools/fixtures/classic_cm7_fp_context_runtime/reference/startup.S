.syntax unified
.cpu cortex-m7
.fpu fpv5-d16
.thumb

.section .isr_vector,"a",%progbits
.balign 1024
.global reference_vector_table
.type reference_vector_table,%object
reference_vector_table:
    .word __reference_stack_top
    .word reference_reset_handler
    .word reference_fault_forbidden
    .word reference_fault_forbidden
    .word reference_fault_forbidden
    .word reference_fault_forbidden
    .word reference_fault_forbidden
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
    b reference_reset_forbidden
.size reference_reset_handler, .-reference_reset_handler

.section .note.GNU-stack,"",%progbits

.syntax unified
.cpu cortex-m4
.thumb
.section .isr_vector,"a",%progbits
.global reference_vectors
.type reference_vectors,%object
reference_vectors:
 .word __reference_msp_top
 .word reference_reset_handler
 .rept 9
 .word reference_fault_forbidden
 .endr
 .word vPortSVCHandler
 .word reference_fault_forbidden
 .word 0
 .word xPortPendSVHandler
 .word xPortSysTickHandler
 .rept 240
 .word reference_fault_forbidden
 .endr
.size reference_vectors,.-reference_vectors
.section .text.reference_reset_handler,"ax",%progbits
.global reference_reset_handler
.type reference_reset_handler,%function
.thumb_func
reference_reset_handler:
 cpsid i
 b reference_reset_forbidden
.size reference_reset_handler,.-reference_reset_handler
.section .note.GNU-stack,"",%progbits

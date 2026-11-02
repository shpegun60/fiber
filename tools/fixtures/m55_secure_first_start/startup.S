.syntax unified
.thumb
.section .vectors,"a",%progbits
.balign 128
#ifdef FIRST_SECURE
.word 0x30010000
.word Reset_Handler
.rept 14
.word first_fault_handler
.endr
#else
.word 0x20020000
.word NS_Reset_Handler
.rept 9
.word first_fault_handler
.endr
.word SVC_Handler
.rept 4
.word first_fault_handler
.endr
#endif
.section .text.startup,"ax",%progbits
#ifdef FIRST_SECURE
.global Reset_Handler
.type Reset_Handler,%function
.thumb_func
Reset_Handler:
#else
.global NS_Reset_Handler
.type NS_Reset_Handler,%function
.thumb_func
NS_Reset_Handler:
#endif
    ldr r0,=__bss_start
    ldr r1,=__bss_end
    movs r2,#0
1:  cmp r0,r1
    bhs 2f
    str r2,[r0],#4
    b 1b
2:
#ifdef FIRST_SECURE
    bl first_secure_main
#else
    bl first_ns_main
#endif
    b .

.section .text.first_fault_handler,"ax",%progbits
.global first_fault_handler
.type first_fault_handler,%function
.thumb_func
first_fault_handler:
    /* Handler always stacks on MSP, even with banked CONTROL.SPSEL=1. */
    tst lr,#8
    beq 3f
    tst lr,#4
    ite eq
    mrseq r0,msp
    mrsne r0,psp
    b 4f
3:  mrs r0,msp
4:  mov r1,lr
    b first_fault_report
.size first_fault_handler,.-first_fault_handler

#ifndef FIRST_SECURE
.section .text.first_task_entry,"ax",%progbits
.global first_task_entry
.type first_task_entry,%function
.thumb_func
first_task_entry:
    /* Capture every GPR before C, including inherited r9 and task-return LR. */
    stmdb sp!,{r0-r12,lr}
    mov r0,sp
    add r1,sp,#56
    mrs r2,control
    mrs r3,psplim
    b first_entry_report
.size first_task_entry,.-first_task_entry

#ifndef FIRST_REFERENCE
.section .text.first_construct,"ax",%progbits
.global first_construct
.type first_construct,%function
.thumb_func
first_construct:
    push {r4,r9,lr}
    ldr r4,[sp,#12]
    sub sp,#4
    str r4,[sp]
    ldr r9,=0x91a2b3c4
    bl fiber_port_context_init
    add sp,#4
    pop {r4,r9,pc}
.size first_construct,.-first_construct

.section .text.first_foreign_255,"ax",%progbits
.global first_foreign_255
.type first_foreign_255,%function
.thumb_func
first_foreign_255:
    msr msp,r0
    dsb
    isb
    svc #255
    udf #0
.size first_foreign_255,.-first_foreign_255
.section .text.first_foreign_70,"ax",%progbits
.global first_foreign_70
.type first_foreign_70,%function
.thumb_func
first_foreign_70:
    msr msp,r0
    dsb
    isb
    svc #70
    udf #0
.size first_foreign_70,.-first_foreign_70
#endif
#endif

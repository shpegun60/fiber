.syntax unified
.thumb
.section .vectors,"a",%progbits
.balign 128
#ifdef RUNNING_SECURE
.word 0x30010000
.word Reset_Handler
.rept 14
.word running_fault_handler
.endr
#else
.word 0x20020000
.word NS_Reset_Handler
.rept 9
.word running_fault_handler
.endr
.word SVC_Handler
.rept 2
.word running_fault_handler
.endr
.word PendSV_Handler
.word running_fault_handler
#endif
.section .text.startup,"ax",%progbits
#ifdef RUNNING_SECURE
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
#ifdef RUNNING_SECURE
    bl running_secure_main
#else
    bl running_ns_main
#endif
    udf #0
.section .text.running_fault_handler,"ax",%progbits
.global running_fault_handler
.type running_fault_handler,%function
.thumb_func
running_fault_handler:
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

#ifndef RUNNING_SECURE
#ifndef RUNNING_REFERENCE
.section .text.running_construct,"ax",%progbits
.global running_construct
.type running_construct,%function
.thumb_func
running_construct:
    push {r4,r5,r9,lr}
    ldr r4,[sp,#16]
    ldr r5,[sp,#20]
    sub sp,sp,#8
    str r4,[sp]
    mov r9,r5
    bl fiber_port_context_init
    add sp,sp,#8
    pop {r4,r5,r9,pc}
.size running_construct,.-running_construct
#endif
#endif

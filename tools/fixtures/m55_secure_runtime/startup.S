.syntax unified
.thumb
.section .vectors,"a",%progbits
.balign 128
#ifdef RUNTIME_SECURE
.word 0x30010000
.word Reset_Handler
.rept 14
.word runtime_fault_handler
.endr
#else
.word 0x20020000
.word NS_Reset_Handler
.rept 9
.word runtime_fault_handler
.endr
.word SVC_Handler
.rept 2
.word runtime_fault_handler
.endr
.word PendSV_Handler
.word runtime_fault_handler
#endif
.section .text.startup,"ax",%progbits
#ifdef RUNTIME_SECURE
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
#ifdef RUNTIME_SECURE
    bl runtime_secure_main
#else
    bl runtime_ns_main
#endif
    udf #0
.section .text.runtime_fault_handler,"ax",%progbits
.global runtime_fault_handler
.type runtime_fault_handler,%function
.thumb_func
runtime_fault_handler:
    tst lr,#8
    beq 3f
    tst lr,#4
    ite eq
    mrseq r0,msp
    mrsne r0,psp
    b 4f
3:  mrs r0,msp
4:  mov r1,lr
    b runtime_fault_report

#ifndef RUNTIME_SECURE
.weak SVC_Handler
.thumb_set SVC_Handler,runtime_fault_handler
.weak PendSV_Handler
.thumb_set PendSV_Handler,runtime_fault_handler
#ifndef RUNTIME_REFERENCE
.section .text.runtime_construct,"ax",%progbits
.global runtime_construct
.type runtime_construct,%function
.thumb_func
runtime_construct:
    push {r4,r5,r9,lr}
    ldr r4,[sp,#16]
    ldr r5,[sp,#20]
    sub sp,sp,#8
    str r4,[sp]
    mov r9,r5
    bl fiber_init
    add sp,sp,#8
    pop {r4,r5,r9,pc}
.size runtime_construct,.-runtime_construct
#endif
#endif

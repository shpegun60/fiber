.syntax unified
.thumb
.section .vectors,"a",%progbits
.balign 2048
#ifdef EXEC_SECURE
 .word 0x30004000, Reset_Handler
 .rept 510
 .word fixture_secure_fault
 .endr
#else
.global fixture_vectors
.type fixture_vectors,%object
fixture_vectors:
 .word 0x20008000, NS_Reset_Handler
 .rept 9
 .word fixture_fault_handler
 .endr
 .word SVC_Handler, fixture_fault_handler, fixture_fault_handler, PendSV_Handler, fixture_irq
 .rept 496
 .word fixture_fault_handler
 .endr
.size fixture_vectors,.-fixture_vectors
#endif
.section .text.startup,"ax",%progbits
#ifdef EXEC_SECURE
.global Reset_Handler
.type Reset_Handler,%function
.thumb_func
Reset_Handler:
#else
.global NS_Reset_Handler
.type NS_Reset_Handler,%function
.thumb_func
NS_Reset_Handler:
 ldr r0,=__data_load
 ldr r1,=__data_start
 ldr r2,=__data_end
1: cmp r1,r2
 bhs 2f
 ldr r3,[r0],#4
 str r3,[r1],#4
 b 1b
2:
#endif
 ldr r0,=__bss_start
 ldr r1,=__bss_end
 movs r2,#0
3: cmp r0,r1
 bhs 4f
 str r2,[r0],#4
 b 3b
4:
#ifdef EXEC_SECURE
 bl fixture_secure_setup
 ldr r1,=0x10000
 ldr r1,[r1]
 msr msp_ns,r1
 bic r0,r0,#1
 bxns r0
#else
 ldr r9,=0x13579bdf
 bl fixture_ns_main
#endif
 udf #1
#ifndef EXEC_SECURE
.global fixture_fault_handler
.type fixture_fault_handler,%function
.thumb_func
fixture_fault_handler:
 mov r1,lr
 tst lr,#8
 beq 5f
 tst lr,#4
 ite eq
 mrseq r0,msp
 mrsne r0,psp
 b fixture_fault_report
5: mrs r0,msp
 b fixture_fault_report

.global fixture_construct
.type fixture_construct,%function
.thumb_func
fixture_construct:
 ldr r12,[sp]
 push {r4,lr}
 sub sp,sp,#8
 str r12,[sp]
 mov r4,r9
 bl fiber_init
 eor r0,r9,r4
 add sp,sp,#8
 pop {r4,pc}
.size fixture_construct,.-fixture_construct

.global fixture_call_psp
.type fixture_call_psp,%function
.thumb_func
fixture_call_psp:
 msr psp,r1
 movs r1,#2
 msr control,r1
 isb
 bx r0
.size fixture_call_psp,.-fixture_call_psp
#endif

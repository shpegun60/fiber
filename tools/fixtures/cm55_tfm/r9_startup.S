.syntax unified
.thumb
.section .secure_vectors,"a",%progbits
.word 0x30010000, r9_secure_reset
.rept 14
.word r9_secure_fault
.endr
.section .text.r9_secure_reset,"ax",%progbits
.global r9_secure_reset
.type r9_secure_reset,%function
.thumb_func
r9_secure_reset:
    bl r9_secure_main
    b .
.size r9_secure_reset,.-r9_secure_reset
.global r9_secure_fault
.type r9_secure_fault,%function
.thumb_func
r9_secure_fault:
    movs r0,#4
    ldr r1,=r9_secure_fault_text
    bkpt 0xab
    ldr r1,=r9_secure_exit_block
    movs r0,#0x20
    bkpt 0xab
    b .
.size r9_secure_fault,.-r9_secure_fault
.section .rodata.r9_secure,"a",%progbits
r9_secure_fault_text: .asciz "FAIL:C5TF-R9:SECURE-FAULT\n"
.align 2
r9_secure_exit_block: .word 0x20026, 41

.section .vectors,"a",%progbits
.word 0x20020000, r9_ns_reset
.word r9_ns_fault, r9_ns_fault, r9_ns_fault, r9_ns_fault, r9_ns_fault
.word 0,0,0,0
.word SVC_Handler
.word r9_ns_fault,0
.word PendSV_Handler
.word r9_ns_fault
.section .text.r9_ns_reset,"ax",%progbits
.global r9_ns_reset
.type r9_ns_reset,%function
.thumb_func
r9_ns_reset:
    ldr r0,=__data_load
    ldr r1,=__data_begin
    ldr r2,=__data_end
1:  cmp r1,r2
    bhs 2f
    ldrb r3,[r0],#1
    strb r3,[r1],#1
    b 1b
2:  ldr r1,=__bss_begin
    ldr r2,=__bss_end
    movs r3,#0
3:  cmp r1,r2
    bhs 4f
    strb r3,[r1],#1
    b 3b
4:  bl r9_ns_main
    b .
.size r9_ns_reset,.-r9_ns_reset
.global r9_ns_fault
.type r9_ns_fault,%function
.thumb_func
r9_ns_fault:
    mov r0,lr
    b r9_fault_report
.size r9_ns_fault,.-r9_ns_fault

.section .text.r9_call_init,"ax",%progbits
.global r9_call_init
.type r9_call_init,%function
.thumb_func
/* r0-r3 and stacked arg/seed: establish R9 immediately before real public init. */
r9_call_init:
    ldr r12,[sp,#4]
    push {r9,lr}
    mov r9,r12
    ldr r12,[sp,#8]
    sub sp,sp,#8
    str r12,[sp]
    bl fiber_init
    add sp,sp,#8
    mov r0,r9
    pop {r9,pc}
.size r9_call_init,.-r9_call_init

.macro R9_HOOK name,target,low,high
.section .text.\name,"ax",%progbits
.global \name
.type \name,%function
.thumb_func
\name:
#ifdef R9_RESERVED
    push {r4,lr}
#else
    push {r9,lr}
    movw r9,#\low
    movt r9,#\high
#endif
    mov r2,r9
    bl \target
#ifdef R9_RESERVED
    pop {r4,pc}
#else
    pop {r9,pc}
#endif
.size \name,.-\name
.endm
R9_HOOK fiber_addr_plausible_ram,r9_hook_ram,0xcafe,0x1357
R9_HOOK fiber_addr_plausible_code,r9_hook_code,0xbeef,0x2468

.section .text.r9_task_a,"ax",%progbits
.global r9_task_a
.type r9_task_a,%function
.thumb_func
r9_task_a:
    movs r0,#0
    mov r1,r9
    bl r9_task_enter
#ifndef R9_RESERVED
    ldr r9,=0xa19a19a1
#endif
    movs r4,#2
1:  ldr r0,=0xe000ed04
    movs r1,#1
    lsls r1,r1,#28
    str r1,[r0]
    dsb
    isb
    movs r0,#0
    mov r1,r9
    bl r9_task_resumed
    subs r4,r4,#1
    bne 1b
    b r9_runtime_done
.size r9_task_a,.-r9_task_a

.section .text.r9_task_b,"ax",%progbits
.global r9_task_b
.type r9_task_b,%function
.thumb_func
r9_task_b:
    movs r0,#1
    mov r1,r9
    bl r9_task_enter
#ifndef R9_RESERVED
    ldr r9,=0xb29b29b2
#endif
2:  ldr r0,=0xe000ed04
    movs r1,#1
    lsls r1,r1,#28
    str r1,[r0]
    dsb
    isb
    movs r0,#1
    mov r1,r9
    bl r9_task_resumed
    b 2b
.size r9_task_b,.-r9_task_b

.section .text.r9_panic,"ax",%progbits
.global fiber_panic
.type fiber_panic,%function
.thumb_func
fiber_panic:
    mov r1,lr
    b r9_panic_report
.size fiber_panic,.-fiber_panic

.syntax unified
.thumb
.section .vectors,"a",%progbits
.balign 2048
    .word 0x20006000
    .word NS_Reset_Handler
    .rept 9
    .word fixture_fault_handler
    .endr
    .word SVC_Handler
    .rept 2
    .word fixture_fault_handler
    .endr
    .word PendSV_Handler
    .rept 497
    .word fixture_fault_handler
    .endr

.section .text.startup,"ax",%progbits
.global NS_Reset_Handler
.type NS_Reset_Handler,%function
.thumb_func
NS_Reset_Handler:
    ldr r0, =__bss_start
    ldr r1, =__bss_end
    movs r2, #0
1:  cmp r0, r1
    bhs 2f
    str r2, [r0], #4
    b 1b
2:  ldr r0, =__slot_zero_start
    ldr r1, =__slot_zero_end
3:  cmp r0, r1
    bhs 4f
    str r2, [r0], #4
    b 3b
4:  bl fixture_ns_main
    udf #1

.global fixture_fault_handler
.type fixture_fault_handler,%function
.thumb_func
fixture_fault_handler:
    mov r1, lr
    tst lr, #4
    ite eq
    mrseq r0, msp
    mrsne r0, psp
    b fixture_fault_report

.section .fiber_port_unprivileged_functions,"ax",%progbits
.macro seed base, table, fpscr, active
.if \active
    ldr r0, =\table
    vldmia r0, {s0-s31}
    ldr r0, =\fpscr
    vmsr fpscr, r0
.endif
    .irp n,0,1,2,3,4,5,6,7,8,9,10,11,12
    ldr r\n, =(\base + \n)
    .endr
.endm
.macro capture offset, active
    /* Preserve every GP register before any scratch use. */
    add sp, sp, #\offset
    stmia sp, {r0-r12,lr}
    mrs r0, control
    str r0, [sp, #56]
    sub r0, sp, #\offset
    str r0, [sp, #60]
    ldr r0, =fiber_internal_runtime_current_context_slot
    ldr r0, [r0]
    str r0, [sp, #64]
.if \active
    add r0, sp, #80
    vstmia r0, {s0-s31}
    vmrs r0, fpscr
    str r0, [sp, #208]
.endif
    sub sp, sp, #\offset
.endm
.macro task name, base, table, fpscr, active
.global \name
.type \name,%function
.thumb_func
\name:
    sub sp, sp, #1024
#if EXEC_CASE == 1
    svc #71
#elif EXEC_CASE == 2
    svc #72
#elif EXEC_CASE == 8
    ldr r0, =fiber_internal_runtime_current_context_slot
.global \name\()_forbidden_store
\name\()_forbidden_store:
    str r0, [r0]
#endif
    seed \base, \table, \fpscr, \active
    bl fiber_port_yield_from_thread
.global \name\()_resume1
\name\()_resume1:
    capture 0, \active
    seed \base, \table, \fpscr, \active
    bl fiber_port_yield_from_thread
.global \name\()_resume2
\name\()_resume2:
    capture 256, \active
    seed \base, \table, \fpscr, \active
    bl fiber_port_yield_from_thread
.global \name\()_resume3
\name\()_resume3:
    capture 512, \active
    b fiber_port_unprivileged_task_return
.size \name, .-\name
.endm
#if EXEC_FP == 2
task fixture_task_a, 0x11000000, fixture_fp_a, 0x00400000, 1
task fixture_task_b, 0x22000000, fixture_fp_b, 0x00800000, 0
#else
task fixture_task_a, 0x11000000, fixture_fp_a, 0x00400000, EXEC_FP
task fixture_task_b, 0x22000000, fixture_fp_b, 0x00800000, EXEC_FP
#endif

.balign 4
fixture_fp_a:
.set n,0
.rept 32
    .word 0x3f100000 + n * 0x1000
    .set n,n+1
.endr
fixture_fp_b:
.set n,0
.rept 32
    .word 0x40100000 + n * 0x1000
    .set n,n+1
.endr

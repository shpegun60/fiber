.syntax unified
.thumb
.section .vectors,"a",%progbits
.balign 2048
#ifdef EXEC_SECURE
    .word 0x30004000
    .word Reset_Handler
    .rept 510
    .word fixture_secure_fault
    .endr
#else
.global fixture_vectors
.type fixture_vectors,%object
fixture_vectors:
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
.size fixture_vectors, .-fixture_vectors
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
#endif
    ldr r0, =__bss_start
    ldr r1, =__bss_end
    movs r2, #0
1:  cmp r0, r1
    bhs 2f
    str r2, [r0], #4
    b 1b
2:
#ifdef EXEC_SECURE
    bl fixture_secure_setup
    ldr r1, =0x00010000
    ldr r1, [r1]
    msr msp_ns, r1
    bic r0, r0, #1
    bxns r0
#else
    ldr r0, =__slot_zero_start
    ldr r1, =__slot_zero_end
3:  cmp r0, r1
    bhs 4f
    str r2, [r0], #4
    b 3b
4:  bl fixture_ns_main
#endif
    b .

#ifndef EXEC_SECURE
.global fixture_fault_handler
.type fixture_fault_handler,%function
.thumb_func
fixture_fault_handler:
    mov r1, lr
    tst lr, #8
    beq 5f
    tst lr, #4
    ite eq
    mrseq r0, msp
    mrsne r0, psp
    b fixture_fault_report
5:  mrs r0, msp
    b fixture_fault_report

.global fixture_raw_svc70
.type fixture_raw_svc70,%function
.thumb_func
fixture_raw_svc70:
    ldr r0, =0x20006000
    msr msp, r0
    isb
    svc #70
    udf #1

.section .fiber_port_unprivileged_functions,"ax",%progbits
.global fixture_task
.type fixture_task,%function
.thumb_func
fixture_task:
    /* Save every initial general register before using any scratch register.
     * The 56-byte capture and 32-byte terminal basic frame stay 8-byte aligned. */
    stmdb sp!, {r0-r12, lr}
    mov r0, sp
    mrs r1, control
    add.w r2, sp, #56
    ldr r3, =0x46535441
    ldr r4, =fiber_internal_runtime_current_context_slot
    ldr r12, [r4]
#if EXEC_CASE == 3
    ldr r4, =fixture_context
.global fixture_forbidden_load
fixture_forbidden_load:
    ldr r4, [r4]
#elif EXEC_CASE == 5
.global fixture_forbidden_store
fixture_forbidden_store:
    str r4, [r4]
#endif
    svc #255
.global fixture_terminal_continuation
fixture_terminal_continuation:
    udf #2
.size fixture_task, .-fixture_task
#endif

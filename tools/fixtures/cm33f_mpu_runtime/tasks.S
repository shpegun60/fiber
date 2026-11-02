.syntax unified
.thumb
.section .fiber_port_unprivileged_functions,"ax",%progbits
.macro seed base,table,fpscr,active
.if \active
    ldr r0,=\table
    vldmia r0,{s0-s31}
    ldr r0,=\fpscr
    vmsr fpscr,r0
.endif
    .irp n,4,5,6,7,8,9,10,11
    ldr r\n,=(\base+\n)
    .endr
.endm
.macro capture offset,active
    add sp,sp,#\offset
    stmia sp,{r0-r12,lr}
    mrs r0,control
    str r0,[sp,#56]
    sub r0,sp,#\offset
    str r0,[sp,#60]
    /* Exercise the real public current/load/barrier path while unprivileged. */
    bl fiber_current
    str r0,[sp,#64]
.if \active
    add r0,sp,#80
    vstmia r0,{s0-s31}
    vmrs r0,fpscr
    str r0,[sp,#208]
.endif
    sub sp,sp,#\offset
.endm
.macro task name,base,table,fpscr,active
.global \name
.type \name,%function
.thumb_func
\name:
    sub sp,sp,#1024
    bl fiber_current
    str r0,[sp,#768]
#if EXEC_CASE == 7
    bl fixture_foreign_yield
#elif EXEC_CASE == 8
    bl fixture_foreign_return
#endif
    seed \base,\table,\fpscr,\active
    bl fiber_schedule
    capture 0,\active
    seed \base,\table,\fpscr,\active
    bl fiber_schedule
    capture 256,\active
    seed \base,\table,\fpscr,\active
    bl fiber_schedule
    capture 512,\active
    b fiber_port_unprivileged_task_return
.size \name,.-\name
.endm
#if EXEC_FP == 2
task fixture_task_a,0x11000000,fixture_fp_a,0x00400000,1
task fixture_task_b,0x22000000,fixture_fp_b,0x00800000,0
#else
task fixture_task_a,0x11000000,fixture_fp_a,0x00400000,EXEC_FP
task fixture_task_b,0x22000000,fixture_fp_b,0x00800000,EXEC_FP
#endif
.balign 4
fixture_fp_a:
.set n,0
.rept 32
    .word 0x3f100000+n*0x1000
    .set n,n+1
.endr
fixture_fp_b:
.set n,0
.rept 32
    .word 0x40100000+n*0x1000
    .set n,n+1
.endr

/* Valid syscall flash, correct opcode, but not an owned continuation. */
.section .fiber_port_syscalls,"ax",%progbits
.global fixture_foreign_yield
.type fixture_foreign_yield,%function
.thumb_func
fixture_foreign_yield:
    svc #71
.global fixture_foreign_yield_continuation
fixture_foreign_yield_continuation:
    udf #71
.size fixture_foreign_yield,.-fixture_foreign_yield
.global fixture_foreign_return
.type fixture_foreign_return,%function
.thumb_func
fixture_foreign_return:
    svc #72
.global fixture_foreign_return_continuation
fixture_foreign_return_continuation:
    udf #72
.size fixture_foreign_return,.-fixture_foreign_return

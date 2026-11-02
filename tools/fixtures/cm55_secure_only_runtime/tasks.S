.syntax unified
.arch armv8.1-m.main
.thumb
.section .text.fixture_tasks,"ax",%progbits
.macro capture offset
    add sp,sp,#\offset
    stmia sp,{r0-r12,lr}
    mrs r0,control
    str r0,[sp,#56]
    sub r0,sp,#\offset
    str r0,[sp,#60]
    bl fiber_current
    str r0,[sp,#64]
    mrs r0,psplim
    str r0,[sp,#68]
    mrs r0,primask
    str r0,[sp,#72]
    mrs r0,basepri
    str r0,[sp,#76]
    mrs r0,faultmask
    str r0,[sp,#80]
    sub sp,sp,#\offset
.endm
.macro seed base
    .irp n,4,5,6,7,8,9,10,11
    ldr r\n,=(\base+\n)
    .endr
.endm
.macro task name,base
.global \name
.type \name,%function
.thumb_func
\name:
    stmdb sp!,{r0-r12,lr}
    sub sp,sp,#1024
    mrs r0,control
    str r0,[sp,#512]
    add r0,sp,#1080
    str r0,[sp,#516]
    bl fiber_current
    str r0,[sp,#520]
#if EXEC_CASE == 9
    movs r0,#1
    msr primask,r0
#elif EXEC_CASE == 10
    movs r0,#64
    msr basepri,r0
#elif EXEC_CASE == 11
    movs r0,#1
    msr faultmask,r0
#elif EXEC_CASE == 12
    svc #69
#endif
    seed \base
    bl fiber_schedule
    capture 0
    seed \base
    bl fiber_schedule
    capture 128
    seed \base
    bl fiber_schedule
    capture 256
    /* Return through the actual constructor-seeded common task-return LR. */
    add sp,sp,#1024
    ldmia sp!,{r0-r12,lr}
    bx lr
.size \name,.-\name
.endm
task fixture_task_a,0x11000000
task fixture_task_b,0x22000000

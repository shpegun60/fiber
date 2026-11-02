.syntax unified
.thumb
.section .text.fixture_construct,"ax",%progbits
.global fixture_construct
.type fixture_construct,%function
.thumb_func
fixture_construct:
    /* Check ordinary ABI callee-save behavior. Initial-frame seed meaning is
     * separately asserted only when the complete C chain reserves r9. */
    push {r4,r5,r9,lr}
    ldr r4,[sp,#16]
    ldr r9,[sp,#20]
    sub sp,sp,#8
    str r4,[sp]
    bl fiber_init
    mov r0,r9
    add sp,sp,#8
    pop {r4,r5,r9,pc}
.size fixture_construct,.-fixture_construct
.global fixture_foreign_svc
.type fixture_foreign_svc,%function
.thumb_func
fixture_foreign_svc:
    svc #69
    bx lr
.size fixture_foreign_svc,.-fixture_foreign_svc

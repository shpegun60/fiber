.syntax unified
.cpu cortex-m4
.thumb
.section .fixture_api_roots,"a",%progbits
.balign 4
.global fixture_public_api_roots
.type fixture_public_api_roots,%object
fixture_public_api_roots:
#if PILOT_FIBER
    .word fiber_v1_init
    .word fiber_v1_current
    .word fiber_v1_set_scheduler
    .word fiber_v1_start
    .word fiber_v1_yield
#else
    .word ctxrt_v1_init
    .word ctxrt_v1_current
    .word ctxrt_v1_set_dispatcher
    .word ctxrt_v1_start
    .word ctxrt_v1_yield
#endif
.size fixture_public_api_roots,.-fixture_public_api_roots
.section .note.GNU-stack,"",%progbits

#include "fixture.h"
.syntax unified
.cpu cortex-m0
.thumb

.section .text.fixture_probe_yield,"ax",%progbits
.balign 2
.global fixture_probe_yield
.type fixture_probe_yield,%function
.thumb_func
fixture_probe_yield:
    push {r4-r7, lr}
    mov r4, r8
    mov r5, r9
    mov r6, r10
    mov r7, r11
    push {r4-r7}
    /* 36 saved bytes + 20 local bytes keep the call eight-byte aligned. */
    sub sp, #20
    str r0, [sp, #0]
    mov r1, sp
    str r1, [sp, #4]
    mrs r1, psp
    str r1, [sp, #8]
    ldr r1, =0xC001CAFE
    str r1, [sp, #12]
    movs r1, #0
    str r1, [sp, #16]
    cmp r0, #1
    bls 1f
    movs r0, #120
    b 9f
1:
    lsls r0, r0, #5
    ldr r1, =fixture_gpr_seeds
    adds r1, r1, r0
    ldr r2, [r1, #16]
    mov r8, r2
    ldr r2, [r1, #20]
    mov r9, r2
    ldr r2, [r1, #24]
    mov r10, r2
    ldr r2, [r1, #28]
    mov r11, r2
    ldr r4, [r1, #0]
    ldr r5, [r1, #4]
    ldr r6, [r1, #8]
    ldr r7, [r1, #12]
#if FIXTURE_USE_FIBER
    bl fiber_v1_yield
#else
    bl ctxrt_v1_yield
#endif
2:
    ldr r0, [sp, #0]
    lsls r0, r0, #5
    ldr r1, =fixture_gpr_seeds
    adds r1, r1, r0
    ldr r2, [r1, #0]
    cmp r4, r2
    bne 4f
    ldr r2, [r1, #4]
    cmp r5, r2
    bne 4f
    ldr r2, [r1, #8]
    cmp r6, r2
    bne 4f
    ldr r2, [r1, #12]
    cmp r7, r2
    bne 4f
    mov r3, r8
    ldr r2, [r1, #16]
    cmp r3, r2
    bne 4f
    mov r3, r9
    ldr r2, [r1, #20]
    cmp r3, r2
    bne 4f
    mov r3, r10
    ldr r2, [r1, #24]
    cmp r3, r2
    bne 4f
    mov r3, r11
    ldr r2, [r1, #28]
    cmp r3, r2
    bne 4f
    mov r0, sp
    ldr r1, [sp, #4]
    cmp r0, r1
    bne 5f
    mrs r0, psp
    ldr r1, [sp, #8]
    cmp r0, r1
    bne 5f
    mov r1, sp
    cmp r0, r1
    bne 5f
    ldr r0, [sp, #12]
    ldr r1, =0xC001CAFE
    cmp r0, r1
    bne 6f
    ldr r0, [sp, #16]
    cmp r0, #0
    bne 7f
    movs r0, #1
    str r0, [sp, #16]
    /* Supplement the public call-ABI phase with a real PendSV request that
     * has no intervening C callee push/pop masking the seeded r4-r11. */
    ldr r0, =0xE000ED04
    ldr r1, =0x10000000
    str r1, [r0]
    dsb
    isb
    b 2b
7:
    add sp, #20
    pop {r0-r3}
    mov r8, r0
    mov r9, r1
    mov r10, r2
    mov r11, r3
    movs r0, #0
    pop {r4-r7, pc}
4:
    movs r0, #121
    b 9f
5:
    movs r0, #122
    b 9f
6:
    movs r0, #123
9:
    bl fixture_check_fail
    udf #0
    b .
.ltorg
.size fixture_probe_yield, .-fixture_probe_yield

#if FIXTURE_CASE >= FIXTURE_PRESTART_FOREIGN_SVC
.section .text.fixture_provenance_probe,"ax",%progbits
.balign 2
.global fixture_provenance_probe
.type fixture_provenance_probe,%function
.thumb_func
fixture_provenance_probe:
    /* An actual AAPCS call boundary supplies an aligned live SP. No synthetic
     * stacked PC, xPSR, EXC_RETURN or exception mode is installed here. */
    mov r0, sp
    movs r1, #7
    tst r0, r1
    bne 8f
#if FIXTURE_CASE == FIXTURE_PRESTART_FOREIGN_SVC
    svc #69
#elif FIXTURE_CASE == FIXTURE_RUNNING_START_SVC
    svc #70
#elif FIXTURE_CASE == FIXTURE_PRESTART_PENDSV
    ldr r0, =0xE000ED04
    ldr r1, =0x10000000
    str r1, [r0]
    dsb
    isb
#endif
8:
    movs r0, #124
    bl fixture_check_fail
    udf #0
    b .
.ltorg
.size fixture_provenance_probe, .-fixture_provenance_probe
#endif

.section .rodata.fixture_gpr_seeds,"a",%progbits
.balign 4
.global fixture_gpr_seeds
.type fixture_gpr_seeds,%object
fixture_gpr_seeds:
    .word 0xA0044404, 0xA0055505, 0xA0066606, 0xA0077707
    .word 0xA0088808, 0xA0099909, 0xA00AAA0A, 0xA00BBB0B
    .word 0xB1144414, 0xB1155515, 0xB1166616, 0xB1177717
    .word 0xB1188818, 0xB1199919, 0xB11AAA1A, 0xB11BBB1B
.size fixture_gpr_seeds, .-fixture_gpr_seeds

.section .text.fixture_semihost_write0,"ax",%progbits
.balign 2
.global fixture_semihost_write0
.type fixture_semihost_write0,%function
.thumb_func
fixture_semihost_write0:
    mov r1, r0
    movs r0, #4
    bkpt #0xAB
    bx lr
.size fixture_semihost_write0, .-fixture_semihost_write0

.section .text.fixture_exit,"ax",%progbits
.balign 2
.global fixture_exit
.type fixture_exit,%function
.thumb_func
fixture_exit:
    sub sp, #8
    str r0, [sp, #4]
    ldr r0, =0x00020026
    str r0, [sp, #0]
    mov r1, sp
    movs r0, #0x20
    bkpt #0xAB
    udf #0
    b .
.ltorg
.size fixture_exit, .-fixture_exit

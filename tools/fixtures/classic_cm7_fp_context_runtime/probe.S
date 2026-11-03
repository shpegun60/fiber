#include "fixture.h"
.syntax unified
.cpu cortex-m7
.fpu fpv5-d16
.thumb

/* Locals: id 0, SP 4, PSP 8, cookie 12, phase 16, saved s16-s31 32..95,
 * FP snapshot 96..223, FPSCR 224, caller FPSCR 228. Total 272 bytes. */
.section .text.fixture_probe_yield,"ax",%progbits
.balign 2
.global fixture_probe_yield
.type fixture_probe_yield,%function
.thumb_func
fixture_probe_yield:
    push {r4-r11, lr}
    sub sp, #236
    str r0, [sp, #0]
    mov r1, sp
    str r1, [sp, #4]
    mrs r1, psp
    str r1, [sp, #8]
    ldr r1, =0xC04FCAFE
    str r1, [sp, #12]
    movs r1, #0
    str r1, [sp, #16]
    cmp r0, #2
    bhi .Lbad_id
    ldr r1, =fixture_probe_sp
    mov r2, sp
    str r2, [r1, r0, lsl #2]
    cmp r0, #2
    beq .Lseed_gpr
    add r1, sp, #32
    vstmia r1, {s16-s31}
    vmrs r1, fpscr
    str r1, [sp, #228]
    movs r1, #132
    mul r0, r0, r1
    ldr r1, =fixture_fp_seeds
    add r0, r0, r1
    vldmia r0!, {s0-s31}
    ldr r1, [r0]
    vmsr fpscr, r1
.Lseed_gpr:
    ldr r0, [sp, #0]
    ldr r1, =fixture_gpr_seeds
    add r1, r1, r0, lsl #5
    ldmia r1, {r4-r11}
    movs r0, #1
    ldr r1, =fixture_observer_phase
    str r0, [r1]
    ldr r0, [sp, #0]
    adds r0, #1
    ldr r1, =fixture_observer_arm
    str r0, [r1]
#if FIXTURE_USE_FIBER
    bl fiber_v1_yield
#else
    bl ctxrt_v1_yield
#endif
.Lcheck:
    ldr r0, [sp, #0]
    ldr r1, =fixture_gpr_seeds
    add r1, r1, r0, lsl #5
    ldr r2, [r1, #0]
    cmp r4, r2
    bne .Lbad_gpr
    ldr r2, [r1, #4]
    cmp r5, r2
    bne .Lbad_gpr
    ldr r2, [r1, #8]
    cmp r6, r2
    bne .Lbad_gpr
    ldr r2, [r1, #12]
    cmp r7, r2
    bne .Lbad_gpr
    ldr r2, [r1, #16]
    cmp r8, r2
    bne .Lbad_gpr
    ldr r2, [r1, #20]
    cmp r9, r2
    bne .Lbad_gpr
    ldr r2, [r1, #24]
    cmp r10, r2
    bne .Lbad_gpr
    ldr r2, [r1, #28]
    cmp r11, r2
    bne .Lbad_gpr
    mov r0, sp
    ldr r1, [sp, #4]
    cmp r0, r1
    bne .Lbad_sp
    mrs r0, psp
    ldr r1, [sp, #8]
    cmp r0, r1
    bne .Lbad_sp
    mov r1, sp
    cmp r0, r1
    bne .Lbad_sp
    ldr r0, [sp, #12]
    ldr r1, =0xC04FCAFE
    cmp r0, r1
    bne .Lbad_cookie
    /* Inspect resumed Thread FPCA before any following FP instruction. */
    mrs r1, control
    and r1, r1, #7
    ldr r0, [sp, #0]
    cmp r0, #2
    beq .Lcheck_inactive
    cmp r1, #6
    bne .Lbad_fpca
    add r0, sp, #96
    vstmia r0, {s0-s31}
    vmrs r0, fpscr
    str r0, [sp, #224]
    ldr r0, [sp, #0]
    movs r1, #132
    mul r0, r0, r1
    ldr r1, =fixture_fp_seeds
    add r1, r1, r0
    add r2, sp, #96
    movs r3, #32
    ldr r0, [sp, #16]
    cmp r0, #0
    bne .Lcompare_fp
    /* Low FP/FPSCR are caller-saved at a C ABI. Only high FP is asserted
     * across the public call; full payload is checked in the direct phase. */
    adds r1, #64
    adds r2, #64
    movs r3, #16
.Lcompare_fp:
    ldr r0, [r1], #4
    ldr r12, [r2], #4
    cmp r0, r12
    bne .Lbad_fp
    subs r3, #1
    bne .Lcompare_fp
    ldr r0, [sp, #16]
    cmp r0, #0
    beq .Lphase_done
    ldr r0, [sp, #224]
    ldr r1, [r1]
    cmp r0, r1
    bne .Lbad_fpscr
    b .Lphase_done
.Lcheck_inactive:
    cmp r1, #2
    bne .Lbad_fpca
.Lphase_done:
    ldr r0, [sp, #16]
    cmp r0, #0
    bne .Lrestore
    movs r0, #1
    str r0, [sp, #16]
    ldr r0, [sp, #0]
    cmp r0, #2
    beq .Ldirect_arm
    movs r1, #132
    mul r0, r0, r1
    ldr r1, =fixture_fp_seeds
    add r0, r0, r1
    /* Re-seed caller-saved state inside the direct assembly envelope. */
    vldmia r0!, {s0-s31}
    ldr r1, [r0]
    vmsr fpscr, r1
.Ldirect_arm:
    movs r0, #2
    ldr r1, =fixture_observer_phase
    str r0, [r1]
    ldr r0, [sp, #0]
    adds r0, #1
    ldr r1, =fixture_observer_arm
    str r0, [r1]
    ldr r0, =0xE000ED04
    ldr r1, =0x10000000
    str r1, [r0]
    dsb
    isb
    b .Lcheck
.Lrestore:
    ldr r0, [sp, #0]
    cmp r0, #2
    beq .Lrestore_core
    ldr r1, [sp, #228]
    vmsr fpscr, r1
    add r0, sp, #32
    vldmia r0, {s16-s31}
.Lrestore_core:
    add sp, #236
    movs r0, #0
    pop {r4-r11, pc}
.Lbad_id:
    movs r0, #120
    b .Lfail
.Lbad_gpr:
    movs r0, #FIXTURE_REASON_GPR
    b .Lfail
.Lbad_sp:
    movs r0, #122
    b .Lfail
.Lbad_cookie:
    movs r0, #123
    b .Lfail
.Lbad_fpca:
    movs r0, #FIXTURE_REASON_FPCA
    b .Lfail
.Lbad_fp:
    cmp r3, #16
    bhi .Lbad_low_fp
    movs r0, #FIXTURE_REASON_HIGH_FP
    b .Lfail
.Lbad_low_fp:
    movs r0, #FIXTURE_REASON_LOW_FP
    b .Lfail
.Lbad_fpscr:
    movs r0, #FIXTURE_REASON_FPSCR
.Lfail:
    bl fixture_check_fail
    udf #0
    b .
.ltorg
.size fixture_probe_yield, .-fixture_probe_yield

.section .rodata.fixture_gpr_seeds,"a",%progbits
.balign 4
.global fixture_gpr_seeds
.type fixture_gpr_seeds,%object
fixture_gpr_seeds:
    .word 0xA0044404, 0xA0055505, 0xA0066606, 0xA0077707
    .word 0xA0088808, 0xA0099909, 0xA00AAA0A, 0xA00BBB0B
    .word 0xB1144414, 0xB1155515, 0xB1166616, 0xB1177717
    .word 0xB1188818, 0xB1199919, 0xB11AAA1A, 0xB11BBB1B
    .word 0xC2244424, 0xC2255525, 0xC2266626, 0xC2277727
    .word 0xC2288828, 0xC2299929, 0xC22AAA2A, 0xC22BBB2B
.size fixture_gpr_seeds, .-fixture_gpr_seeds

.section .rodata.fixture_fp_seeds,"a",%progbits
.balign 4
.global fixture_fp_seeds
.type fixture_fp_seeds,%object
fixture_fp_seeds:
    .word 0x3F100000, 0x3F110001, 0x3F120002, 0x3F130003
    .word 0x3F140004, 0x3F150005, 0x3F160006, 0x3F170007
    .word 0x3F180008, 0x3F190009, 0x3F1A000A, 0x3F1B000B
    .word 0x3F1C000C, 0x3F1D000D, 0x3F1E000E, 0x3F1F000F
    .word 0x3F200010, 0x3F210011, 0x3F220012, 0x3F230013
    .word 0x3F240014, 0x3F250015, 0x3F260016, 0x3F270017
    .word 0x3F280018, 0x3F290019, 0x3F2A001A, 0x3F2B001B
    .word 0x3F2C001C, 0x3F2D001D, 0x3F2E001E, 0x3F2F001F
    .word 0x01000000
    .word 0x40200000, 0x40210001, 0x40220002, 0x40230003
    .word 0x40240004, 0x40250005, 0x40260006, 0x40270007
    .word 0x40280008, 0x40290009, 0x402A000A, 0x402B000B
    .word 0x402C000C, 0x402D000D, 0x402E000E, 0x402F000F
    .word 0x40300010, 0x40310011, 0x40320012, 0x40330013
    .word 0x40340014, 0x40350015, 0x40360016, 0x40370017
    .word 0x40380018, 0x40390019, 0x403A001A, 0x403B001B
    .word 0x403C001C, 0x403D001D, 0x403E001E, 0x403F001F
    .word 0x02400000
.size fixture_fp_seeds, .-fixture_fp_seeds

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

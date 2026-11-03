#include "fixture.h"
.syntax unified
.cpu cortex-m4
.fpu fpv4-sp-d16
.thumb

/* 36 saved GPR bytes + 236 local bytes = 272, preserving AAPCS8 alignment.
 * Locals: worker0, box4, SP8, cookie12, phase16, reserved/unused20, result24,
 * caller high-FP32..95, snapshot96..223, FPSCR224, caller FPSCR228,
 * cookie232. Every writable address is on this worker's own MPU stack.
 */
.section .fixture_user_functions,"ax",%progbits
.balign 2
.global fixture_fp_probe
.type fixture_fp_probe,%function
.thumb_func
fixture_fp_probe:
    push {r4-r11, lr}
    sub sp, #236
    str r0, [sp, #0]
    str r1, [sp, #4]
    mov r2, sp
    str r2, [sp, #8]
    ldr r2, =0xc04fcafe
    str r2, [sp, #12]
    ldr r2, =0x13579bdf
    str r2, [sp, #232]
    movs r2, #0
    str r2, [r1, #PILOT_BOX_REASON]
    cmp r0, #2
    bhi .Lbad_worker
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
    str r0, [sp, #16]
    ldr r1, [sp, #4]
    str r0, [r1, #PILOT_BOX_PHASE]
.global fixture_fp_public_call
fixture_fp_public_call:
    bl fixture_task_yield
.global fixture_fp_public_resume
fixture_fp_public_resume:
    b .Lcheck

.Ldirect:
    ldr r0, [sp, #0]
    cmp r0, #2
    beq .Ldirect_arm
    movs r1, #132
    mul r0, r0, r1
    ldr r1, =fixture_fp_seeds
    add r0, r0, r1
    /* The public C ABI can clobber low FP/FPSCR. Re-seed inside the assembly
     * envelope before calling the real naked SVC71 scheduling primitive. */
    vldmia r0!, {s0-s31}
    ldr r1, [r0]
    vmsr fpscr, r1
.Ldirect_arm:
    movs r0, #2
    str r0, [sp, #16]
    ldr r1, [sp, #4]
    str r0, [r1, #PILOT_BOX_PHASE]
.global fixture_fp_direct_call
fixture_fp_direct_call:
    bl fiber_port_runtime_schedule
.global fixture_fp_direct_resume
fixture_fp_direct_resume:

.Lcheck:
    ldr r0, [sp, #4]
    add r0, r0, #PILOT_BOX_GPRS
    stmia r0, {r4-r11}
    mov r2, r0
    ldr r0, [sp, #0]
    ldr r1, =fixture_gpr_seeds
    add r1, r1, r0, lsl #5
    movs r3, #8
.Lcompare_gpr:
    ldr r0, [r1], #4
    ldr r12, [r2], #4
    cmp r0, r12
    bne .Lbad_gpr
    subs r3, #1
    bne .Lcompare_gpr

    mov r0, sp
    ldr r1, [sp, #8]
    cmp r0, r1
    bne .Lbad_sp
    ldr r2, [sp, #4]
    str r1, [r2, #PILOT_BOX_BEFORE_SP]
    str r0, [r2, #PILOT_BOX_AFTER_SP]
    ldr r0, [sp, #12]
    ldr r1, =0xc04fcafe
    cmp r0, r1
    bne .Lbad_cookie
    str r0, [r2, #PILOT_BOX_COOKIE0]
    ldr r0, [sp, #232]
    ldr r1, =0x13579bdf
    cmp r0, r1
    bne .Lbad_cookie
    str r0, [r2, #PILOT_BOX_COOKIE1]
    mrs r0, ipsr
    cmp r0, #0
    bne .Lbad_ipsr

    /* Observe Thread FPCA before this resumed path executes any VFP opcode. */
    mrs r1, control
    str r1, [r2, #PILOT_BOX_CONTROL]
    ldr r0, [sp, #0]
    cmp r0, #2
    beq .Lcheck_inactive
    cmp r1, #7
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
    cmp r0, #1
    bne .Lcompare_fp
    /* Across the genuine public yield, assert only ABI-preserved high FP. */
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
    ldr r2, [sp, #4]
    ldr r0, [r2, #PILOT_BOX_FP_CHECKS]
    adds r0, #1
    str r0, [r2, #PILOT_BOX_FP_CHECKS]
    ldr r0, [sp, #16]
    cmp r0, #1
    beq .Lphase_done
    ldr r0, [sp, #224]
    ldr r1, [r1]
    cmp r0, r1
    bne .Lbad_fpscr
    ldr r0, [r2, #PILOT_BOX_FPSCR_CHECKS]
    adds r0, #1
    str r0, [r2, #PILOT_BOX_FPSCR_CHECKS]
    b .Lphase_done
.Lcheck_inactive:
    cmp r1, #3
    bne .Lbad_fpca
.Lphase_done:
    ldr r2, [sp, #4]
    ldr r0, [r2, #PILOT_BOX_COMPLETED]
    adds r0, #1
    str r0, [r2, #PILOT_BOX_COMPLETED]
    ldr r0, [sp, #16]
    cmp r0, #1
    beq .Ldirect
    movs r0, #0
    b .Lfinish

.Lbad_worker:
    movs r0, #120
    b .Lfinish
.Lbad_gpr:
    movs r0, #PILOT_REASON_GPR
    b .Lfinish
.Lbad_sp:
    movs r0, #PILOT_REASON_SP
    b .Lfinish
.Lbad_cookie:
    movs r0, #PILOT_REASON_COOKIE
    b .Lfinish
.Lbad_ipsr:
    movs r0, #PILOT_REASON_IPSR
    b .Lfinish
.Lbad_fpca:
    movs r0, #PILOT_REASON_FPCA
    b .Lfinish
.Lbad_fp:
    cmp r3, #16
    bhi .Lbad_low_fp
    movs r0, #PILOT_REASON_HIGH_FP
    b .Lfinish
.Lbad_low_fp:
    movs r0, #PILOT_REASON_LOW_FP
    b .Lfinish
.Lbad_fpscr:
    movs r0, #PILOT_REASON_FPSCR
.Lfinish:
    str r0, [sp, #24]
    ldr r1, [sp, #4]
    str r0, [r1, #PILOT_BOX_REASON]
    ldr r0, [sp, #0]
    cmp r0, #2
    bhs .Lrestore_core
    ldr r0, [sp, #228]
    vmsr fpscr, r0
    add r0, sp, #32
    vldmia r0, {s16-s31}
.Lrestore_core:
    ldr r0, [sp, #24]
    add sp, #236
    pop {r4-r11, pc}
.ltorg
.size fixture_fp_probe, .-fixture_fp_probe

.section .fixture_user_rodata,"a",%progbits
.balign 4
.global fixture_gpr_seeds
.type fixture_gpr_seeds,%object
fixture_gpr_seeds:
.irp worker,0,1,2
.irp reg,4,5,6,7,8,9,10,11
    .word (0xa4000000 + \worker * 0x01000000 + \reg * 0x1111)
.endr
.endr
.size fixture_gpr_seeds, .-fixture_gpr_seeds
.global fixture_fp_seeds
.type fixture_fp_seeds,%object
fixture_fp_seeds:
.irp worker,0,1
.irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    .word (0x3f000000 + \worker * 0x01000000 + \reg * 0x00010101)
.endr
    .word (\worker * 0x00400000)
.endr
.size fixture_fp_seeds, .-fixture_fp_seeds
.section .note.GNU-stack,"",%progbits

.syntax unified
.thumb
.fpu fpv5-sp-d16
.section .text.fixture_task,"ax",%progbits
.global fixture_task
.type fixture_task,%function
.thumb_func
fixture_task:
 sub sp,sp,#8
 str r0,[sp]
 ldr r1,=fixture_gpr_payload
 add r1,r1,r0,lsl #5
#if EXEC_RESERVED_R9
 ldmia r1!,{r4-r8}
 adds r1,r1,#4
 ldmia r1!,{r10-r11}
#else
 ldmia r1!,{r4-r11}
#endif
 cmp r0,#1
 beq 1f
 ldr r1,=fixture_fp_payload
 add r1,r1,r0,lsl #7
 vldmia r1,{s0-s31}
 cmp r0,#0
 ite eq
 moveq r1,#0x400000
 movne r1,#0x800000
 vmsr fpscr,r1
1:
 ldr r0,[sp]
 ldr r1,=fixture_gpr_capture
 add r1,r1,r0,lsl #5
 stmia r1,{r4-r11}
 cmp r0,#1
 beq 2f
 ldr r1,=fixture_fp_capture
 add r1,r1,r0,lsl #7
 vstmia r1,{s0-s31}
 vmrs r2,fpscr
 ldr r1,=fixture_fpscr_capture
 str r2,[r1,r0,lsl #2]
2:
 bl fixture_step
 bl fiber_schedule
 b 1b
.size fixture_task,.-fixture_task
.section .rodata.payload,"a",%progbits
.balign 8
.global fixture_gpr_payload
fixture_gpr_payload:
.set owner,0
.rept 3
.set regno,4
.rept 8
#if EXEC_RESERVED_R9
.if regno == 9
 .word 0x13579bdf
.else
 .word 0x44000000 + owner*0x10000 + regno
.endif
#else
 .word 0x44000000 + owner*0x10000 + regno
#endif
.set regno,regno+1
.endr
.set owner,owner+1
.endr
.global fixture_fp_payload
fixture_fp_payload:
.set owner,0
.rept 3
.set regno,0
.rept 32
 .word 0x3f000000 + owner*0x100000 + regno
.set regno,regno+1
.endr
.set owner,owner+1
.endr

.syntax unified
.thumb
.section .vectors,"a",%progbits
.balign 128
#ifdef FIXTURE_SECURE
.word 0x30004000
.word Reset_Handler
.rept 9
.word fixture_fault
.endr
.word fixture_secure_svc
.rept 4
.word fixture_fault
.endr
#else
.word 0x20008000
.word NS_Reset_Handler
.rept 9
.word fixture_fault
.endr
.word fixture_ns_svc
.word fixture_fault
.word fixture_fault
.word fixture_ns_pendsv
.word fixture_ns_systick
#endif
.section .text.startup,"ax",%progbits
#ifdef FIXTURE_SECURE
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
    ldr r0,=__bss_start
    ldr r1,=__bss_end
    movs r2,#0
1:  cmp r0,r1
    bhs 2f
    str r2,[r0],#4
    b 1b
2:
#ifdef FIXTURE_SECURE
    bl fixture_secure_main
#else
    bl fixture_ns_main
#endif
    b .

.section .text.fixture_fault,"ax",%progbits
.global fixture_fault
.type fixture_fault,%function
.thumb_func
fixture_fault:
    tst lr,#8
    beq 3f
    tst lr,#4
    ite eq
    mrseq r0,msp
    mrsne r0,psp
    b 4f
3:  mrs r0,msp
4:  mov r1,lr
    b fixture_fault_report
.size fixture_fault,.-fixture_fault

#ifdef FIXTURE_SECURE
/* Debugger-directed policy changes execute real Secure CPU instructions.
 * These are ordinary fixture symbols, never NSC entries or port helpers. */
.macro helper name, insn
.global \name
.type \name,%function
.thumb_func
\name:
    \insn
    bx lr
.size \name,.-\name
.endm
.section .text.fixture_policy,"ax",%progbits
helper fixture_word_store, "str r0,[r1]"
helper fixture_word_load, "ldr r0,[r1]"
helper fixture_control_store, "msr control,r0"
helper fixture_control_ns_store, "msr control_ns,r0"
helper fixture_control_load, "mrs r0,control"
helper fixture_control_ns_load, "mrs r0,control_ns"
helper fixture_masks_store, "msr primask,r0"
helper fixture_basepri_store, "msr basepri,r0"
helper fixture_faultmask_store, "msr faultmask,r0"
#endif

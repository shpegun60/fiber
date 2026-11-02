.syntax unified
.thumb

.section .text.r9_call_init,"ax",%progbits
.global r9_call_init
.type r9_call_init,%function
.thumb_func
/* Thumb-1-compatible: preserve the caller's R9, seed immediately before the
 * real public API call, return its post-call R9 in R0, then restore outer R9. */
r9_call_init:
    push {r4-r7,lr}
    mov r4,r9
    ldr r5,[sp,#20]
    ldr r6,[sp,#24]
    mov r9,r6
    sub sp,sp,#12
    str r5,[sp]
    bl fiber_init
    add sp,sp,#12
    mov r0,r9
    mov r9,r4
    pop {r4-r7,pc}
.size r9_call_init,.-r9_call_init

/* Hooks use R9 as a legal AAPCS temporary and restore it before returning.
 * The policies remain actual compiled code; the emulator never skips calls. */
.macro R9_HOOK name,target,value
.section .text.\name,"ax",%progbits
.global \name
.type \name,%function
.thumb_func
\name:
#if R9_RESERVED
    ldr r3,=\target
    bx r3
#else
    push {r4,lr}
    mov r4,r9
    ldr r3,=\value
    mov r9,r3
    bl \target
    mov r9,r4
    pop {r4,pc}
#endif
    .ltorg
.size \name,.-\name
.endm
R9_HOOK fiber_addr_plausible_ram,r9_ram_policy,0x1357CAFE
R9_HOOK fiber_addr_plausible_code,r9_code_policy,0x2468BEEF

/* Scalar, loop-explicit memory fixtures work on all qualified instruction
 * subsets, without excluding branch-count/FP flags from production code. */
.section .text.memcpy,"ax",%progbits
.global memcpy
.type memcpy,%function
.thumb_func
memcpy:
    push {r4,lr}
    mov r3,r0
1:  cmp r2,#0
    beq 2f
    ldrb r4,[r1]
    strb r4,[r3]
    adds r1,#1
    adds r3,#1
    subs r2,#1
    b 1b
2:  pop {r4,pc}
.size memcpy,.-memcpy

.section .text.memset,"ax",%progbits
.global memset
.type memset,%function
.thumb_func
memset:
    mov r3,r0
1:  cmp r2,#0
    beq 2f
    strb r1,[r3]
    adds r3,#1
    subs r2,#1
    b 1b
2:  bx lr
.size memset,.-memset

.section .text.r9_stop,"ax",%progbits
.global r9_stop
.type r9_stop,%function
.thumb_func
r9_stop:
    bkpt #0
    b .
.size r9_stop,.-r9_stop

.section .text.r9_fault_probe,"ax",%progbits
.global r9_fault_probe
.type r9_fault_probe,%function
.thumb_func
r9_fault_probe:
    udf #0
    b .
.size r9_fault_probe,.-r9_fault_probe

/* Unexecuted external image boundaries let complete existing source groups
 * link. Calling any of them faults the test; no Secure/TF-M success is faked. */
.macro UNEXECUTED name
.section .text.\name,"ax",%progbits
.global \name
.type \name,%function
.thumb_func
\name:
    udf #0
    b .
.size \name,.-\name
.endm
UNEXECUTED tfm_ns_interface_init
UNEXECUTED fiber_secure_gateway_v1_abi_version
UNEXECUTED fiber_secure_gateway_v1_context_port_id
UNEXECUTED fiber_secure_gateway_v1_context_layout_version
UNEXECUTED fiber_secure_gateway_v1_context_feature_mask
UNEXECUTED fiber_secure_context_gateway_v1_abi_version
UNEXECUTED fiber_secure_context_gateway_v1_stack_alignment
UNEXECUTED fiber_secure_context_gateway_v1_max_stack_bytes
UNEXECUTED fiber_secure_context_gateway_v1_max_contexts
UNEXECUTED fiber_secure_context_gateway_v1_initialize
UNEXECUTED fiber_secure_context_gateway_v1_allocate
UNEXECUTED fiber_secure_context_gateway_v1_load
UNEXECUTED fiber_secure_context_gateway_v1_save

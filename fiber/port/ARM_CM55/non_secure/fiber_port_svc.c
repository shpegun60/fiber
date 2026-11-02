/* C55S one-shot owned SVC only. There is deliberately no PendSV handler. */
#include "fiber_portmacro.h"
#include "fiber_port_private.h"

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_arm_cm55_secure_context_first_start_component_v1_anchor(void)
{
	FIBER_RUNTIME_PORT_ABI_RETAIN_V1();
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
}

FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM FIBER_GENERAL_REGS_ONLY
void fiber_port_start_first_context(uintptr_t msp_top FIBER_ATTR_UNUSED_PARAM)
{
	fiber_portASM volatile(
		".syntax unified\n"
		"mrs r1, ipsr\n"
		"cbnz r1, 9f\n"
		"mrs r1, control\n"
		"cbnz r1, 9f\n"
		"mrs r1, primask\n"
		"cbnz r1, 9f\n"
		"mrs r1, basepri\n"
		"cbnz r1, 9f\n"
		"mrs r1, faultmask\n"
		"cbnz r1, 9f\n"
		"cpsid i\n"
		"dsb\n"
		"isb\n"
		"ldr r1, =0xE000ED08\n"
		"ldr r1, [r1]\n"
		"ldr r2, =__fiber_c55s_ns_vector_start__\n"
		"cmp r1, r2\n"
		"bne 9f\n"
		"ldr r2, [r1, #44]\n"
		"ldr r3, =SVC_Handler\n"
		"cmp r2, r3\n"
		"bne 9f\n"
		"cmp r0, #0\n"
		"beq 1f\n"
		"ldr r2, [r1]\n"
		"cmp r0, r2\n"
		"bne 9f\n"
		"tst r0, #7\n"
		"bne 9f\n"
		"msr msp, r0\n"
		"isb\n"
		"mrs r1, msp\n"
		"cmp r1, r0\n"
		"bne 9f\n"
		"1:\n"
		"ldr r1, =0xE000ED04\n"
		"ldr r2, =0x08000000\n"
		"str r2, [r1]\n"
		"cpsie f\n"
		"cpsie i\n"
		"dsb\n"
		"isb\n"
		"svc #70\n"
		".global fiber_port_c55s_first_start_svc_return\n"
		"fiber_port_c55s_first_start_svc_return:\n"
		"movs r0, #121\n" /* 'y': a successful first SVC never returns here. */
		"bl fiber_panic\n"
		"b .\n"
		"9:\n"
		"movs r0, #108\n"
		"bl fiber_panic\n"
		"b .\n"
		".ltorg\n"
		::: "memory", "cc");
}

FIBER_ATTR_NAKED_ASM FIBER_GENERAL_REGS_ONLY
void SVC_Handler(void)
{
	fiber_portASM volatile(
		".syntax unified\n"
		"mrs r3, ipsr\n"
		"cmp r3, #11\n"
		"bne 9f\n"
		"mvn r3, #71\n" /* B8: NS Thread/MSP basic frame. */
		"cmp lr, r3\n"
		"bne 9f\n"
		"mrs r3, control\n"
		"cbnz r3, 9f\n"
		"mrs r3, primask\n"
		"cbnz r3, 9f\n"
		"mrs r3, basepri\n"
		"cbnz r3, 9f\n"
		"mrs r3, faultmask\n"
		"cbnz r3, 9f\n"
		"mrs r0, msp\n"
		"mov r1, lr\n"
		/* Assembly-only common storage read; never a C declaration/lvalue. */
		"ldr r2, =fiber_internal_runtime_current_context_slot\n"
		"ldr r2, [r2]\n"
		"cpsid i\n"
		"dsb\n"
		"isb\n"
		"b fiber_port_svc_dispatch\n"
		"9:\n"
		"movs r0, #108\n"
		"bl fiber_panic\n"
		"b .\n"
		".ltorg\n"
		::: "memory", "cc");
}

FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM FIBER_GENERAL_REGS_ONLY
void fiber_port_restore_first_context_from_svc(FiberContext *ctx FIBER_ATTR_UNUSED_PARAM)
{
	fiber_portASM volatile(
		".syntax unified\n"
		"ldr r0, [r0]\n"
		/* Handle was checked/published by C. Preserve the reference special-
		 * word order, but restore all GPRs rather than skipping their slots. */
		"ldmia r0!, {r1-r3}\n"
		"mvn r12, #67\n"
		"cmp r3, r12\n"
		"bne 8f\n"
		"msr psplim, r2\n"
		"dsb\n"
		"isb\n"
		"mrs r12, psplim\n"
		"cmp r12, r2\n"
		"bne 7f\n"
		"movs r1, #2\n"
		"msr control, r1\n"
		"isb\n"
		/* Armv8-M Handler uses MSP, but SPSEL writes/readback are real. */
		"mrs r12, control\n"
		"cmp r12, #2\n"
		"bne 9f\n"
		"add r1, r0, #32\n"
		"msr psp, r1\n"
		"isb\n"
		"mrs r12, psp\n"
		"cmp r12, r1\n"
		"bne 8f\n"
		"mrs r1, primask\n"
		"cmp r1, #1\n"
		"bne 9f\n"
		"mrs r1, basepri\n"
		"cbnz r1, 9f\n"
		"mrs r1, faultmask\n"
		"cbnz r1, 9f\n"
		"mrs r1, ipsr\n"
		"cmp r1, #11\n"
		"bne 9f\n"
		/* No failure branch or C call after this final GPR restore. */
		"ldmia r0!, {r4-r11}\n"
		"dsb\n"
		"isb\n"
		"cpsie i\n"
		"dsb\n"
		"isb\n"
		"bx r3\n"
		"7:\n"
		"movs r0, #76\n"
		"b 6f\n"
		"8:\n"
		"movs r0, #120\n"
		"b 6f\n"
		"9:\n"
		"movs r0, #108\n"
		"6:\n"
		"bl fiber_panic\n"
		"b .\n"
		::: "memory", "cc");
}

/*
 * fiber_port_armv7em.c
 *
 * ARMv7E-M PendSV port.
 *
 * This file owns the moved STM32H7/Cortex-M7 PendSV implementation. The move is
 * intended to preserve the validated save/restore behavior while putting the
 * CPU-specific path behind the v2 port boundary.
 */

#include "../fiber_port.h"

#if FIBER_PORT_ARMV7EM

/*
 * ARMv7E-M PendSV implementation.
 *
 * This is a mechanical move of the validated STM32H7/Cortex-M7 mainline path
 * from fiber_core.c. Do not add scheduler policy here. The common runtime owns
 * switch validation, current-context ownership, and publication ordering.
 */
FIBER_ATTR_NAKED_ASM
void fiber_pendsv(void)
{
	__ASM volatile(
			".syntax unified                         \n"

			/* ----------------------------------------------------------------------
			 * Prologue: get PSP and sync pipeline
			 * ---------------------------------------------------------------------- */
			"mrs   r0, psp                          \n" /* r0 = PSP */

#if FIBER_SWITCH_STRICT_BARRIERS
			"dsb                                    \n"  /* (optional) serialize before branch */
#else
			"dmb                                    \n"
#endif /* FIBER_SWITCH_STRICT_BARRIERS */
			"isb                                    \n" /* synchronize */

			/* ----------------------------------------------------------------------
			 * Load exchange pointers and early exit if no target
			 * ---------------------------------------------------------------------- */
			"ldr   r2, =fiber_internal_port_switch_to_slot \n" /* r2 = &target slot */
			"ldr   r2, [r2]                         \n" /* r2 = target context */
			"cbz   r2, 5f                           \n" /* if no target, return */

			"ldr   r1, =fiber_internal_port_switch_from_slot \n" /* r1 = &source slot */
			"ldr   r1, [r1]                         \n" /* r1 = source context */

			/* ----------------------------------------------------------------------
			 * Save source context (only if source slot is not NULL)
			 * Save r4..r11 and EXC_RETURN; optionally save S16..S31 if extended FP frame
			 * ---------------------------------------------------------------------- */
			"cbz   r1, 1f                           \n" /* skip if from == NULL */

#if FIBER_HAS_FPU
			/* SAVE high FP regs S16..S31 iff extended frame present (LR.bit4 == 0) */
			"tst   lr, #0x10                        \n" /* 1 => base frame only, 0 => extended present */
			"bne   2f                               \n" /* if bit4==1 then skip FP save */
			"vstmdb r0!, {s16-s31}                  \n" /* push S16..S31 */
			"2:                                     \n" /* label: skip-fpu-save */
#endif /* FIBER_HAS_FPU */

			"stmdb r0!, {r4-r11, r14}               \n" /* push r4..r11 and LR(EXC_RETURN) */
			"str   r0, [r1]                         \n" /* from->sp = r0 */

			"1:                                     \n" /* label: skip-save */

			/* ----------------------------------------------------------------------
			 * Load target SW area: [r4..r11][r14]
			 * ---------------------------------------------------------------------- */
			"ldr   r0, [r2]                         \n" /* r0 = to->sp */
			"ldmia r0!, {r4-r11, r14}               \n" /* pop r4..r11 and LR(EXC_RETURN) */

#if FIBER_HAS_FPU
			/* RESTORE high FP regs if target wants extended FP frame (LR bit4 == 0) */
			"tst   r14, #0x10                       \n" /* check target EXC_RETURN */
			"bne   3f                               \n" /* if bit4==1 then skip FP restore */
			"vldmia r0!, {s16-s31}                  \n" /* pop S16..S31 */
			"3:                                     \n" /* label: skip-fpu-restore */
#endif /* FIBER_HAS_FPU */

			/* ----------------------------------------------------------------------
			 * Program PSP to target HW frame and clean exchange slots
			 * ---------------------------------------------------------------------- */
			"str   r0, [r2]                         \n" /* to->sp = r0 (now points at HW frame) */
			"msr   psp, r0                          \n" /* PSP := start of HW frame for 'to' */
			"isb                                    \n" /* synchronize before exception return */

			/* Publish the runtime-owned current context, FreeRTOS pxCurrentTCB style. */
			"ldr   r1, =fiber_internal_port_current_context \n" /* r1 = &current context */
			"str   r2, [r1]                         \n" /* current context = to */

			/* Clear exchange slots to avoid stale pointers */
			"movs  r3, #0                           \n" /* r3 = 0 */
			"ldr   r1, =fiber_internal_port_switch_from_slot \n" /* r1 = &source slot */
			"str   r3, [r1]                         \n" /* source slot = NULL */
			"ldr   r1, =fiber_internal_port_switch_to_slot \n" /* r1 = &target slot */
			"str   r3, [r1]                         \n" /* target slot = NULL */

#if FIBER_SWITCH_STRICT_BARRIERS
			"dsb                                    \n"  /* (optional) serialize before branch */
#else
			"dmb                                    \n"
#endif /* FIBER_SWITCH_STRICT_BARRIERS */

			"isb                                    \n" /* synchronize */

			/* ----------------------------------------------------------------------
			 * Return from exception using EXC_RETURN in r14
			 * ---------------------------------------------------------------------- */
			"bx    r14                              \n" /* exception return to Thread mode via PSP */

			/* ----------------------------------------------------------------------
			 * Epilogue: early-out if no target
			 * ---------------------------------------------------------------------- */
			"5:                                     \n"
			"dsb                                    \n" /* ensure memory effects complete */
			"isb                                    \n" /* synchronize pipeline */
			"bx    lr                               \n" /* nothing to do -> return */
			:
			:
			: "memory","cc"
	);
}

#endif /* FIBER_PORT_ARMV7EM */

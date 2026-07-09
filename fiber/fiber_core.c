/* pendvswitch.c - FreeRTOS-style cooperative PendSV with PSPLIM and robust FPU gates
 *
 * This file implements a FreeRTOS-like PendSV context switch for STM32/Cortex-M
 * targets, with STM32H7/Cortex-M7 as the primary validated path. See README.md
 * and FREERTOS_SUPPORT_PLAN.md for the current support matrix.
 * Design goals:
 *   - Correct stack math for v6-M, v7-M, v7E-M and v8-M Mainline paths.
 *   - Optional FPU gates: save/restore S16..S31 only when an extended frame is present (LR bit4 == 0).
 *   - PSPLIM update on v8-M Mainline before programming PSP for the target task.
 *   - v8-M Baseline/M23 PSPLIM and security variants are not validated yet.
 *   - Paranoid runtime checks in fiber_init() to catch configuration errors early.
 *
 * Code comments are intentionally exhaustive and in English.
 */

#include "fiber_core.h"
#include "port/fiber_port.h"

BT_STATIC_ASSERT(offsetof(FiberContext, sp) == 0, "sp must be at offset 0");

/* ---------------- Small helpers ---------------- */
__STATIC_FORCEINLINE uint32_t fiber_read_r9(void) { uint32_t v; __ASM volatile("mov %0, r9":"=r"(v)); return v; }
__STATIC_FORCEINLINE uint32_t xpsr_T(void) { return 0x01000000u; }
__STATIC_FORCEINLINE uint32_t fiber_stacked_pc(entry_t entry) { return ((uint32_t)(uintptr_t)entry) & ~1u; }

/* Safety net if a task ever returns from its entry function */
FIBER_NORETURN FIBER_ATTR_SENSITIVE static void fiber_task_return(void) { fiber_panic('R'); }

/* ---------------- Paranoid seed builder ----------------
 * We build a full software area (callee-saved + EXC_RETURN) under a hardware frame.
 * Layouts:
 *   v6-M / v8-M Baseline frame:  [LR][r8..r11][r4..r7]  (low -> high)
 *   v7/v8 Mainline frame:        [r4..r11][LR]           (low -> high)
 * The hardware frame is always the standard 8 registers (R0..R3, R12, LR, PC, xPSR).
 *
 * We also reserve *one* HW frame of headroom above current PSP to survive the first
 * exception return without running into canary/PSPLIM, exactly as in robust RTOS ports.
 */
void fiber_init(FiberContext* const ctx, void* const stack_begin, void* const stack_end,
		const entry_t entry, void* const arg)
{
	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }

	/* -------- basic nullness and monotonicity -------- */
	FIBER_REQUIRE(ctx         != NULL, 'C');
	FIBER_REQUIRE(stack_begin != NULL, 'B');
	FIBER_REQUIRE(stack_end   != NULL, 'T');
	FIBER_REQUIRE(entry       != NULL, 'E');
	FIBER_REQUIRE(stack_end > stack_begin, 'N');

	/* -------- entry must be Thumb and plausibly executable -------- */
	{
		const uintptr_t ea = (uintptr_t)entry;
		FIBER_REQUIRE((ea & 1u) == 1u, 'e');  /* Thumb bit */
		FIBER_REQUIRE(fiber_addr_plausible_code(ea & ~(uintptr_t)1u) != 0, 'c');
	}

	/* -------- obtain sealed boot plan from your existing factory -------- */
	ctx->boot = fiber_create_boot(stack_begin, stack_end, entry, arg);

	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }

	/* -------- top must be 8-byte aligned (AAPCS) -------- */
	FIBER_REQUIRE((((uintptr_t)ctx->boot.stack_top) & 7u) == 0u, 'a');

	/* -------- ensure enough space for seed frames --------
	 * We require:
	 *   - FIBER_EXC_PER_LEVEL bytes headroom (one full HW exception level as defined by your platform)
	 *   - one "real" HW frame we build (always base 8 regs = FIBER_EXC_BASE_BYTES)
	 *   - SW area: 9 words (36 bytes)
	 */
	{
		const size_t need_seed = (size_t)FIBER_EXC_PER_LEVEL
				+ (size_t)FIBER_EXC_BASE_BYTES
				+ (size_t)(9u * 4u);
		FIBER_REQUIRE(ctx->boot.avail >= need_seed, 'Z');
	}

#if defined(FIBER_STACK_CANARY) && !FIBER_HAS_PSPLIM
	/* Write a canary at the low PSP bound if PSPLIM is unavailable on this core. */
	{
		const uintptr_t canary_cell = fiber_word_align_up((uintptr_t)ctx->boot.begin);
		((volatile uint32_t*)canary_cell)[0] = FIBER_CANARY_VALUE;
		{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
	}
#endif

/* ------ Reserve one HW frame headroom above (protects first EXC return) ------ */
	uint32_t* sp = (uint32_t*)(ctx->boot.stack_top - (uintptr_t)FIBER_EXC_PER_LEVEL);

	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }

	/* -------------------- Hardware frame (8 words) -------------------- */
	*(--sp) = xpsr_T();                                       /* xPSR: T-bit set */
	*(--sp) = fiber_stacked_pc(entry);                        /* PC: task entry; xPSR.T selects Thumb */
	*(--sp) = ((uint32_t)(uintptr_t)&fiber_task_return) | 1u; /* LR: if task returns, trap into WFI loop */
	*(--sp) = 0; /* R12 */
	*(--sp) = 0; /* R3  */
	*(--sp) = 0; /* R2  */
	*(--sp) = 0; /* R1  */
	*(--sp) = (uint32_t)(uintptr_t)arg;                       /* R0: task argument */

	/* -------------------- Software-saved area (callee-saved + EXC_RETURN) -------------------- */
#if FIBER_PORT_IS_BASELINE
	/* M0/M23 memory (low to high): [LR][r8..r11][r4..r7] */
	*(--sp) = 0;               /* r7 */
	*(--sp) = 0;               /* r6 */
	*(--sp) = 0;               /* r5 */
	*(--sp) = 0;               /* r4 */
	*(--sp) = 0;               /* r11 */
	*(--sp) = 0;               /* r10 */
	*(--sp) = fiber_read_r9(); /* r9  (seed SB base) */
	*(--sp) = 0;               /* r8  */
	*(--sp) = FIBER_INITIAL_EXC_RETURN; /* LR(EXC_RETURN): Thread via PSP, no FP frame */
#else
	/* M3/M4/M7/M33 memory (low to high): [r4..r11][LR] */
	*(--sp) = FIBER_INITIAL_EXC_RETURN; /* LR(EXC_RETURN): Thread via PSP, no FP frame */
	*(--sp) = 0;               /* r11 */
	*(--sp) = 0;               /* r10 */
	*(--sp) = fiber_read_r9(); /* r9  (seed SB base) */
	*(--sp) = 0;               /* r8  */
	*(--sp) = 0;               /* r7 */
	*(--sp) = 0;               /* r6 */
	*(--sp) = 0;               /* r5 */
	*(--sp) = 0;               /* r4 */
#endif

	ctx->sp = sp;

	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }

	/* Intentionally expect sp % 8 == 4 after placing SW area.
	 * After removing SW area in PendSV, PSP will be 8-byte aligned exactly at HW frame. */
	FIBER_REQUIRE((((uintptr_t)ctx->sp) & 7u) == 4u, 'A');

	/* Ensure PSP is inside declared PSP region [stack_base, stack_top - HW_headroom] */
	FIBER_REQUIRE((uintptr_t)ctx->sp >= ctx->boot.stack_base, 'U');
	FIBER_REQUIRE((uintptr_t)ctx->sp <= ctx->boot.stack_top - (uintptr_t)FIBER_EXC_PER_LEVEL, 'S');

	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
}

FiberContext* fiber_current(void)
{
	return fiber_port_load_current_context();
}

FIBER_NORETURN
void fiber_start(FiberContext* const ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'C');
	FIBER_REQUIRE(ctx->boot.sealed != 0u, 's');

	fiber_port_seed_current_context(ctx);

	fiber_boot(&ctx->boot);
	FIBER_UNREACHABLE();
}

void fiber_yield_to(FiberContext* const to)
{
	FiberContext* const from = fiber_current();

	FIBER_REQUIRE(from != NULL, 'G');
	fiber_switch(from, to);
}

/* --------------------------------------------------------------------------
 * fiber_switch: robust cooperative trigger
 *
 * Goals:
 *  - Reject NULL 'from' in the public API
 *  - No-op when 'to' is NULL or 'to' == 'from'
 *  - Write ordering: source slot must be visible before target slot becomes visible
 *  - Pend PendSV only after both slots are published
 *  - Optional IRQ masking while publishing slots (universal across M0..M33)
 *  - Keep barriers conservative to avoid reordering surprises
 * -------------------------------------------------------------------------- */

#ifndef FIBER_SWITCH_MASK_IRQS
/* 0 = do not touch PRIMASK; 1 = mask IRQs during slot update */
# define FIBER_SWITCH_MASK_IRQS 1
#endif

#if FIBER_SWITCH_MASK_IRQS
static inline uint32_t fiber_primask_save_disable_local(void)
{
	uint32_t pm;
	__ASM volatile(
			"mrs %0, primask \n"
			"cpsid i         \n"
			: "=r"(pm)
			:
			: "memory");
	{ __DSB(); __ISB(); }
	return pm;
}

static inline void fiber_primask_restore_local(uint32_t pm)
{
	{ __DSB(); __ISB(); }
	__ASM volatile("msr primask, %0" :: "r"(pm) : "memory");
	{ __DSB(); __ISB(); }
}
#endif

void fiber_switch(FiberContext* const from, FiberContext* const to)
{
	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');  /* fiber_switch is a Thread-mode API */
	FIBER_REQUIRE(from != NULL, 'F');        /* public API requires a source context */

	/* Fast no-op: nothing to switch or self-switch requested */
	if (!to || to == from) {
		__COMPILER_BARRIER();
		return;
	}

	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p'); /* do not defer the switch out of a masked region */
#if FIBER_HAS_BASEPRI
	FIBER_REQUIRE(__get_BASEPRI() == 0u, 'b'); /* do not let priority masking defer PendSV */
#endif

#if FIBER_VALIDATE_CURRENT
	{
		FiberContext* const current = fiber_current();

		if (current != NULL) {
			FIBER_REQUIRE(current == from, 'G');
		}
	}
#endif

#if FIBER_SWITCH_MASK_IRQS
	const uint32_t pm = fiber_primask_save_disable_local();
#endif

	/* Publish source before target so PendSV cannot see a target without a source. */
	fiber_port_publish_switch_slots(from, to);

	/* Pend PendSV after slots are visible. Strongly ordered afterwards. */
	fiber_port_pend_switch();

#if FIBER_SWITCH_MASK_IRQS
	fiber_primask_restore_local(pm);
#else
	{ __DSB(); __ISB(); }    /* serialize before potential immediate tail-chaining */
#endif
}




/* --------- PendSV: FreeRTOS pattern + PSPLIM update on v8-M ---------
 * Every line is commented to make instruction intent obvious during audits.
 */

/* Safe constant for "to->boot.stack_base" offset in ASM (avoid nested-designator offsetof) */
enum {
	OFF_TO_PSLIM = offsetof(FiberContext, boot) + offsetof(FiberBoot, stack_base)
};

BT_STATIC_ASSERT(OFF_TO_PSLIM < 4096, "OFF_TO_PSLIM must fit Thumb-2 LDR imm12");

#if !FIBER_PORT_ARMV7EM
FIBER_ATTR_NAKED_ASM
void fiber_pendsv(void)
{
#if FIBER_PORT_IS_BASELINE
	/* ------------------------ Cortex-M0/M0+ / v8-M Baseline ------------------------ */
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
			"isb                                    \n" /* sync pipeline before touching stack memory */

			/* ----------------------------------------------------------------------
			 * Load exchange pointers and early exit if no target
			 * ---------------------------------------------------------------------- */
			"ldr   r2, =fiber_internal_port_switch_to_slot \n" /* r2 = &target slot */
			"ldr   r2, [r2]                         \n" /* r2 = target context */
			"cmp   r2, #0                           \n" /* Thumb-1 safe null check */
			"beq   5f                               \n" /* if no target, nothing to do: return */

			"ldr   r1, =fiber_internal_port_switch_from_slot \n" /* r1 = &source slot */
			"ldr   r1, [r1]                         \n" /* r1 = source context */

			/* ----------------------------------------------------------------------
			 * Save current context (only if source slot is not NULL)
			 * SW layout low->high: [LR][r8..r11][r4..r7]
			 * ARMv6-M lacks STMDB, so do manual pre-decrement + STMIA.
			 * ---------------------------------------------------------------------- */
			"cmp   r1, #0                           \n" /* Thumb-1 safe null check */
			"beq   1f                               \n" /* if from == NULL skip saving */

			/* Reserve SW area (9 words = 36 bytes): [LR][r8..r11][r4..r7] */
			"subs  r0, #36                          \n" /* r0 = base of SW area */

			/* Save LR(EXC_RETURN) at [base+0]. Thumb-1 cannot STR LR directly. */
			"mov   r3, lr                           \n"
			"str   r3, [r0]                         \n"

			/* Save r4..r7 at [base+20] */
			"mov   r3, r0                           \n"
			"adds  r3, #20                          \n"
			"stmia r3!, {r4-r7}                     \n" /* r0 untouched */

			/* Stage and save r8..r11 at [base+4] */
			"mov   r4, r8                           \n"
			"mov   r5, r9                           \n"
			"mov   r6, r10                          \n"
			"mov   r7, r11                          \n"
			"mov   r3, r0                           \n"
			"adds  r3, #4                           \n"
			"stmia r3!, {r4-r7}                     \n" /* r3 now points to [base+20] */

			/* from->sp = base (bottom of SW area) */
			"str   r0, [r1]                         \n"

			"1:                                     \n" /* label: skip-save */

			/* ----------------------------------------------------------------------
			 * Load target SW area: [LR][r8..r11][r4..r7]
			 * ---------------------------------------------------------------------- */
			"ldr   r0, [r2]                         \n" /* r0 = to->sp (base) */
			"ldr   r3, [r0]                         \n" /* r3 = saved EXC_RETURN */
			"mov   lr, r3                           \n" /* LR = saved EXC_RETURN */

			/* r3 := base+4; load staged r8..r11 into r4..r7, then move back to r8..r11 */
			"mov   r3, r0                           \n"
			"adds  r3, #4                           \n"
			"ldmia r3!, {r4-r7}                     \n"
			"mov   r8,  r4                          \n"
			"mov   r9,  r5                          \n"
			"mov   r10, r6                          \n"
			"mov   r11, r7                          \n"

			/* Now r3 == base+20; load real r4..r7; after this r3 == base+36 (HW frame) */
			"ldmia r3!, {r4-r7}                     \n"

			/* ----------------------------------------------------------------------
			 * Program PSP for target HW frame and clean exchange slots.
			 * This generic baseline path does not program PSPLIM; M23
			 * PSPLIM/security variants are not validated yet.
			 * ---------------------------------------------------------------------- */
			"str   r3, [r2]                         \n" /* to->sp = HW frame */
			"msr   psp, r3                          \n" /* PSP := start of HW frame for 'to' */
			"isb                                    \n" /* sync before exception return */

			/* Publish the runtime-owned current context, FreeRTOS pxCurrentTCB style. */
			"ldr   r1, =fiber_internal_port_current_context \n" /* r1 = &current context */
			"str   r2, [r1]                         \n" /* current context = to */

			/* Clear exchange slots for hygiene/diagnostics */
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
			 * Return from exception using EXC_RETURN in LR
			 * ---------------------------------------------------------------------- */
			"bx    lr                               \n" /* exception return */

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
#else
	/* ------------------------ Non-ARMv7E-M Mainline fallback ---------------------- */
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

#if FIBER_HAS_PSPLIM
			/* ----------------------------------------------------------------------
			 * Program PSPLIM on v8-M Mainline (protect PSP lower bound)
			 * ---------------------------------------------------------------------- */
			"ldr   r3, [r2, %c[offsb]]              \n" /* r3 = to->boot.stack_base */
			FBR_ASM_MSR_PSPLIM("r3")                    /* write PSPLIM */
			"dsb                                    \n" /* ensure memory effects complete */
			"isb                                    \n" /* synchronize pipeline */
#endif /* FIBER_HAS_PSPLIM */

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
			: [offsb] "I" (OFF_TO_PSLIM)
			  : "memory","cc"
	);
#endif

}
#endif /* !FIBER_PORT_ARMV7EM */

#ifndef FIBER_PENDSV_WIRED
FIBER_DIAG_WARN("[fiber]: user must wire PendSV_Handler to call fiber_pendsv(); define FIBER_PENDSV_WIRED=1 after you do it");
#endif /* FIBER_PENDSV_WIRED */

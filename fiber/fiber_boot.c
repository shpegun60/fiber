/*
 * fiber_boot.c
 *
 * Minimal, universal PSP boot helpers for STM32 Cortex-M (bare-metal).
 * - Naked trampoline to switch Thread mode to PSP and tail-call entry.
 * - Paranoid context builder and checker with red-zone & PSPLIM accounting.
 * - Platform bootstrap: faults/STKALIGN/unaligned/div0/FPU/TrustZone.
 * - Environment precondition check (Thread, privileged, MSP selected).
 * - Final boot from a sealed FiberBoot (never returns).
 *
 * No RTOS coexistence. If you call this under an RTOS, you own the crash.
 *
 * Arch support notes:
 * - ARMv6-M (Cortex-M0/M0+): PSP present; CONTROL.SPSEL works; no PSPLIM; no Mem/Bus/Usage faults; no FPU.
 * - ARMv7-M / ARMv7E-M: PSP present; optional FPU; no PSPLIM.
 * - ARMv8-M Mainline: PSP + policy-gated PSPLIM; TrustZone runtime is gated
 *   until a full FreeRTOS-style security-domain context layout is implemented.
 */

#include "fiber_boot.h"
#include "port/fiber_port_boot_record.h"

#ifndef FIBER_HAS_FAULTMASK
# if defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7EM__) \
		|| defined(__ARM_ARCH_8M_MAIN__) || defined(__ARM_ARCH_8_1M_MAIN__)
#  define FIBER_HAS_FAULTMASK 1
# else
#  define FIBER_HAS_FAULTMASK 0
# endif
#endif

/* -------------------------------------------------------------------------- 	*/
/* Weak defaults for platform hooks (app may override)                         	*/
/* -------------------------------------------------------------------------- 	*/
FIBER_WEAK int fiber_addr_plausible_ram(uintptr_t start, uintptr_t end) {
	(void)start; (void)end; return 1; /* accept any RAM range by default */
}

FIBER_WEAK int fiber_addr_plausible_code(uintptr_t addr) {
	(void)addr; return 1;             /* accept any code address by default */
}

FIBER_WEAK uintptr_t fiber_fallback_initial_msp(void) {
	return (uintptr_t)0;              /* default: no usable fallback */
}

#if FIBER_HAS_FPU && FIBER_BOOT_CLEAR_FPCA
# define FIBER_BOOT_CLEAR_FPCA_ASM \
			"movs  r5, #4              \n"  /* mask for CONTROL.FPCA                  */ \
			"bics  r3, r5              \n"  /* clear FPCA before first fiber entry    */
# define FIBER_BOOT_VERIFY_FPCA_CLEAR_ASM \
			"movs  r5, #4              \n"  /* mask for CONTROL.FPCA                  */ \
			"tst   r4, r5              \n"  /* FPCA must be clear after CONTROL write */ \
			"bne   9f                  \n"
#else
# define FIBER_BOOT_CLEAR_FPCA_ASM
# define FIBER_BOOT_VERIFY_FPCA_CLEAR_ASM
#endif

/* -----------------------------------------------------------------------------*/
/* Naked trampoline: atomically switch Thread to PSP and branch to entry(arg).	*/
/* Never returns. M0-safe (Thumb-1 only where required).                      	*/
/*                                                                            	*/
/* Register contract on entry:                                                	*/
/*   r0: psp_top  - target PSP top (8-byte aligned by caller)                 	*/
/*   r1: entry    - entry function (Thumb, must not return)                   	*/
/*   r2: arg      - argument passed to entry(arg)                              	*/
/*   r3: msp_top  - optional new MSP top; if 0, MSP is left unchanged         	*/
/* -----------------------------------------------------------------------------*/
static FIBER_NORETURN FIBER_ATTR_NAKED_ASM
void fiber_boot_trampoline(void* psp_top, entry_t entry, void* arg, void* msp_top)
{
	__ASM volatile(
			".syntax unified          \n"
			/* ---------------------------------------------------------------------- 	*/
			/* Save & mask IRQs                                                       	*/
			/* ---------------------------------------------------------------------- 	*/
			"mrs   r12, PRIMASK        \n"  /* save current IRQ mask into r12         	*/
			"cpsid i                   \n"  /* mask IRQs (NMI/HardFault stay enabled) 	*/
			/* ---------------------------------------------------------------------- 	*/
			"dsb                       \n"  /* complete prior explicit memory accesses 	*/
			"isb                       \n"  /* synchronize pipeline; ultra-conservative here */

			/* ---------------------------------------------------------------------- 	*/
			/* Program PSP                                                            	*/
			/* ---------------------------------------------------------------------- 	*/
			"lsrs  r0, r0, #3          \n"  /* align psp_top down to 8 bytes: r0 >>= 3 	*/
			"lsls  r0, r0, #3          \n"  /* restore magnitude with low 3 bits = 0   	*/
			"msr   psp, r0             \n"  /* PSP = r0 (new process stack pointer)    	*/
			"isb                       \n"  /* ensure PSP write takes effect before read-back (required before dependent reads) */
			/* read-back PSP into r4 and verify */
			"mrs   r4, psp             \n"
			"cmp   r4, r0              \n"
			"bne   9f                  \n"  /* if PSP didn't take the value, go to fatal path */
			/* ---------------------------------------------------------------------- 	*/
			"dsb                       \n"  /* complete prior explicit memory accesses 	*/
			"isb                       \n"  /* synchronize pipeline; ultra-conservative here */

			/* ---------------------------------------------------------------------- 	*/
			/* Optionally set MSP if msp_top != 0                                     	*/
			/* ---------------------------------------------------------------------- 	*/
			"cmp   r3, #0              \n"  /* msp_top provided? compare r3 with 0     	*/
			"beq   1f                  \n"  /* if r3 == 0, skip MSP update             	*/
			"lsrs  r3, r3, #3          \n"  /* align msp_top down to 8 bytes: r3 >>= 3 	*/
			"lsls  r3, r3, #3          \n"  /* restore magnitude with low 3 bits = 0   	*/
			"msr   msp, r3             \n"  /* MSP = r3 (new main stack for handlers)  	*/
			"isb                       \n"  /* ensure MSP write takes effect before read-back */
			/* read-back MSP into r4 and verify */
			"mrs   r4, msp             \n"
			"cmp   r4, r3              \n"
			"bne   9f                  \n"  /* mismatch means we refuse to proceed safely */
			"1:                        \n"  /* label: fall through (no MSP change)     	*/
			/* ---------------------------------------------------------------------- 	*/
			"dsb                       \n"  /* complete prior explicit memory accesses 	*/
			"isb                       \n"  /* synchronize pipeline; ultra-conservative here */

			/* ---------------------------------------------------------------------- 	*/
			/* Select PSP for Thread mode                                             	*/
			/* ---------------------------------------------------------------------- 	*/
			"mrs   r3, control         \n"  /* r3 = CONTROL                             */
			FIBER_BOOT_CLEAR_FPCA_ASM
			"movs  r5, #2              \n"  /* mask for SPSEL                           */
			"orrs  r3, r5              \n"  /* set CONTROL.SPSEL (bit1) -> use PSP (Thumb-1 safe) */
			"msr   control, r3         \n"  /* write CONTROL with SPSEL=1               */
			"isb                       \n"  /* make SPSEL change visible before verification (architecturally required) */
			/* verify SPSEL==1 */
			"mrs   r4, control         \n"
			FIBER_BOOT_VERIFY_FPCA_CLEAR_ASM
			"movs  r5, #2              \n"
			"tst   r4, r5              \n"
			"beq   9f                  \n"  /* if SPSEL didn't latch, fail hard         */
			/* ---------------------------------------------------------------------- 	*/
			"dsb                       \n"  /* complete prior explicit memory accesses 	*/
			"isb                       \n"  /* synchronize pipeline; ultra-conservative here */

			/* ---------------------------------------------------------------------- 	*/
			/* Safety: if entry() ever returns, fault deterministically                	*/
			/* ---------------------------------------------------------------------- 	*/
			"movs  r3, #0              \n"  /* M0/M0+: no MOV imm to LR; zero r3 first  */
			"mov   lr, r3              \n"  /* LR = 0 (Thumb bit cleared) => INVSTATE   */
			/* returning via BX LR will cause INVSTATE/HardFault */
			/* ---------------------------------------------------------------------- 	*/
			"dsb                       \n"  /* complete prior explicit memory accesses 	*/
			"isb                       \n"  /* synchronize pipeline; ultra-conservative here */

			/* ---------------------------------------------------------------------- 	*/
			/* r0 = arg                                    								*/
			/* ---------------------------------------------------------------------- 	*/
			"mov   r0, r2              \n"  /* r0 = arg (ABI: first argument in r0)    	*/
			/* ---------------------------------------------------------------------- 	*/
			"dsb                       \n"  /* complete prior explicit memory accesses 	*/
			"isb                       \n"  /* synchronize pipeline; ultra-conservative here */

			/* ---------------------------------------------------------------------- 	*/
			/* Restore IRQ mask                                                       	*/
			/* ---------------------------------------------------------------------- 	*/
			"msr   PRIMASK, r12        \n"  /* restore saved PRIMASK (may unmask IRQs) 	*/
			/* ---------------------------------------------------------------------- 	*/
			"dsb                       \n"  /* complete prior explicit memory accesses 	*/
			"isb                       \n"  /* synchronize pipeline; ultra-conservative here */

			/* ---------------------------------------------------------------------- 	*/
			/* Tail-call entry(arg) - never returns                                    	*/
			/* ---------------------------------------------------------------------- 	*/
			"bx    r1                  \n"  /* branch to entry (Thumb), never returns  	*/

			/* Fatal path: make a UsageFault and park */
			"9:                        \n"
			/* ---------------------------------------------------------------------- 	*/
			"dsb                       \n"  /* complete prior explicit memory accesses 	*/
			"isb                       \n"  /* synchronize pipeline; ultra-conservative here */
			/* ---------------------------------------------------------------------- 	*/
			"bkpt  0                   \n"  /* breakpoint; outside the debugger usually HardFault */
			"b     9b                  \n"  /* spin forever in the fault path (won't return) */

			:
			:
			: "r0","r1","r2","r3","r4","r5","r12","lr","cc","memory"
	);
}

/* -------------------------------------------------------------------------- */
/* Fault hygiene: clear "sticky" status where present (v7-M/v7E-M/v8-M Main). */
/* Use read-then-write (W1C) to avoid leftovers from a previous session.      */
/* -------------------------------------------------------------------------- */
static inline void fiber_clear_sticky_faults(void)
{
#if defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7EM__) || defined(__ARM_ARCH_8M_MAIN__)
	/* CFSR: Configurable Fault Status Register (W1C). */
	const volatile uint32_t cfsr = SCB->CFSR;   /* read current sticky bits */
	SCB->CFSR = cfsr;                  			/* write back one bits to clear them */

	/* HFSR: Hard Fault Status Register (W1C). */
	const volatile uint32_t hfsr = SCB->HFSR;
	SCB->HFSR = hfsr;

	/* DFSR: Debug Fault Status Register (W1C). Some CMSIS expose bit masks, some do not. */
# if defined(SCB_DFSR_EXTERNAL_Msk) || defined(SCB_DFSR_BKPT_Msk) || 		\
		defined(SCB_DFSR_DWTTRAP_Msk)  || defined(SCB_DFSR_VCATCH_Msk) || 	\
		defined(SCB_DFSR_HALTED_Msk)
	const volatile uint32_t dfsr = SCB->DFSR;
	SCB->DFSR = dfsr;
# else
	SCB->DFSR = 0x1Fu;                 		/* clear all standard DFSR bits if masks are missing */
# endif

	{ __DSB(); __ISB(); }                  	/* serialize side effects of status clears */
#else
	(void)0;                            	/* v6-M may lack these regs: nothing to do */
#endif
}

/* -------------------------------------------------------------------------- */
/* Platform bootstrap: enable faults, enforce STKALIGN, UB traps, FPU policy. */
/* Idempotent and safe to call multiple times at boot.                        */
/* -------------------------------------------------------------------------- */
void fiber_platform_bootstrap(void)
{
	fiber_clear_sticky_faults();

	/* Let Mem/Bus/Usage faults fire (where available) to catch programming errors early. */
#if defined(SCB_SHCSR_MEMFAULTENA_Msk) || defined(SCB_SHCSR_BUSFAULTENA_Msk) || defined(SCB_SHCSR_USGFAULTENA_Msk)
	SCB->SHCSR |=
# ifdef SCB_SHCSR_MEMFAULTENA_Msk
			SCB_SHCSR_MEMFAULTENA_Msk |
# endif
# ifdef SCB_SHCSR_BUSFAULTENA_Msk
			SCB_SHCSR_BUSFAULTENA_Msk |
# endif
# ifdef SCB_SHCSR_USGFAULTENA_Msk
			SCB_SHCSR_USGFAULTENA_Msk
# else
			0u
# endif
			;

	{ __DSB(); __ISB(); }
#endif

	/* Keep exception frames 8-byte aligned as per ARM ABI. */
#ifdef SCB_CCR_STKALIGN_Msk
	SCB->CCR |= SCB_CCR_STKALIGN_Msk;
	{ __DSB(); __ISB(); }
#endif

	/* Optionally trap unaligned accesses and division-by-zero to surface UB early. */
#if defined(SCB_CCR_UNALIGN_TRP_Msk) && FIBER_ENABLE_UNALIGNED_TRAP
	SCB->CCR |= SCB_CCR_UNALIGN_TRP_Msk;
	{ __DSB(); __ISB(); }
#endif
#if defined(SCB_CCR_DIV_0_TRP_Msk) && FIBER_ENABLE_DIV0_TRAP
	SCB->CCR |= SCB_CCR_DIV_0_TRP_Msk;
	{ __DSB(); __ISB(); }
#endif

#if defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7EM__) \
 || defined(__ARM_ARCH_8M_MAIN__) || defined(__ARM_ARCH_8_1M_MAIN__)
    __set_BASEPRI(0);
    { __DSB(); __ISB(); }
#endif /* BASEPRI */

#if FIBER_HAS_FAULTMASK
	__set_FAULTMASK(0);
	{ __DSB(); __ISB(); }
#endif /* FAULTMASK */

	/* Optionally enable FPU access (CP10/CP11) if an FPU exists and the build may emit FP instructions.	 */
	fiber_fpu_enable_early();
}

uintptr_t fiber_boot_prepare_msp_for_start(const FiberBoot* const ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'n');
	fiber_boot_check(ctx);

	if (ctx->msp_policy == FIBER_MSP_POLICY_REWIND) {
		uint32_t ra = fiber_read_initial_msp();
		__ISB();
		uint32_t rb = fiber_read_initial_msp();

		if ((ra == 0u) || (ra != rb)) {
			const uintptr_t fb = fiber_fallback_initial_msp();
			FIBER_REQUIRE(fb != 0u, 'f');
			ra = (uint32_t)fb;
			rb = (uint32_t)fb;
		}

		const uintptr_t expected = fiber_stack_align_down((uintptr_t)ra);
		FIBER_REQUIRE(expected == ctx->msp_top, 'W');
		FIBER_REQUIRE(ctx->msp_top != 0u, 'M');
		{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
		return ctx->msp_top;
	}

	const uintptr_t cur_msp = fiber_stack_align_down((uintptr_t)__get_MSP());
	FIBER_REQUIRE(cur_msp == ctx->msp_top, 'K');
	FIBER_REQUIRE(!(cur_msp > ctx->stack_base && cur_msp <= ctx->stack_top), 'o');
	{
		const size_t gap = (cur_msp > ctx->stack_top)
							 ? (size_t)(cur_msp - ctx->stack_top)
									 : (size_t)(ctx->stack_base - cur_msp);
		FIBER_REQUIRE(gap >= (size_t)FIBER_STACK_REDZONE_BYTES, 'g');
	}

	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
	return 0u;
}

static uint32_t fiber_boot_hash32_accum(uint32_t h, uint32_t v)
{
	h ^= (uint8_t)(v);
	h *= 16777619u;
	h ^= (uint8_t)(v >> 8);
	h *= 16777619u;
	h ^= (uint8_t)(v >> 16);
	h *= 16777619u;
	h ^= (uint8_t)(v >> 24);
	h *= 16777619u;
	return h;
}

uint32_t fiber_port_boot_compute_hash(const FiberBoot *c)
{
	/* Hash invariant fields only. Do not include sealed or hash itself. */
	uint32_t h = 2166136261u;

	h = fiber_boot_hash32_accum(h, (uint32_t)(uintptr_t)c->begin);
	h = fiber_boot_hash32_accum(h, (uint32_t)(uintptr_t)c->end);
	h = fiber_boot_hash32_accum(h, (uint32_t)c->stack_base);
	h = fiber_boot_hash32_accum(h, (uint32_t)c->stack_top);
	h = fiber_boot_hash32_accum(h, (uint32_t)c->avail);
	h = fiber_boot_hash32_accum(h, (uint32_t)(uintptr_t)c->entry);
	h = fiber_boot_hash32_accum(h, (uint32_t)(uintptr_t)c->arg);
	h = fiber_boot_hash32_accum(h, (uint32_t)c->msp_policy);
	h = fiber_boot_hash32_accum(h, (uint32_t)c->msp_top);
	h = fiber_boot_hash32_accum(h, (uint32_t)c->magic);
	h = fiber_boot_hash32_accum(h, (uint32_t)c->version);
	h = fiber_boot_hash32_accum(h, (uint32_t)c->guard_lo);
	h = fiber_boot_hash32_accum(h, (uint32_t)c->guard_hi);
	return h;
}

void fiber_port_boot_record_fast_check(const FiberBoot *ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'n');
	FIBER_REQUIRE(ctx->magic == FIBER_BOOT_RECORD_MAGIC, 'm');
	FIBER_REQUIRE(ctx->version == FIBER_BOOT_RECORD_VERSION, 'v');
	FIBER_REQUIRE(ctx->guard_lo == FIBER_BOOT_RECORD_GUARD_LO, 'g');
	FIBER_REQUIRE(ctx->guard_hi == FIBER_BOOT_RECORD_GUARD_HI, 'G');
	FIBER_REQUIRE(ctx->sealed == 1u, 's');
}

void fiber_port_boot_record_check(const FiberBoot *ctx)
{
	fiber_port_boot_record_fast_check(ctx);
	FIBER_REQUIRE(ctx->hash == fiber_port_boot_compute_hash(ctx), 'h');
}


/* -------------------------------------------------------------------------- */
/* MSP planning (called by constructor)                                       */
/* - For REWIND: read VTOR[0] twice (stability), else require fallback.       */
/* - For VALIDATE: snapshot current MSP.                                      */
/* Both paths: plausibility, non-overlap, minimum gap to PSP.                 */
/* -------------------------------------------------------------------------- */
static void fiber_plan_msp(FiberBoot* const ctx)
{
#if FIBER_REWIND_MSP
	ctx->msp_policy = FIBER_MSP_POLICY_REWIND;

	uint32_t msp0a = fiber_read_initial_msp();
	__ISB();
	uint32_t msp0b = fiber_read_initial_msp();

	if ((msp0a == 0u) || (msp0a != msp0b)) {
		const uintptr_t fb = fiber_fallback_initial_msp();  /* fallback must provide non-zero MSP */
		FIBER_REQUIRE(fb != 0u, 'f');
		msp0a = (uint32_t)fb;
		msp0b = (uint32_t)fb;
	}
	FIBER_REQUIRE(msp0a == msp0b, 'V');

	ctx->msp_top = fiber_stack_align_down((uintptr_t)msp0a);
#else
	ctx->msp_policy = FIBER_MSP_POLICY_VALIDATE;
	ctx->msp_top    = fiber_stack_align_down((uintptr_t)__get_MSP());
#endif

	FIBER_REQUIRE(ctx->msp_top != 0u, 'M');

	/* MSP must look like RAM. Use [max(msp-4, msp)..msp] slice to avoid underflow. */
	{
		const uintptr_t chk = (ctx->msp_top >= 4u) ? (ctx->msp_top - 4u) : ctx->msp_top;
		FIBER_REQUIRE(fiber_addr_plausible_ram(chk, ctx->msp_top) != 0, 'R');
	}

	/* No overlap with PSP region [stack_base..stack_top]. */
	FIBER_REQUIRE(!(ctx->msp_top > ctx->stack_base && ctx->msp_top <= ctx->stack_top),
			(ctx->msp_policy == FIBER_MSP_POLICY_REWIND) ? 'O' : 'o');

	/* Minimum gap MSP<->PSP at least red-zone. */
	{
		const size_t gap = (ctx->msp_top > ctx->stack_top)
							 ? (size_t)(ctx->msp_top - ctx->stack_top)
									 : (size_t)(ctx->stack_base - ctx->msp_top);

		FIBER_REQUIRE(gap >= (size_t)FIBER_STACK_REDZONE_BYTES,
				(ctx->msp_policy == FIBER_MSP_POLICY_REWIND) ? 'G' : 'g');
	}
}

/* -------------------------------------------------------------------------- */
/* Constructor                                                                */
/* -------------------------------------------------------------------------- */
FiberBoot fiber_create_boot(void* const begin, void* const end, const entry_t entry, void* const arg)
{
	FiberBoot ctx = (FiberBoot){0};
	/* ------------------------------------------------------------------ *
	 * Contract checks (raw inputs)                                		  *
	 * ------------------------------------------------------------------ */
	{
		{ __DSB(); __ISB(); __COMPILER_BARRIER(); }

		FIBER_REQUIRE(begin  != NULL, 'B');
		FIBER_REQUIRE(end    != NULL, 'T');
		FIBER_REQUIRE(entry  != NULL, 'E');
		FIBER_REQUIRE(end > begin,    'N'); /* non-empty raw range */
	}

	/* ------------------------------------------------------------------ *
	 * Entry function sanity                                              *
	 * ------------------------------------------------------------------ */
	{
		const uintptr_t entry_addr = (uintptr_t)entry;
		FIBER_REQUIRE((entry_addr & 1u) == 1u, 'e'); /* must be Thumb (bit0=1) */
		FIBER_REQUIRE(fiber_addr_plausible_code(entry_addr & ~(uintptr_t)1u) != 0, 'c');

		/* Write derived fields */
		ctx.entry = entry;
		ctx.arg   = arg;
		{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
	}

	/* Normalize and compute PSP bounds */
	{
		const uintptr_t base_raw  = (uintptr_t)begin;
		const uintptr_t top_raw   = (uintptr_t)end;
		const uintptr_t base_word = fiber_word_align_up(base_raw);

		FIBER_REQUIRE(base_word <= (UINTPTR_MAX - (uintptr_t)FIBER_STACK_REDZONE_BYTES), 'o');

		const uintptr_t after_red   	= base_word + (uintptr_t)FIBER_STACK_REDZONE_BYTES;
		const uintptr_t base_aligned	= fiber_stack_align_up(after_red);   /* PSPLIM / lower PSP bound */
		const uintptr_t top_aligned 	= fiber_stack_align_down(top_raw);   /* SP start */

		FIBER_REQUIRE(base_aligned >= base_raw, 'r');
		FIBER_REQUIRE(top_aligned  >  base_aligned, 'h');
		FIBER_REQUIRE(base_aligned >= base_word, 'w');
		FIBER_REQUIRE(top_aligned  <= top_raw,   't');

		FIBER_REQUIRE((base_aligned % FIBER_STACK_ALIGN) == 0u, 'A');
		FIBER_REQUIRE((top_aligned  % FIBER_STACK_ALIGN) == 0u, 'A');

		/* ------------------------------------------------------------------ *
		 * Region plausibility and minimum sizing                             *
		 * ------------------------------------------------------------------ */

		/* Application-defined plausibility of the PSP region itself. */
		FIBER_REQUIRE(fiber_addr_plausible_ram(base_aligned, top_aligned) != 0, 'P');

		/* Exactly one exception frame on PSP + extra prologue margin. */
		const size_t need  = (size_t)FIBER_STACK_WITHOUT_REDZONE;
		const size_t avail = (size_t)(top_aligned - base_aligned);
		FIBER_REQUIRE(avail >= need, 'H');

		/* Write derived fields */
		ctx.begin      = begin;
		ctx.end        = end;
		ctx.stack_base = base_aligned;
		ctx.stack_top  = top_aligned;
		ctx.avail      = avail;
		{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
	}

	/* MSP policy planning + checks (same semantics as runtime path) */
	fiber_plan_msp(&ctx);

	/* Seal with metadata (magic/version/canaries/hash) */
	ctx.magic    = FIBER_BOOT_RECORD_MAGIC;
	ctx.version  = FIBER_BOOT_RECORD_VERSION;
	ctx.sealed   = 0u;                /* not sealed until hash is set */
	ctx.guard_lo = FIBER_BOOT_RECORD_GUARD_LO;
	ctx.guard_hi = FIBER_BOOT_RECORD_GUARD_HI;
	ctx.hash     = 0u;

	ctx.hash   = fiber_port_boot_compute_hash(&ctx);
	ctx.sealed = 1u;

	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }

	fiber_boot_check(&ctx);
	return ctx;
}

/* -------------------------------------------------------------------------- */
/* Context validator (paranoid)                                               */
/* -------------------------------------------------------------------------- */
void fiber_boot_check(const FiberBoot* const ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'n');

	/* Integrity header */
	fiber_boot_simple_check(ctx);

	/* Payload presence */
	FIBER_REQUIRE(ctx->begin != NULL, 'B');
	FIBER_REQUIRE(ctx->end   != NULL, 'T');
	FIBER_REQUIRE(ctx->entry != NULL, 'E');
	FIBER_REQUIRE(ctx->end > ctx->begin, 'N');

	FIBER_REQUIRE(ctx->stack_base > 0u, 'b');
	FIBER_REQUIRE(ctx->stack_top  > 0u, 't');
	FIBER_REQUIRE(ctx->avail      > 0u, 'a');

	/* Entry sanity */
	{
		const uintptr_t entry_addr = (uintptr_t)ctx->entry;
		FIBER_REQUIRE((entry_addr & 1u) == 1u, 'e'); /* Thumb */
		FIBER_REQUIRE(fiber_addr_plausible_code(entry_addr & ~(uintptr_t)1u) != 0, 'c');
	}

	/* PSP structural invariants */
	{
		const uintptr_t base_raw  = (uintptr_t)ctx->begin;
		const uintptr_t top_raw   = (uintptr_t)ctx->end;
		const uintptr_t base_word = fiber_word_align_up(base_raw);

		FIBER_REQUIRE(base_word <= (UINTPTR_MAX - (uintptr_t)FIBER_STACK_REDZONE_BYTES), 'o');
		const uintptr_t after_red   = base_word + (uintptr_t)FIBER_STACK_REDZONE_BYTES;
		const uintptr_t min_base    = fiber_stack_align_up(after_red);
		const uintptr_t max_top     = fiber_stack_align_down(top_raw);

		FIBER_REQUIRE(ctx->stack_base >= base_raw, 'R');
		FIBER_REQUIRE(ctx->stack_top  <= top_raw,  'T');
		FIBER_REQUIRE(ctx->stack_top  >  ctx->stack_base, 'H');

		FIBER_REQUIRE((ctx->stack_base % FIBER_STACK_ALIGN) == 0u, 'A');
		FIBER_REQUIRE((ctx->stack_top  % FIBER_STACK_ALIGN) == 0u, 'A');

		FIBER_REQUIRE(fiber_addr_plausible_ram(ctx->stack_base, ctx->stack_top) != 0, 'P');
		FIBER_REQUIRE(ctx->avail == (size_t)(ctx->stack_top - ctx->stack_base), 'S');

		FIBER_REQUIRE(ctx->stack_base >= min_base, 'Z');
		FIBER_REQUIRE(ctx->stack_top  <= max_top,  'z');

		const size_t need = (size_t)FIBER_STACK_WITHOUT_REDZONE;
		FIBER_REQUIRE(ctx->avail >= need, 'h');
	}

	/* MSP plan invariants */
	{
		FIBER_REQUIRE((ctx->msp_policy == FIBER_MSP_POLICY_VALIDATE) ||
				(ctx->msp_policy == FIBER_MSP_POLICY_REWIND), 'p');

		FIBER_REQUIRE(ctx->msp_top != 0u, 'M');
		FIBER_REQUIRE((ctx->msp_top % FIBER_STACK_ALIGN) == 0u, 'A');

		const uintptr_t chk = (ctx->msp_top >= 4u) ? (ctx->msp_top - 4u) : ctx->msp_top;
		FIBER_REQUIRE(fiber_addr_plausible_ram(chk, ctx->msp_top) != 0, 'R');

		FIBER_REQUIRE(!(ctx->msp_top > ctx->stack_base && ctx->msp_top <= ctx->stack_top),
				(ctx->msp_policy == FIBER_MSP_POLICY_REWIND) ? 'O' : 'o');

		const size_t gap = (ctx->msp_top > ctx->stack_top)
							 ? (size_t)(ctx->msp_top - ctx->stack_top)
									 : (size_t)(ctx->stack_base - ctx->msp_top);
		FIBER_REQUIRE(gap >= (size_t)FIBER_STACK_REDZONE_BYTES,
				(ctx->msp_policy == FIBER_MSP_POLICY_REWIND) ? 'G' : 'g');

#if FIBER_REWIND_MSP
		/* Extra paranoia: if we plan to rewind, verify VTOR still points to same MSP. */
		uint32_t ra = fiber_read_initial_msp();
		__ISB();
		uint32_t rb = fiber_read_initial_msp();
		if ((ra == 0u) || (ra != rb)) {
			const uintptr_t fb = fiber_fallback_initial_msp();
			FIBER_REQUIRE(fb != 0u, 'f');
			ra = (uint32_t)fb;
			rb = (uint32_t)fb;
		}
		const uintptr_t expected = fiber_stack_align_down((uintptr_t)ra);
		FIBER_REQUIRE(ctx->msp_top == expected, 'W'); /* plan drifted */
#endif
	}
}

/* -------------------------------------------------------------------------- 	*/
/* Simple Context Validator (no paranoia)                                		*/
/* -------------------------------------------------------------------------- 	*/
void fiber_boot_simple_check(const FiberBoot* const ctx)
{
	fiber_port_boot_record_check(ctx);
}

/* -------------------------------------------------------------------------- */
/* Environment precondition check (Thread mode, privileged, MSP selected).    */
/* traps via FIBER_REQUIRE.                    								  */
/* -------------------------------------------------------------------------- */
void fiber_env_check(void)
{
	const uint32_t ctl0 = __get_CONTROL();

	/* Must be Thread mode (not Handler). */
	FIBER_REQUIRE(__get_IPSR() == 0u, 'I');

	/* Must be privileged and using MSP in Thread mode. */
	FIBER_REQUIRE((ctl0 & 1u) == 0u, 'p'); /* nPRIV==0 => privileged */
	FIBER_REQUIRE((ctl0 & 2u) == 0u, 's'); /* SPSEL==0 => MSP selected in Thread */

}

/* -------------------------------------------------------------------------- */
/* Final boot using a prepared and sealed FiberBoot.                        */
/* - Re-validates environment and context.                                     */
/* - Programs PSPLIM (v8-M Mainline) to stack_base.                            */
/* - Optionally rewinds MSP to ctx->msp_top (REWIND) or validates equality     */
/*   (VALIDATE).                                                               */
/* - Switches Thread to PSP and tail-calls entry(arg) via the trampoline.      */
/* - Never returns.                                                            */
/* -------------------------------------------------------------------------- */
FIBER_NORETURN
FIBER_ATTR_SENSITIVE
void fiber_boot(const FiberBoot* const ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'n');

	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }

	/* Environment must be clean: Thread mode, privileged, MSP selected. */
	fiber_env_check();

	/* Context must pass all paranoid invariants. */
	fiber_boot_check(ctx);

	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }

	/* Platform hygiene before switching stacks. */
	fiber_platform_bootstrap();

	/* Program PSPLIM only when the selected security policy allows register access. */
#if FIBER_USE_PSPLIM_REGISTER
	fiber_psplim_config((uint32_t)ctx->stack_base);
	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }							/* ensure PSPLIM is live before using PSP */
	FIBER_REQUIRE(fiber_get_psplim() == (uint32_t)ctx->stack_base, 'L');/* read-back verify */
#endif /* FIBER_USE_PSPLIM_REGISTER */

	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }

	const uintptr_t msp_top = fiber_boot_prepare_msp_for_start(ctx);
	fiber_boot_trampoline((void*)ctx->stack_top, ctx->entry, ctx->arg,
			(void*)msp_top);

	/* If we ever get here, the world is broken. Scream and park forever. */
	__BKPT(0);                 /* outside a debugger this typically HardFaults */
	for (;;) { __WFE(); }      /* never returns */
}

#undef FIBER_BOOT_CLEAR_FPCA_ASM
#undef FIBER_BOOT_VERIFY_FPCA_CLEAR_ASM

/*
 * fiber_port_boot.c
 *
 * ARMv6-M-owned PSP boot helpers.
 * - Paranoid context builder and checker with red-zone & PSPLIM accounting.
 * - Platform bootstrap: fault policy/STKALIGN/unaligned/div0/FPU/TrustZone.
 * - Environment precondition check (Thread, privileged, MSP selected).
 *
 * No RTOS coexistence. If you call this under an RTOS, you own the crash.
 *
 * Scope: Cortex-M0/M0+ only. PSP and CONTROL.SPSEL are available; PSPLIM,
 * configurable Mem/Bus/Usage faults, BASEPRI, and FPU context are not.
 */

#include "../fiber_port_select.h"

#if FIBER_PORT_ARMV6M

#include "../fiber_port_selected.h"
#include "../../fiber_platform_policy.h"

static void fiber_port_boot_simple_check(const FiberPortBoot* const ctx);

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
/* -------------------------------------------------------------------------- */
/* Fault hygiene: clear "sticky" status where present (v7-M/v7E-M/v8-M Main). */
/* Use read-then-write (W1C) to avoid leftovers from a previous session.      */
/* -------------------------------------------------------------------------- */
#if FIBER_CLEAR_STICKY_FAULT_STATUS_ON_START
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
#endif

/* -------------------------------------------------------------------------- */
/* Platform bootstrap: apply fault policy, STKALIGN, UB traps, and FPU policy. */
/* Idempotent and safe to call multiple times at boot.                        */
/* -------------------------------------------------------------------------- */
void fiber_port_runtime_prepare(void)
{
#if FIBER_CLEAR_STICKY_FAULT_STATUS_ON_START
	fiber_clear_sticky_faults();
#endif

	/* Let Mem/Bus/Usage faults fire (where available) to catch programming errors early. */
#if FIBER_ENABLE_CONFIGURABLE_FAULTS && \
		(defined(SCB_SHCSR_MEMFAULTENA_Msk) || \
		 defined(SCB_SHCSR_BUSFAULTENA_Msk) || \
		 defined(SCB_SHCSR_USGFAULTENA_Msk))
	const uint32_t required_fault_enables =
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
	SCB->SHCSR |= required_fault_enables;

	{ __DSB(); __ISB(); }
	FIBER_REQUIRE((SCB->SHCSR & required_fault_enables) ==
			required_fault_enables, 'F');
#endif

	/* Keep exception frames 8-byte aligned as per ARM ABI. */
#ifdef SCB_CCR_STKALIGN_Msk
	SCB->CCR |= SCB_CCR_STKALIGN_Msk;
	{ __DSB(); __ISB(); }
	FIBER_REQUIRE((SCB->CCR & SCB_CCR_STKALIGN_Msk) != 0u, 'A');
#endif

	/* Optionally trap unaligned accesses and division-by-zero to surface UB early. */
#if defined(SCB_CCR_UNALIGN_TRP_Msk) && FIBER_ENABLE_UNALIGNED_TRAP
	SCB->CCR |= SCB_CCR_UNALIGN_TRP_Msk;
	{ __DSB(); __ISB(); }
	FIBER_REQUIRE((SCB->CCR & SCB_CCR_UNALIGN_TRP_Msk) != 0u, 'A');
#endif
#if defined(SCB_CCR_DIV_0_TRP_Msk) && FIBER_ENABLE_DIV0_TRAP
	SCB->CCR |= SCB_CCR_DIV_0_TRP_Msk;
	{ __DSB(); __ISB(); }
	FIBER_REQUIRE((SCB->CCR & SCB_CCR_DIV_0_TRP_Msk) != 0u, 'D');
#endif

#if FIBER_PORT_HAS_BASEPRI
	fiber_port_basepri_write(0u);
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
#endif /* BASEPRI */

#if FIBER_PORT_HAS_FAULTMASK
	__set_FAULTMASK(0);
	{ __DSB(); __ISB(); }
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
#endif /* FAULTMASK */

	/* Let the selected port apply its FPU policy, if any. */
	fiber_port_fpu_enable_early();
}

uintptr_t fiber_port_boot_prepare_msp_for_start(const FiberPortBoot* const ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'n');
	fiber_port_boot_check(ctx);

	if (ctx->msp_policy == FIBER_PORT_MSP_POLICY_REWIND) {
		uint32_t ra = fiber_port_read_initial_msp();
		__ISB();
		uint32_t rb = fiber_port_read_initial_msp();

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

static FIBER_GENERAL_REGS_ONLY
uint32_t fiber_boot_hash32_accum(uint32_t h, uint32_t v)
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

FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_boot_record_compute_hash(const FiberPortBoot *c)
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

FIBER_GENERAL_REGS_ONLY
void fiber_port_boot_record_fast_check(const FiberPortBoot *ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'n');
	FIBER_REQUIRE(ctx->magic == FIBER_PORT_BOOT_RECORD_MAGIC, 'm');
	FIBER_REQUIRE(ctx->version == FIBER_PORT_BOOT_RECORD_VERSION, 'v');
	FIBER_REQUIRE(ctx->guard_lo == FIBER_PORT_BOOT_RECORD_GUARD_LO, 'g');
	FIBER_REQUIRE(ctx->guard_hi == FIBER_PORT_BOOT_RECORD_GUARD_HI, 'G');
	FIBER_REQUIRE(ctx->sealed == 1u, 's');

	/* Cheap structural checks remain active when per-switch hashing is off. */
	const uintptr_t begin = (uintptr_t)ctx->begin;
	const uintptr_t end = (uintptr_t)ctx->end;
	FIBER_REQUIRE(begin != 0u, 'B');
	FIBER_REQUIRE(end != 0u, 'T');
	FIBER_REQUIRE(end > begin, 'N');
	FIBER_REQUIRE(ctx->stack_base >= begin, 'U');
	FIBER_REQUIRE(ctx->stack_top <= end, 'T');
	FIBER_REQUIRE(ctx->stack_top > ctx->stack_base, 'S');
	FIBER_REQUIRE((ctx->stack_base &
			((uintptr_t)FIBER_PORT_STACK_ALIGNMENT - 1u)) == 0u,
			'A');
	FIBER_REQUIRE((ctx->stack_top &
			((uintptr_t)FIBER_PORT_STACK_ALIGNMENT - 1u)) == 0u,
			'A');
	FIBER_REQUIRE(ctx->avail == (size_t)(ctx->stack_top - ctx->stack_base), 'a');
	FIBER_REQUIRE(ctx->entry != NULL, 'E');
	FIBER_REQUIRE((((uintptr_t)ctx->entry) & 1u) != 0u, 'e');
	FIBER_REQUIRE((ctx->msp_policy == FIBER_PORT_MSP_POLICY_VALIDATE) ||
			(ctx->msp_policy == FIBER_PORT_MSP_POLICY_REWIND), 'M');
	FIBER_REQUIRE(ctx->msp_top != 0u, 'M');
	FIBER_REQUIRE((ctx->msp_top &
			((uintptr_t)FIBER_PORT_STACK_ALIGNMENT - 1u)) == 0u,
			'M');
}

FIBER_GENERAL_REGS_ONLY
void fiber_port_boot_record_check(const FiberPortBoot *ctx)
{
	fiber_port_boot_record_fast_check(ctx);
	FIBER_REQUIRE(ctx->hash == fiber_port_boot_record_compute_hash(ctx), 'h');
}


/* -------------------------------------------------------------------------- */
/* MSP planning (called by constructor)                                       */
/* - For REWIND: read VTOR[0] twice (stability), else require fallback.       */
/* - For VALIDATE: snapshot current MSP.                                      */
/* Both paths: plausibility, non-overlap, minimum gap to PSP.                 */
/* -------------------------------------------------------------------------- */
static void fiber_port_boot_plan_msp(FiberPortBoot* const ctx)
{
#if FIBER_REWIND_MSP
	ctx->msp_policy = FIBER_PORT_MSP_POLICY_REWIND;

	uint32_t msp0a = fiber_port_read_initial_msp();
	__ISB();
	uint32_t msp0b = fiber_port_read_initial_msp();

	if ((msp0a == 0u) || (msp0a != msp0b)) {
		const uintptr_t fb = fiber_fallback_initial_msp();  /* fallback must provide non-zero MSP */
		FIBER_REQUIRE(fb != 0u, 'f');
		msp0a = (uint32_t)fb;
		msp0b = (uint32_t)fb;
	}
	FIBER_REQUIRE(msp0a == msp0b, 'V');

	ctx->msp_top = fiber_stack_align_down((uintptr_t)msp0a);
#else
	ctx->msp_policy = FIBER_PORT_MSP_POLICY_VALIDATE;
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
			(ctx->msp_policy == FIBER_PORT_MSP_POLICY_REWIND) ? 'O' : 'o');

	/* Minimum gap MSP<->PSP at least red-zone. */
	{
		const size_t gap = (ctx->msp_top > ctx->stack_top)
							 ? (size_t)(ctx->msp_top - ctx->stack_top)
									 : (size_t)(ctx->stack_base - ctx->msp_top);

		FIBER_REQUIRE(gap >= (size_t)FIBER_STACK_REDZONE_BYTES,
				(ctx->msp_policy == FIBER_PORT_MSP_POLICY_REWIND) ? 'G' : 'g');
	}
}

/* -------------------------------------------------------------------------- */
/* Constructor                                                                */
/* -------------------------------------------------------------------------- */
FiberPortBoot fiber_port_boot_create(void* const begin, void* const end, const entry_t entry, void* const arg)
{
	FiberPortBoot ctx = (FiberPortBoot){0};
	/* ------------------------------------------------------------------ *
	 * Contract checks (raw inputs)                                		  *
	 * ------------------------------------------------------------------ */
	{
		{ __DSB(); __ISB(); __COMPILER_BARRIER(); }

		FIBER_REQUIRE(begin  != NULL, 'B');
		FIBER_REQUIRE(end    != NULL, 'T');
		FIBER_REQUIRE(entry  != NULL, 'E');
		FIBER_REQUIRE((uintptr_t)end > (uintptr_t)begin, 'N'); /* non-empty raw range */
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

		FIBER_REQUIRE((base_aligned % FIBER_PORT_STACK_ALIGNMENT) == 0u, 'A');
		FIBER_REQUIRE((top_aligned % FIBER_PORT_STACK_ALIGNMENT) == 0u, 'A');

		/* ------------------------------------------------------------------ *
		 * Region plausibility and minimum sizing                             *
		 * ------------------------------------------------------------------ */

		/* Application-defined plausibility of the PSP region itself. */
		FIBER_REQUIRE(fiber_addr_plausible_ram(base_aligned, top_aligned) != 0, 'P');

		/* Exact selected-port maximum saved context. */
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
	fiber_port_boot_plan_msp(&ctx);

	/* Seal with metadata (magic/version/canaries/hash) */
	ctx.magic    = FIBER_PORT_BOOT_RECORD_MAGIC;
	ctx.version  = FIBER_PORT_BOOT_RECORD_VERSION;
	ctx.sealed   = 0u;                /* not sealed until hash is set */
	ctx.guard_lo = FIBER_PORT_BOOT_RECORD_GUARD_LO;
	ctx.guard_hi = FIBER_PORT_BOOT_RECORD_GUARD_HI;
	ctx.hash     = 0u;

	ctx.hash   = fiber_port_boot_record_compute_hash(&ctx);
	ctx.sealed = 1u;

	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }

	fiber_port_boot_check(&ctx);
	return ctx;
}

/* -------------------------------------------------------------------------- */
/* Context validator (paranoid)                                               */
/* -------------------------------------------------------------------------- */
void fiber_port_boot_check(const FiberPortBoot* const ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'n');

	/* Integrity header */
	fiber_port_boot_simple_check(ctx);

	/* Payload presence */
	FIBER_REQUIRE(ctx->begin != NULL, 'B');
	FIBER_REQUIRE(ctx->end   != NULL, 'T');
	FIBER_REQUIRE(ctx->entry != NULL, 'E');
	FIBER_REQUIRE((uintptr_t)ctx->end > (uintptr_t)ctx->begin, 'N');

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

		FIBER_REQUIRE((ctx->stack_base % FIBER_PORT_STACK_ALIGNMENT) == 0u,
				'A');
		FIBER_REQUIRE((ctx->stack_top % FIBER_PORT_STACK_ALIGNMENT) == 0u,
				'A');

		FIBER_REQUIRE(fiber_addr_plausible_ram(ctx->stack_base, ctx->stack_top) != 0, 'P');
		FIBER_REQUIRE(ctx->avail == (size_t)(ctx->stack_top - ctx->stack_base), 'S');

		FIBER_REQUIRE(ctx->stack_base >= min_base, 'Z');
		FIBER_REQUIRE(ctx->stack_top  <= max_top,  'z');

		const size_t need = (size_t)FIBER_STACK_WITHOUT_REDZONE;
		FIBER_REQUIRE(ctx->avail >= need, 'h');
	}

	/* MSP plan invariants */
	{
		FIBER_REQUIRE((ctx->msp_policy == FIBER_PORT_MSP_POLICY_VALIDATE) ||
				(ctx->msp_policy == FIBER_PORT_MSP_POLICY_REWIND), 'p');

		FIBER_REQUIRE(ctx->msp_top != 0u, 'M');
		FIBER_REQUIRE((ctx->msp_top % FIBER_PORT_STACK_ALIGNMENT) == 0u,
				'A');

		const uintptr_t chk = (ctx->msp_top >= 4u) ? (ctx->msp_top - 4u) : ctx->msp_top;
		FIBER_REQUIRE(fiber_addr_plausible_ram(chk, ctx->msp_top) != 0, 'R');

		FIBER_REQUIRE(!(ctx->msp_top > ctx->stack_base && ctx->msp_top <= ctx->stack_top),
				(ctx->msp_policy == FIBER_PORT_MSP_POLICY_REWIND) ? 'O' : 'o');

		const size_t gap = (ctx->msp_top > ctx->stack_top)
							 ? (size_t)(ctx->msp_top - ctx->stack_top)
									 : (size_t)(ctx->stack_base - ctx->msp_top);
		FIBER_REQUIRE(gap >= (size_t)FIBER_STACK_REDZONE_BYTES,
				(ctx->msp_policy == FIBER_PORT_MSP_POLICY_REWIND) ? 'G' : 'g');

#if FIBER_REWIND_MSP
		/* Extra paranoia: if we plan to rewind, verify VTOR still points to same MSP. */
		uint32_t ra = fiber_port_read_initial_msp();
		__ISB();
		uint32_t rb = fiber_port_read_initial_msp();
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
static void fiber_port_boot_simple_check(const FiberPortBoot* const ctx)
{
	fiber_port_boot_record_check(ctx);
}

/* -------------------------------------------------------------------------- */
/* Environment precondition check (Thread mode, privileged, MSP selected).    */
/* traps via FIBER_REQUIRE.                    								  */
/* -------------------------------------------------------------------------- */
void fiber_port_require_start_environment(void)
{
	const uint32_t ctl0 = __get_CONTROL();

	/* Must be Thread mode (not Handler). */
	FIBER_REQUIRE(__get_IPSR() == 0u, 'I');

	/* Must be privileged and using MSP in Thread mode. */
	FIBER_REQUIRE((ctl0 & 1u) == 0u, 'p'); /* nPRIV==0 => privileged */
	FIBER_REQUIRE((ctl0 & 2u) == 0u, 's'); /* SPSEL==0 => MSP selected in Thread */

}

void fiber_port_context_init(FiberContext *const ctx, void *const stack_begin,
		void *const stack_end, const entry_t entry, void *const arg)
{
	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
	FIBER_REQUIRE(ctx != NULL, 'C');
	FIBER_REQUIRE(stack_begin != NULL, 'B');
	FIBER_REQUIRE(stack_end != NULL, 'T');
	FIBER_REQUIRE(entry != NULL, 'E');
	const uintptr_t context_begin = (uintptr_t)ctx;
	const uintptr_t stack_raw_begin = (uintptr_t)stack_begin;
	const uintptr_t stack_raw_end = (uintptr_t)stack_end;
	FIBER_REQUIRE((context_begin & ((uintptr_t)_Alignof(FiberContext) - 1u)) == 0u, 'A');
	FIBER_REQUIRE(context_begin <= (UINTPTR_MAX - sizeof(*ctx)), 'O');
	const uintptr_t context_end = context_begin + sizeof(*ctx);
	FIBER_REQUIRE(stack_raw_end > stack_raw_begin, 'N');
	FIBER_REQUIRE(fiber_addr_plausible_ram(context_begin, context_end) != 0, 'C');
	FIBER_REQUIRE((context_end <= stack_raw_begin) || (context_begin >= stack_raw_end), 'C');
	const uintptr_t entry_addr = (uintptr_t)entry;
	FIBER_REQUIRE((entry_addr & 1u) == 1u, 'e');
	FIBER_REQUIRE(fiber_addr_plausible_code(entry_addr & ~(uintptr_t)1u) != 0, 'c');
	ctx->boot = fiber_port_boot_create(stack_begin, stack_end, entry, arg);
	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
	FIBER_REQUIRE((ctx->boot.stack_top & ((uintptr_t)FIBER_PORT_STACK_ALIGNMENT - 1u)) == 0u, 'a');
	FIBER_REQUIRE(ctx->boot.avail >= (size_t)FIBER_PORT_INITIAL_CONTEXT_BYTES, 'Z');
#if FIBER_STACK_CANARY
	const uintptr_t canary_cell = fiber_word_align_up((uintptr_t)ctx->boot.begin);
	((volatile uint32_t *)canary_cell)[0] = FIBER_INTERNAL_STACK_CANARY_VALUE;
	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
#endif
	fiber_port_init_context_frame(ctx);
	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
	FIBER_REQUIRE(((uintptr_t)ctx->sp & 7u) == (uintptr_t)FIBER_PORT_SAVED_SP_MOD8, 'A');
	FIBER_REQUIRE((uintptr_t)ctx->sp >= ctx->boot.stack_base, 'U');
	FIBER_REQUIRE((uintptr_t)ctx->sp <= ctx->boot.stack_top - (uintptr_t)FIBER_EXC_BASE_BYTES, 'S');
	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
}

static FIBER_GENERAL_REGS_ONLY void fiber_port_validate_stack_canary(const FiberContext *const ctx)
{
#if FIBER_STACK_CANARY
	const uintptr_t begin = (uintptr_t)ctx->boot.begin;
	const uintptr_t canary_cell = fiber_word_align_up(begin);
	FIBER_REQUIRE(canary_cell >= begin, 'c');
	FIBER_REQUIRE(canary_cell <= (UINTPTR_MAX - sizeof(uint32_t)), 'c');
	FIBER_REQUIRE((canary_cell + sizeof(uint32_t)) <= ctx->boot.stack_base, 'c');
	FIBER_REQUIRE(*(const volatile uint32_t *)canary_cell == FIBER_INTERNAL_STACK_CANARY_VALUE, 'c');
#else
	(void)ctx;
#endif
}

FIBER_GENERAL_REGS_ONLY void fiber_port_context_validate_restore(FiberContext *ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'N');
	FIBER_REQUIRE(((uintptr_t)ctx & ((uintptr_t)_Alignof(FiberContext) - 1u)) == 0u, 'A');
	FIBER_REQUIRE(ctx->sp != NULL, 'P');
#if FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH
	fiber_port_boot_record_check(&ctx->boot);
#else
	fiber_port_boot_record_fast_check(&ctx->boot);
#endif
	fiber_port_validate_stack_canary(ctx);
	const uintptr_t sp = (uintptr_t)ctx->sp;
	const uintptr_t available_bytes = ctx->boot.stack_top - sp;
	FIBER_REQUIRE((sp & 7u) == (uintptr_t)FIBER_PORT_SAVED_SP_MOD8, 'A');
	FIBER_REQUIRE(sp >= ctx->boot.stack_base, 'U');
	FIBER_REQUIRE(sp < ctx->boot.stack_top, 'T');
	FIBER_REQUIRE(available_bytes >= (uintptr_t)FIBER_PORT_SOFTWARE_FRAME_BYTES, 'X');
	const uint32_t *const words = (const uint32_t *)sp;
	const uint32_t exc_return = words[FIBER_PORT_EXC_RETURN_WORD_INDEX];
	FIBER_REQUIRE(fiber_port_exc_return_is_valid(exc_return) != 0u, 'x');
	uintptr_t hardware_frame_offset = (uintptr_t)FIBER_PORT_SOFTWARE_FRAME_BYTES;
#if FIBER_PORT_HAS_EXTENDED_FP_CONTEXT
	if ((exc_return & 0x10u) == 0u) { hardware_frame_offset += (uintptr_t)FIBER_HIGH_FP_SOFTWARE_BYTES; }
#endif
	if ((exc_return & 0x10u) == 0u) { hardware_frame_offset += (uintptr_t)FIBER_EXC_FP_EXT_BYTES; }
	const uintptr_t stacked_pc_offset = hardware_frame_offset + (6u * 4u);
	const uintptr_t stacked_xpsr_offset = hardware_frame_offset + (7u * 4u);
	uintptr_t required_bytes = hardware_frame_offset + (uintptr_t)FIBER_EXC_BASE_BYTES;
	FIBER_REQUIRE(available_bytes >= required_bytes, 'X');
	const uint32_t stacked_pc = *(const uint32_t *)(sp + stacked_pc_offset);
	const uint32_t stacked_xpsr = *(const uint32_t *)(sp + stacked_xpsr_offset);
	FIBER_REQUIRE((stacked_xpsr & (1u << 24u)) != 0u, 'x');
	FIBER_REQUIRE((stacked_xpsr & 0x1FFu) == 0u, 'x');
	FIBER_REQUIRE((stacked_pc & 1u) == 0u, 'x');
	if ((stacked_xpsr & (1u << 9u)) != 0u) { required_bytes += (uintptr_t)FIBER_EXCEPTION_ALIGNMENT_PAD_BYTES; }
	FIBER_REQUIRE(available_bytes >= required_bytes, 'X');
}

uintptr_t fiber_port_context_prepare_first_start(FiberContext *const ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'N');
	fiber_port_boot_check(&ctx->boot);
#if FIBER_PORT_USES_PSPLIM_REGISTER
	fiber_port_psplim_config((uint32_t)ctx->boot.stack_base);
	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
	FIBER_REQUIRE(fiber_port_psplim_read() == (uint32_t)ctx->boot.stack_base, 'L');
#endif
	const uintptr_t msp_top = fiber_port_boot_prepare_msp_for_start(&ctx->boot);
	fiber_port_context_validate_restore(ctx);
	return msp_top;
}

void fiber_port_require_start_interrupt_state(void)
{
	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
#if FIBER_PORT_HAS_BASEPRI
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
#endif
#if FIBER_PORT_HAS_FAULTMASK
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
#endif
}

#endif /* ARMv6-M selected boot implementation */

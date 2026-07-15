/*
 * fiber_port_boot.c
 *
 * ARM_CM3-owned PSP boot helpers.
 * - Paranoid context builder and checker with red-zone & PSPLIM accounting.
 * - Platform bootstrap: fault policy/STKALIGN/unaligned/div0/FPU/TrustZone.
 * - Environment precondition check (Thread, privileged, MSP selected).
 *
 * The cooperative fiber runtime owns PSP, PendSV, and SVC state while active.
 *
 * Scope: Cortex-M3 / ARMv7-M only. PSP, BASEPRI, and configurable fault
 * policy are available; PSPLIM and FPU context are not part of this port.
 */

#include "../fiber_port_select.h"

#if FIBER_PORT_ARMV7M

#include "fiber_port_private.h"
#include "../../fiber_platform_policy.h"

static void fiber_port_boot_simple_check(const FiberPortBoot* const ctx);
#if FIBER_REWIND_MSP
static FIBER_GENERAL_REGS_ONLY
uintptr_t fiber_port_fallback_initial_msp_checked(void);
#endif

/* -------------------------------------------------------------------------- */
/* Optional permissive defaults for bring-up only.                             */
/* -------------------------------------------------------------------------- */
#if FIBER_ALLOW_PERMISSIVE_ADDRESS_MAP_HOOKS
FIBER_WEAK FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_ram(uintptr_t start, uintptr_t end) {
	(void)start; (void)end; return 1; /* accept any RAM range by default */
}

FIBER_WEAK FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_code(uintptr_t addr) {
	(void)addr; return 1;             /* accept any code address by default */
}
#endif

FIBER_WEAK FIBER_GENERAL_REGS_ONLY
uintptr_t fiber_fallback_initial_msp(void) {
	return (uintptr_t)0;              /* default: no usable fallback */
}

/* Startup MSP ownership is runtime-wide, never a property of one context.
 * Keeping this plan outside FiberPortBoot prevents a context created before
 * start from freezing a stale Thread/MSP snapshot. */
typedef struct FiberPortStartMspPlan {
	uintptr_t top;
	uint32_t prepared;
} FiberPortStartMspPlan;

static FiberPortStartMspPlan fiber_port_start_msp_plan;

static void fiber_port_prepare_start_msp_plan(void)
{
	FIBER_REQUIRE(fiber_port_start_msp_plan.prepared == 0u, 'M');

	uintptr_t top;
#if FIBER_REWIND_MSP
	uint32_t first = fiber_port_read_initial_msp();
	__ISB();
	uint32_t second = fiber_port_read_initial_msp();

	if ((first == 0u) || (first != second)) {
		const uintptr_t fallback = fiber_port_fallback_initial_msp_checked();
		FIBER_REQUIRE(fallback != 0u, 'f');
		first = (uint32_t)fallback;
		second = (uint32_t)fallback;
	}
	FIBER_REQUIRE(first == second, 'V');
	top = fiber_stack_align_down((uintptr_t)first);
#else
	top = fiber_stack_align_down((uintptr_t)__get_MSP());
#endif

	FIBER_REQUIRE(top != 0u, 'M');
	FIBER_REQUIRE((top & ((uintptr_t)FIBER_PORT_STACK_ALIGNMENT - 1u)) == 0u,
			'M');
	{
		const uintptr_t check = (top >= 4u) ? (top - 4u) : top;
		FIBER_REQUIRE(fiber_addr_plausible_ram(check, top) != 0, 'R');
	}

	fiber_port_start_msp_plan.top = top;
	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
	fiber_port_start_msp_plan.prepared = 1u;
	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
}

static FIBER_GENERAL_REGS_ONLY
void fiber_port_validate_start_msp_for_boot(const FiberPortBoot *const ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'n');
	FIBER_REQUIRE(fiber_port_start_msp_plan.prepared == 1u, 'M');

	const uintptr_t top = fiber_port_start_msp_plan.top;
	FIBER_REQUIRE(top != 0u, 'M');
	FIBER_REQUIRE((top & ((uintptr_t)FIBER_PORT_STACK_ALIGNMENT - 1u)) == 0u,
			'M');
	FIBER_REQUIRE(!(top > ctx->stack_base && top <= ctx->stack_top), 'O');
	{
		const size_t gap = (top > ctx->stack_top)
				? (size_t)(top - ctx->stack_top)
				: (size_t)(ctx->stack_base - top);
		FIBER_REQUIRE(gap >= (size_t)FIBER_STACK_REDZONE_BYTES, 'G');
	}

#if FIBER_REWIND_MSP
	uint32_t first = fiber_port_read_initial_msp();
	__ISB();
	uint32_t second = fiber_port_read_initial_msp();
	if ((first == 0u) || (first != second)) {
		const uintptr_t fallback = fiber_port_fallback_initial_msp_checked();
		FIBER_REQUIRE(fallback != 0u, 'f');
		first = (uint32_t)fallback;
		second = (uint32_t)fallback;
	}
	FIBER_REQUIRE(first == second, 'V');
	FIBER_REQUIRE(top == fiber_stack_align_down((uintptr_t)first), 'W');
#endif
}

static FIBER_GENERAL_REGS_ONLY
void fiber_port_validate_context_pointer(const FiberContext *const ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'N');

	const uintptr_t begin = (uintptr_t)ctx;
	FIBER_REQUIRE((begin & ((uintptr_t)_Alignof(FiberContext) - 1u)) == 0u,
			'A');
	FIBER_REQUIRE(begin <= (UINTPTR_MAX - sizeof(*ctx)), 'O');
#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH
	const uintptr_t end = begin + sizeof(*ctx);
	FIBER_REQUIRE(fiber_addr_plausible_ram(begin, end) != 0, 'C');
#endif
}

#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH
static FIBER_GENERAL_REGS_ONLY
void fiber_port_validate_stack_address_map_on_switch(
		const FiberContext *const ctx)
{
	FIBER_REQUIRE(fiber_addr_plausible_ram(ctx->boot.stack_base,
			ctx->boot.stack_top) != 0, 'P');
}
#endif
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
/* One-shot runtime preparation: apply port policy and create the startup MSP */
/* plan after fiber_start() has established its interrupt preconditions.      */
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

	/* Let the selected port apply its FPU policy, if any. */
	fiber_port_fpu_enable_early();
	fiber_port_prepare_start_msp_plan();
}

uintptr_t fiber_port_boot_prepare_msp_for_start(const FiberPortBoot* const ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'n');
	fiber_port_boot_check(ctx);
	fiber_port_validate_start_msp_for_boot(ctx);
	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }

#if FIBER_REWIND_MSP
	return fiber_port_start_msp_plan.top;
#else
	return 0u;
#endif
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
	h = fiber_boot_hash32_accum(h, c->abi_port_id);
	h = fiber_boot_hash32_accum(h, c->abi_layout_version);
	h = fiber_boot_hash32_accum(h, c->abi_context_size);
	h = fiber_boot_hash32_accum(h, c->abi_context_alignment);
	h = fiber_boot_hash32_accum(h, c->abi_feature_mask);
	h = fiber_boot_hash32_accum(h, c->abi_initial_exc_return);
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
	FIBER_REQUIRE(ctx->abi_port_id == FIBER_PORT_CONTEXT_ABI_PORT_ID, 'q');
	FIBER_REQUIRE(ctx->abi_layout_version == FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION,
			'q');
	FIBER_REQUIRE(ctx->abi_context_size == (uint32_t)sizeof(FiberContext), 'q');
	FIBER_REQUIRE(ctx->abi_context_alignment == (uint32_t)_Alignof(FiberContext),
			'q');
	FIBER_REQUIRE(ctx->abi_feature_mask == FIBER_PORT_CONTEXT_ABI_FEATURE_MASK,
			'q');
	FIBER_REQUIRE(ctx->abi_initial_exc_return == FIBER_PORT_INITIAL_EXC_RETURN,
			'q');
}

FIBER_GENERAL_REGS_ONLY
void fiber_port_boot_record_check(const FiberPortBoot *ctx)
{
	fiber_port_boot_record_fast_check(ctx);
	FIBER_REQUIRE(ctx->hash == fiber_port_boot_record_compute_hash(ctx), 'h');
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

	/* Seal with metadata (magic/version/canaries/hash) */
	ctx.abi_port_id = FIBER_PORT_CONTEXT_ABI_PORT_ID;
	ctx.abi_layout_version = FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION;
	ctx.abi_context_size = (uint32_t)sizeof(FiberContext);
	ctx.abi_context_alignment = (uint32_t)_Alignof(FiberContext);
	ctx.abi_feature_mask = FIBER_PORT_CONTEXT_ABI_FEATURE_MASK;
	ctx.abi_initial_exc_return = FIBER_PORT_INITIAL_EXC_RETURN;
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

/* Integration hooks must not silently alter selected CPU execution state.
 * Address-map hooks run only when enabled; the MSP fallback is guarded locally. */
#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH || FIBER_REWIND_MSP
typedef struct FiberPortValidationCpuState {
	uint32_t primask;
	uint32_t control;
#if FIBER_PORT_HAS_BASEPRI
	uint32_t basepri;
#endif
#if FIBER_PORT_HAS_FAULTMASK
	uint32_t faultmask;
#endif
} FiberPortValidationCpuState;

static FIBER_GENERAL_REGS_ONLY void
fiber_port_capture_validation_cpu_state(FiberPortValidationCpuState *const state)
{
	FIBER_REQUIRE(state != NULL, 'C');
	fiber_portCOMPILER_BARRIER();
	state->primask = __get_PRIMASK();
	state->control = __get_CONTROL();
#if FIBER_PORT_HAS_BASEPRI
	state->basepri = fiber_port_basepri_read();
#endif
#if FIBER_PORT_HAS_FAULTMASK
	state->faultmask = __get_FAULTMASK();
#endif
	fiber_portCOMPILER_BARRIER();
}

static FIBER_GENERAL_REGS_ONLY void
fiber_port_validate_validation_cpu_state(const FiberPortValidationCpuState *const before)
{
	FIBER_REQUIRE(before != NULL, 'C');
	fiber_portCOMPILER_BARRIER();
	FIBER_REQUIRE(__get_PRIMASK() == before->primask, 'r');
	FIBER_REQUIRE(__get_CONTROL() == before->control, 'l');
#if FIBER_PORT_HAS_BASEPRI
	FIBER_REQUIRE(fiber_port_basepri_read() == before->basepri, 'B');
#endif
#if FIBER_PORT_HAS_FAULTMASK
	FIBER_REQUIRE(__get_FAULTMASK() == before->faultmask, 't');
#endif
	fiber_portCOMPILER_BARRIER();
}
#endif

#if FIBER_REWIND_MSP
static FIBER_GENERAL_REGS_ONLY
uintptr_t fiber_port_fallback_initial_msp_checked(void)
{
	FiberPortValidationCpuState cpu_state;
	fiber_port_capture_validation_cpu_state(&cpu_state);
	const uintptr_t fallback = fiber_fallback_initial_msp();
	fiber_port_validate_validation_cpu_state(&cpu_state);
	return fallback;
}
#endif

FIBER_GENERAL_REGS_ONLY
void fiber_port_context_validate_save_current(const FiberContext *ctx)
{
#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH
	FiberPortValidationCpuState cpu_state;
	fiber_port_capture_validation_cpu_state(&cpu_state);
#endif
	fiber_port_validate_context_pointer(ctx);
#if FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH
	fiber_port_boot_record_check(&ctx->boot);
#else
	fiber_port_boot_record_fast_check(&ctx->boot);
#endif
#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH
	fiber_port_validate_stack_address_map_on_switch(ctx);
#endif
	fiber_port_validate_stack_canary(ctx);
	/* The running context passed restore validation before it entered Thread
	 * mode. The startup MSP plan is restore-only and is not used for saving. */

	/* ctx->sp names the last saved frame and is stale while this fiber runs.
	 * Validate the live PSP instead, before PendSV assembly reads boot fields. */
	const uintptr_t psp = (uintptr_t)__get_PSP();
	FIBER_REQUIRE((psp & ((uintptr_t)sizeof(uint32_t) - 1u)) == 0u, 'A');
	FIBER_REQUIRE(psp >= ctx->boot.stack_base, 'U');
	FIBER_REQUIRE(psp <= ctx->boot.stack_top, 'T');

#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH
	fiber_port_validate_validation_cpu_state(&cpu_state);
#endif
}

FIBER_GENERAL_REGS_ONLY void fiber_port_context_validate_restore(FiberContext *ctx)
{
#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH
	FiberPortValidationCpuState cpu_state;
	fiber_port_capture_validation_cpu_state(&cpu_state);
#endif
	fiber_port_validate_context_pointer(ctx);
	FIBER_REQUIRE(ctx->sp != NULL, 'P');
#if FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH
	fiber_port_boot_record_check(&ctx->boot);
#else
	fiber_port_boot_record_fast_check(&ctx->boot);
#endif
#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH
	fiber_port_validate_stack_address_map_on_switch(ctx);
#endif
	fiber_port_validate_start_msp_for_boot(&ctx->boot);
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
#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH
	FIBER_REQUIRE(fiber_addr_plausible_code((uintptr_t)stacked_pc) != 0, 'c');
#endif
	if ((stacked_xpsr & (1u << 9u)) != 0u) { required_bytes += (uintptr_t)FIBER_EXCEPTION_ALIGNMENT_PAD_BYTES; }
	FIBER_REQUIRE(available_bytes >= required_bytes, 'X');

#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH
	fiber_port_validate_validation_cpu_state(&cpu_state);
#endif
}

uintptr_t fiber_port_context_prepare_first_start(FiberContext *const ctx)
{
	fiber_port_context_validate_restore(ctx);
#if FIBER_PORT_USES_PSPLIM_REGISTER
	fiber_port_psplim_config((uint32_t)ctx->boot.stack_base);
	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
	FIBER_REQUIRE(fiber_port_psplim_read() == (uint32_t)ctx->boot.stack_base, 'L');
#endif
	const uintptr_t msp_top = fiber_port_boot_prepare_msp_for_start(&ctx->boot);
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

#endif /* ARMv7-M selected boot implementation */

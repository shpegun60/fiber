/* ARM_CM33F_NTZ immutable boot metadata and initial-frame validation. */

#include "fiber_port_private.h"

#if FIBER_ALLOW_PERMISSIVE_ADDRESS_MAP_HOOKS
FIBER_WEAK FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_ram(uintptr_t start, uintptr_t end)
{
	(void)start;
	(void)end;
	return 1;
}

FIBER_WEAK FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_code(uintptr_t addr)
{
	(void)addr;
	return 1;
}
#endif

static FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_hash32_accum(uint32_t hash, uint32_t value)
{
	hash ^= (uint8_t)value;
	hash *= 16777619u;
	hash ^= (uint8_t)(value >> 8u);
	hash *= 16777619u;
	hash ^= (uint8_t)(value >> 16u);
	hash *= 16777619u;
	hash ^= (uint8_t)(value >> 24u);
	hash *= 16777619u;
	return hash;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_boot_record_compute_hash(const FiberPortBoot *const boot)
{
	FIBER_REQUIRE(boot != NULL, 'n');
	uint32_t hash = 2166136261u;

	hash = fiber_port_hash32_accum(hash, (uint32_t)(uintptr_t)boot->begin);
	hash = fiber_port_hash32_accum(hash, (uint32_t)(uintptr_t)boot->end);
	hash = fiber_port_hash32_accum(hash, (uint32_t)boot->stack_base);
	hash = fiber_port_hash32_accum(hash, (uint32_t)boot->stack_top);
	hash = fiber_port_hash32_accum(hash, (uint32_t)boot->avail);
	hash = fiber_port_hash32_accum(hash, (uint32_t)(uintptr_t)boot->entry);
	hash = fiber_port_hash32_accum(hash, (uint32_t)(uintptr_t)boot->arg);
	hash = fiber_port_hash32_accum(hash, boot->abi_port_id);
	hash = fiber_port_hash32_accum(hash, boot->abi_layout_version);
	hash = fiber_port_hash32_accum(hash, boot->abi_context_size);
	hash = fiber_port_hash32_accum(hash, boot->abi_context_alignment);
	hash = fiber_port_hash32_accum(hash, boot->abi_feature_mask);
	hash = fiber_port_hash32_accum(hash, boot->abi_initial_exc_return);
	hash = fiber_port_hash32_accum(hash, boot->magic);
	hash = fiber_port_hash32_accum(hash, (uint32_t)boot->version);
	hash = fiber_port_hash32_accum(hash, boot->guard_lo);
	hash = fiber_port_hash32_accum(hash, boot->guard_hi);
	return hash;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_boot_record_fast_check(const FiberPortBoot *const boot)
{
	FIBER_REQUIRE(boot != NULL, 'n');
	FIBER_REQUIRE(boot->magic == FIBER_PORT_BOOT_RECORD_MAGIC, 'm');
	FIBER_REQUIRE(boot->version == FIBER_PORT_BOOT_RECORD_VERSION, 'v');
	FIBER_REQUIRE(boot->guard_lo == FIBER_PORT_BOOT_RECORD_GUARD_LO, 'g');
	FIBER_REQUIRE(boot->guard_hi == FIBER_PORT_BOOT_RECORD_GUARD_HI, 'G');
	FIBER_REQUIRE(boot->sealed == 1u, 's');

	const uintptr_t begin = (uintptr_t)boot->begin;
	const uintptr_t end = (uintptr_t)boot->end;
	FIBER_REQUIRE(begin != 0u, 'B');
	FIBER_REQUIRE(end > begin, 'N');
	FIBER_REQUIRE(boot->stack_base >= begin, 'U');
	FIBER_REQUIRE(boot->stack_top <= end, 'T');
	FIBER_REQUIRE(boot->stack_top > boot->stack_base, 'S');
	FIBER_REQUIRE((boot->stack_base &
			((uintptr_t)FIBER_PORT_STACK_ALIGNMENT - 1u)) == 0u, 'A');
	FIBER_REQUIRE((boot->stack_top &
			((uintptr_t)FIBER_PORT_STACK_ALIGNMENT - 1u)) == 0u, 'A');
	FIBER_REQUIRE(boot->avail ==
			(size_t)(boot->stack_top - boot->stack_base), 'a');
	FIBER_REQUIRE(boot->entry != NULL, 'E');
	FIBER_REQUIRE((((uintptr_t)boot->entry) & 1u) != 0u, 'e');
	FIBER_REQUIRE(boot->abi_port_id == FIBER_PORT_CONTEXT_ABI_PORT_ID, 'q');
	FIBER_REQUIRE(boot->abi_layout_version ==
			FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION, 'q');
	FIBER_REQUIRE(boot->abi_context_size == (uint32_t)sizeof(FiberContext),
			'q');
	FIBER_REQUIRE(boot->abi_context_alignment ==
			(uint32_t)_Alignof(FiberContext), 'q');
	FIBER_REQUIRE(boot->abi_feature_mask ==
			FIBER_PORT_CONTEXT_ABI_FEATURE_MASK, 'q');
	FIBER_REQUIRE(boot->abi_initial_exc_return ==
			FIBER_PORT_INITIAL_EXC_RETURN, 'q');
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_boot_record_check(const FiberPortBoot *const boot)
{
	fiber_port_boot_record_fast_check(boot);
	FIBER_REQUIRE(boot->hash == fiber_port_boot_record_compute_hash(boot), 'h');
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_boot_create(FiberPortBoot *const boot,
		void *const begin,
		void *const end,
		const entry_t entry,
		void *const arg)
{
	FIBER_REQUIRE(boot != NULL, 'n');
	FIBER_REQUIRE(begin != NULL, 'B');
	FIBER_REQUIRE(end != NULL, 'T');
	FIBER_REQUIRE(entry != NULL, 'E');

	const uintptr_t raw_begin = (uintptr_t)begin;
	const uintptr_t raw_end = (uintptr_t)end;
	FIBER_REQUIRE(raw_end > raw_begin, 'N');
	FIBER_REQUIRE(fiber_addr_plausible_ram(raw_begin, raw_end) != 0, 'P');
	const uintptr_t entry_addr = (uintptr_t)entry;
	FIBER_REQUIRE((entry_addr & 1u) != 0u, 'e');
	FIBER_REQUIRE(fiber_addr_plausible_code(
			entry_addr & ~(uintptr_t)1u) != 0, 'c');

	const uintptr_t word_begin = fiber_word_align_up(raw_begin);
	FIBER_REQUIRE(word_begin <=
			(UINTPTR_MAX - (uintptr_t)FIBER_STACK_REDZONE_BYTES), 'o');
	const uintptr_t stack_base = fiber_stack_align_up(
			word_begin + (uintptr_t)FIBER_STACK_REDZONE_BYTES);
	const uintptr_t stack_top = fiber_stack_align_down(raw_end);
	FIBER_REQUIRE(stack_base >= raw_begin, 'r');
	FIBER_REQUIRE(stack_top > stack_base, 'h');
	FIBER_REQUIRE(stack_top <= raw_end, 't');
	FIBER_REQUIRE(fiber_addr_plausible_ram(stack_base, stack_top) != 0, 'P');

	const size_t available = (size_t)(stack_top - stack_base);
	FIBER_REQUIRE(available >= (size_t)FIBER_STACK_WITHOUT_REDZONE, 'H');

	boot->begin = begin;
	boot->end = end;
	boot->stack_base = stack_base;
	boot->stack_top = stack_top;
	boot->avail = available;
	boot->entry = entry;
	boot->arg = arg;
	boot->abi_port_id = FIBER_PORT_CONTEXT_ABI_PORT_ID;
	boot->abi_layout_version = FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION;
	boot->abi_context_size = (uint32_t)sizeof(FiberContext);
	boot->abi_context_alignment = (uint32_t)_Alignof(FiberContext);
	boot->abi_feature_mask = FIBER_PORT_CONTEXT_ABI_FEATURE_MASK;
	boot->abi_initial_exc_return = FIBER_PORT_INITIAL_EXC_RETURN;
	boot->magic = FIBER_PORT_BOOT_RECORD_MAGIC;
	boot->version = FIBER_PORT_BOOT_RECORD_VERSION;
	boot->sealed = 0u;
	boot->guard_lo = FIBER_PORT_BOOT_RECORD_GUARD_LO;
	boot->guard_hi = FIBER_PORT_BOOT_RECORD_GUARD_HI;
	boot->hash = 0u;
	boot->hash = fiber_port_boot_record_compute_hash(boot);
	boot->sealed = 1u;

	{
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
		fiber_portCOMPILER_BARRIER();
	}
	fiber_port_boot_check(boot);
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_boot_check(const FiberPortBoot *const boot)
{
	fiber_port_boot_record_check(boot);
	const uintptr_t raw_begin = (uintptr_t)boot->begin;
	const uintptr_t raw_end = (uintptr_t)boot->end;
	const uintptr_t word_begin = fiber_word_align_up(raw_begin);
	FIBER_REQUIRE(word_begin <=
			(UINTPTR_MAX - (uintptr_t)FIBER_STACK_REDZONE_BYTES), 'o');
	const uintptr_t expected_base = fiber_stack_align_up(
			word_begin + (uintptr_t)FIBER_STACK_REDZONE_BYTES);
	const uintptr_t expected_top = fiber_stack_align_down(raw_end);
	FIBER_REQUIRE(expected_top > expected_base, 'H');
	FIBER_REQUIRE(boot->stack_base == expected_base, 'Z');
	FIBER_REQUIRE(boot->stack_top == expected_top, 'z');
	FIBER_REQUIRE(boot->avail ==
			(size_t)(expected_top - expected_base), 'S');
	FIBER_REQUIRE(fiber_addr_plausible_ram(raw_begin, raw_end) != 0, 'P');
	FIBER_REQUIRE(fiber_addr_plausible_code(
			((uintptr_t)boot->entry) & ~(uintptr_t)1u) != 0, 'c');
	FIBER_REQUIRE(fiber_addr_plausible_ram(
			boot->stack_base, boot->stack_top) != 0, 'P');
	FIBER_REQUIRE(boot->avail >= (size_t)FIBER_STACK_WITHOUT_REDZONE, 'h');
}

static FIBER_GENERAL_REGS_ONLY
void fiber_port_validate_initial_frame(const FiberContext *const ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'C');
	const uint32_t *const frame = ctx->sp;
	FIBER_REQUIRE(frame != NULL, 'P');
	FIBER_REQUIRE(frame[0] == (uint32_t)ctx->boot.stack_base, 'L');
	FIBER_REQUIRE(frame[FIBER_PORT_EXC_RETURN_WORD_INDEX] ==
			FIBER_PORT_INITIAL_EXC_RETURN, 'x');
	FIBER_REQUIRE(frame[FIBER_PORT_SOFTWARE_FRAME_WORDS] ==
			(uint32_t)(uintptr_t)ctx->boot.arg, '0');
	FIBER_REQUIRE(frame[2] == 0u, '4');
	FIBER_REQUIRE(frame[3] == 0u, '5');
	FIBER_REQUIRE(frame[4] == 0u, '6');
	FIBER_REQUIRE(frame[5] == 0u, '7');
	FIBER_REQUIRE(frame[6] == 0u, '8');
	FIBER_REQUIRE(frame[8] == 0u, '1');
	FIBER_REQUIRE(frame[9] == 0u, '1');
	FIBER_REQUIRE(frame[11] == 0u, '1');
	FIBER_REQUIRE(frame[12] == 0u, '2');
	FIBER_REQUIRE(frame[13] == 0u, '3');
	FIBER_REQUIRE(frame[14] == 0u, '2');
	FIBER_REQUIRE(frame[FIBER_PORT_SOFTWARE_FRAME_WORDS + 5u] ==
			(((uint32_t)(uintptr_t)&fiber_internal_task_return) | 1u), 'R');
	FIBER_REQUIRE(frame[FIBER_PORT_SOFTWARE_FRAME_WORDS + 6u] ==
			fiber_port_stacked_pc((uintptr_t)ctx->boot.entry), 'x');
	FIBER_REQUIRE(frame[FIBER_PORT_SOFTWARE_FRAME_WORDS + 7u] ==
			fiber_port_initial_xpsr(), 'X');
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_context_init(FiberContext *const ctx,
		void *const stack_begin,
		void *const stack_end,
		const entry_t entry,
		void *const arg)
{
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
	FIBER_REQUIRE(ctx != NULL, 'C');
	FIBER_REQUIRE(stack_begin != NULL, 'B');
	FIBER_REQUIRE(stack_end != NULL, 'T');
	FIBER_REQUIRE(entry != NULL, 'E');

	const uintptr_t context_begin = (uintptr_t)ctx;
	FIBER_REQUIRE((context_begin &
			((uintptr_t)_Alignof(FiberContext) - 1u)) == 0u, 'A');
	FIBER_REQUIRE(context_begin <= (UINTPTR_MAX - sizeof(*ctx)), 'O');
	const uintptr_t context_end = context_begin + sizeof(*ctx);
	const uintptr_t raw_stack_begin = (uintptr_t)stack_begin;
	const uintptr_t raw_stack_end = (uintptr_t)stack_end;
	FIBER_REQUIRE(raw_stack_end > raw_stack_begin, 'N');
	FIBER_REQUIRE(fiber_addr_plausible_ram(
			context_begin, context_end) != 0, 'C');
	FIBER_REQUIRE((context_end <= raw_stack_begin) ||
			(context_begin >= raw_stack_end), 'C');

	const uintptr_t entry_addr = (uintptr_t)entry;
	FIBER_REQUIRE((entry_addr & 1u) != 0u, 'e');
	FIBER_REQUIRE(fiber_addr_plausible_code(
			entry_addr & ~(uintptr_t)1u) != 0, 'c');

	fiber_port_boot_create(&ctx->boot, stack_begin, stack_end, entry, arg);
#if FIBER_STACK_CANARY
	const uintptr_t canary_cell = fiber_word_align_up((uintptr_t)ctx->boot.begin);
	FIBER_REQUIRE(canary_cell <= (UINTPTR_MAX - sizeof(uint32_t)), 'O');
	FIBER_REQUIRE((canary_cell + sizeof(uint32_t)) <=
			ctx->boot.stack_base, 'c');
	FIBER_REQUIRE(fiber_addr_plausible_ram(canary_cell,
			canary_cell + sizeof(uint32_t)) != 0, 'c');
	((volatile uint32_t *)canary_cell)[0] =
			FIBER_INTERNAL_STACK_CANARY_VALUE;
#endif
	fiber_port_init_context_frame(ctx);

	FIBER_REQUIRE((uintptr_t)ctx->sp ==
			(ctx->boot.stack_top -
			 (uintptr_t)FIBER_PORT_INITIAL_CONTEXT_BYTES), 'S');
	FIBER_REQUIRE(((uintptr_t)ctx->sp & 7u) ==
			(uintptr_t)FIBER_PORT_SAVED_SP_MOD8, 'A');
	FIBER_REQUIRE((uintptr_t)ctx->sp >= ctx->boot.stack_base, 'U');
	fiber_port_validate_initial_frame(ctx);
	{
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
		fiber_portCOMPILER_BARRIER();
	}
}

typedef struct FiberPortStartMspPlan {
	uintptr_t top;
	uint32_t prepared;
} FiberPortStartMspPlan;

static FiberPortStartMspPlan fiber_port_start_msp_plan;

static FIBER_GENERAL_REGS_ONLY
void fiber_port_validate_context_pointer(const FiberContext *const ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'N');
	const uintptr_t begin = (uintptr_t)ctx;
	FIBER_REQUIRE((begin & ((uintptr_t)_Alignof(FiberContext) - 1u)) == 0u,
			'A');
	FIBER_REQUIRE(begin <= (UINTPTR_MAX - sizeof(*ctx)), 'O');
#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH
	FIBER_REQUIRE(fiber_addr_plausible_ram(begin,
			begin + sizeof(*ctx)) != 0, 'C');
#endif
}

static FIBER_GENERAL_REGS_ONLY
void fiber_port_validate_stack_canary(const FiberContext *const ctx)
{
#if FIBER_STACK_CANARY
	const uintptr_t begin = (uintptr_t)ctx->boot.begin;
	const uintptr_t canary_cell = fiber_word_align_up(begin);
	FIBER_REQUIRE(canary_cell >= begin, 'c');
	FIBER_REQUIRE(canary_cell <= (UINTPTR_MAX - sizeof(uint32_t)), 'c');
	FIBER_REQUIRE((canary_cell + sizeof(uint32_t)) <=
			ctx->boot.stack_base, 'c');
	FIBER_REQUIRE(*(const volatile uint32_t *)canary_cell ==
			FIBER_INTERNAL_STACK_CANARY_VALUE, 'c');
#else
	(void)ctx;
#endif
}

#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH
typedef struct FiberPortValidationCpuState {
	uint32_t primask;
	uint32_t control;
	uint32_t basepri;
	uint32_t faultmask;
	uint32_t cpacr;
	uint32_t fpccr;
} FiberPortValidationCpuState;

static FIBER_GENERAL_REGS_ONLY
void fiber_port_capture_validation_cpu_state(
		FiberPortValidationCpuState *const state)
{
	FIBER_REQUIRE(state != NULL, 'C');
	fiber_portCOMPILER_BARRIER();
	state->primask = __get_PRIMASK();
	state->control = __get_CONTROL();
	state->basepri = fiber_port_basepri_read();
	state->faultmask = __get_FAULTMASK();
	state->cpacr = fiber_portCPACR_REG;
	state->fpccr = fiber_portFPCCR_REG;
	fiber_portCOMPILER_BARRIER();
}

static FIBER_GENERAL_REGS_ONLY
void fiber_port_validate_validation_cpu_state(
		const FiberPortValidationCpuState *const before)
{
	FIBER_REQUIRE(before != NULL, 'C');
	fiber_portCOMPILER_BARRIER();
	FIBER_REQUIRE(__get_PRIMASK() == before->primask, 'r');
	FIBER_REQUIRE(__get_CONTROL() == before->control, 'l');
	FIBER_REQUIRE(fiber_port_basepri_read() == before->basepri, 'B');
	FIBER_REQUIRE(__get_FAULTMASK() == before->faultmask, 't');
	FIBER_REQUIRE(fiber_portCPACR_REG == before->cpacr, 'e');
	FIBER_REQUIRE(fiber_portFPCCR_REG == before->fpccr, 'E');
	fiber_port_fpu_require_ready();
	fiber_portCOMPILER_BARRIER();
}
#endif

static FIBER_GENERAL_REGS_ONLY
void fiber_port_prepare_start_msp_plan(void)
{
	FIBER_REQUIRE(fiber_port_start_msp_plan.prepared == 0u, 'M');
	uintptr_t top;

#if FIBER_REWIND_MSP
	const uint32_t first = fiber_port_read_initial_msp();
	fiber_portINST_SYNC_BARRIER();
	const uint32_t second = fiber_port_read_initial_msp();
	FIBER_REQUIRE(first != 0u, 'M');
	FIBER_REQUIRE(first == second, 'V');
	top = (uintptr_t)first;
#else
	top = (uintptr_t)__get_MSP();
#endif

	FIBER_REQUIRE(top != 0u, 'M');
	FIBER_REQUIRE((top & ((uintptr_t)FIBER_PORT_STACK_ALIGNMENT - 1u)) == 0u,
			'M');
	FIBER_REQUIRE(top >= sizeof(uint32_t), 'R');
	FIBER_REQUIRE(fiber_addr_plausible_ram(top - sizeof(uint32_t), top) != 0,
			'R');

	fiber_port_start_msp_plan.top = top;
	{
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
		fiber_portCOMPILER_BARRIER();
	}
	fiber_port_start_msp_plan.prepared = 1u;
	{
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
		fiber_portCOMPILER_BARRIER();
	}
}

static FIBER_GENERAL_REGS_ONLY
void fiber_port_validate_start_msp_for_boot(const FiberPortBoot *const boot)
{
	FIBER_REQUIRE(boot != NULL, 'n');
	FIBER_REQUIRE(fiber_port_start_msp_plan.prepared == 1u, 'M');
	const uintptr_t top = fiber_port_start_msp_plan.top;
	FIBER_REQUIRE(top != 0u, 'M');
	FIBER_REQUIRE((top & ((uintptr_t)FIBER_PORT_STACK_ALIGNMENT - 1u)) == 0u,
			'M');
	FIBER_REQUIRE(!(top > boot->stack_base && top <= boot->stack_top), 'O');
	const size_t gap = (top > boot->stack_top)
			? (size_t)(top - boot->stack_top)
			: (size_t)(boot->stack_base - top);
	FIBER_REQUIRE(gap >= (size_t)FIBER_STACK_REDZONE_BYTES, 'G');

#if FIBER_REWIND_MSP
	const uint32_t first = fiber_port_read_initial_msp();
	fiber_portINST_SYNC_BARRIER();
	const uint32_t second = fiber_port_read_initial_msp();
	FIBER_REQUIRE(first != 0u, 'M');
	FIBER_REQUIRE(first == second, 'V');
	FIBER_REQUIRE(top == (uintptr_t)first, 'W');
#endif
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_context_validate_save_current(const FiberContext *const ctx)
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
	FIBER_REQUIRE(fiber_addr_plausible_ram(ctx->boot.stack_base,
			ctx->boot.stack_top) != 0, 'P');
#endif
	fiber_port_validate_stack_canary(ctx);
	/* CPACR/FPCCR must be valid before PendSV executes a conditional VFP
	 * instruction. LSPACT is deliberately allowed here: an FP Thread context
	 * may legitimately complete lazy preservation while PendSV enters. */
	fiber_port_fpu_require_configured();

	/* The saved SP names the previous restore image while this context runs.
	 * Validate live PSP before naked assembly reads any boot metadata. */
	const uintptr_t psp = (uintptr_t)__get_PSP();
	FIBER_REQUIRE((psp & ((uintptr_t)sizeof(uint32_t) - 1u)) == 0u, 'A');
	FIBER_REQUIRE(psp >= ctx->boot.stack_base, 'U');
	FIBER_REQUIRE(psp <= ctx->boot.stack_top, 'T');
#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH
	fiber_port_validate_validation_cpu_state(&cpu_state);
#endif
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_context_validate_restore(FiberContext *const ctx)
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
	FIBER_REQUIRE(fiber_addr_plausible_ram(ctx->boot.stack_base,
			ctx->boot.stack_top) != 0, 'P');
#endif
	fiber_port_validate_stack_canary(ctx);
	fiber_port_fpu_require_configured();
	FIBER_REQUIRE(ctx->sp != NULL, 'P');

	const uintptr_t sp = (uintptr_t)ctx->sp;
	FIBER_REQUIRE((sp & 7u) == (uintptr_t)FIBER_PORT_SAVED_SP_MOD8, 'A');
	FIBER_REQUIRE(sp >= ctx->boot.stack_base, 'U');
	FIBER_REQUIRE(sp < ctx->boot.stack_top, 'T');
	const uintptr_t available = ctx->boot.stack_top - sp;
	FIBER_REQUIRE(available >= (uintptr_t)FIBER_PORT_INITIAL_CONTEXT_BYTES,
			'X');

	const uint32_t *const words = (const uint32_t *)sp;
	FIBER_REQUIRE(words[0] == (uint32_t)ctx->boot.stack_base, 'L');
	const uint32_t exc_return = words[FIBER_PORT_EXC_RETURN_WORD_INDEX];
	FIBER_REQUIRE(fiber_port_exc_return_is_valid(exc_return) != 0u, 'x');
	const uint32_t extended = (exc_return & 0x10u) == 0u;
	const uintptr_t high_fp_words = extended != 0u
			? ((uintptr_t)FIBER_PORT_HIGH_FP_SOFTWARE_BYTES / sizeof(uint32_t))
			: 0u;
	const uintptr_t hardware_words =
			(uintptr_t)FIBER_PORT_SOFTWARE_FRAME_WORDS + high_fp_words;
	uintptr_t required = (uintptr_t)FIBER_PORT_SOFTWARE_FRAME_BYTES +
			(uintptr_t)FIBER_PORT_EXC_BASE_BYTES;
	if (extended != 0u) {
		required += (uintptr_t)FIBER_PORT_HIGH_FP_SOFTWARE_BYTES +
				(uintptr_t)FIBER_PORT_EXC_FP_EXT_BYTES;
	}
	FIBER_REQUIRE(available >= required, 'X');

	const uint32_t stacked_pc = words[hardware_words + 6u];
	const uint32_t stacked_xpsr = words[hardware_words + 7u];
	FIBER_REQUIRE((stacked_xpsr & (1u << 24u)) != 0u, 'x');
	FIBER_REQUIRE((stacked_xpsr & 0x1FFu) == 0u, 'x');
	FIBER_REQUIRE(stacked_pc >= 2u, 'x');
	FIBER_REQUIRE((stacked_pc & 1u) == 0u, 'x');
#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH
	FIBER_REQUIRE(fiber_addr_plausible_code((uintptr_t)stacked_pc) != 0, 'c');
#endif
	if ((stacked_xpsr & (1u << 9u)) != 0u) {
		required += (uintptr_t)FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES;
	}
	FIBER_REQUIRE(available >= required, 'X');
#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH
	fiber_port_validate_validation_cpu_state(&cpu_state);
#endif
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uintptr_t fiber_port_context_prepare_first_start(FiberContext *const ctx)
{
	fiber_port_context_validate_restore(ctx);
	/* A newly constructed context always starts basic. An extended first image
	 * would claim s16-s31 state that has never been captured for this fiber. */
	FIBER_REQUIRE(ctx->sp[FIBER_PORT_EXC_RETURN_WORD_INDEX] ==
			FIBER_PORT_INITIAL_EXC_RETURN, 'x');
	FIBER_REQUIRE(ctx->sp[0] == (uint32_t)ctx->boot.stack_base, 'L');
	fiber_port_validate_start_msp_for_boot(&ctx->boot);
#if FIBER_REWIND_MSP
	return fiber_port_start_msp_plan.top;
#else
	return 0u;
#endif
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_require_start_environment(void)
{
	const uint32_t control = __get_CONTROL();
	FIBER_REQUIRE(__get_IPSR() == 0u, 'I');
	FIBER_REQUIRE((control & 1u) == 0u, 'p');
	FIBER_REQUIRE((control & 2u) == 0u, 's');
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_require_start_interrupt_state(void)
{
	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_prepare(void)
{
#ifdef SCB_CCR_STKALIGN_Msk
	SCB->CCR |= SCB_CCR_STKALIGN_Msk;
	{
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
	}
	FIBER_REQUIRE((SCB->CCR & SCB_CCR_STKALIGN_Msk) != 0u, 'A');
#endif
	fiber_port_fpu_prepare();
	fiber_port_fpu_require_ready();
	fiber_port_prepare_start_msp_plan();
}

/* ARM_CM33F TrustZone Non-secure immutable boot metadata and construction. */

#include "fiber_portmacro.h"
#include "fiber_port_boot.h"
#include "../../../fiber_runtime_port_abi.h"

/* Staged construction retains its exact expectation. Only an explicit test
 * fixture (or future complete runtime) supplies the matching cohort provider. */

#if FIBER_ALLOW_PERMISSIVE_ADDRESS_MAP_HOOKS
FIBER_WEAK FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_ram(uintptr_t start, uintptr_t end)
{
	(void)start;
	(void)end;
	return 1;
}

FIBER_WEAK FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_code(uintptr_t addr)
{
	(void)addr;
	return 1;
}
#endif

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
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
	hash = fiber_port_hash32_accum(hash, boot->secure_stack_bytes);
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
	FIBER_REQUIRE((boot->secure_stack_bytes == 0u) ||
			((boot->secure_stack_bytes >= 8u) &&
			 ((boot->secure_stack_bytes & 7u) == 0u)), 'D');
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
FiberPortBoot fiber_port_boot_create(void *const begin,
		void *const end,
		const entry_t entry,
		void *const arg)
{
	FiberPortBoot boot = (FiberPortBoot){0};
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

	boot.begin = begin;
	boot.end = end;
	boot.stack_base = stack_base;
	boot.stack_top = stack_top;
	boot.avail = available;
	boot.entry = entry;
	boot.arg = arg;
	boot.secure_stack_bytes = 0u;
	boot.abi_port_id = FIBER_PORT_CONTEXT_ABI_PORT_ID;
	boot.abi_layout_version = FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION;
	boot.abi_context_size = (uint32_t)sizeof(FiberContext);
	boot.abi_context_alignment = (uint32_t)_Alignof(FiberContext);
	boot.abi_feature_mask = FIBER_PORT_CONTEXT_ABI_FEATURE_MASK;
	boot.abi_initial_exc_return = FIBER_PORT_INITIAL_EXC_RETURN;
	boot.magic = FIBER_PORT_BOOT_RECORD_MAGIC;
	boot.version = FIBER_PORT_BOOT_RECORD_VERSION;
	boot.sealed = 0u;
	boot.guard_lo = FIBER_PORT_BOOT_RECORD_GUARD_LO;
	boot.guard_hi = FIBER_PORT_BOOT_RECORD_GUARD_HI;
	boot.hash = 0u;
	boot.hash = fiber_port_boot_record_compute_hash(&boot);
	boot.sealed = 1u;

	{
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
		fiber_portCOMPILER_BARRIER();
	}
	fiber_port_boot_check(&boot);
	return boot;
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

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_boot_attach_secure_stack(FiberPortBoot *const boot,
		const uint32_t secure_stack_bytes)
{
	FIBER_REQUIRE(boot != NULL, 'n');
	fiber_port_boot_check(boot);
	FIBER_REQUIRE(boot->secure_stack_bytes == 0u, 'D');
	FIBER_REQUIRE((secure_stack_bytes >= 8u) &&
			((secure_stack_bytes & 7u) == 0u), 'D');

	boot->sealed = 0u;
	fiber_portCOMPILER_BARRIER();
	boot->secure_stack_bytes = secure_stack_bytes;
	boot->hash = fiber_port_boot_record_compute_hash(boot);
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_portCOMPILER_BARRIER();
	boot->sealed = 1u;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_portCOMPILER_BARRIER();
	fiber_port_boot_check(boot);
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_context_frame_check(const FiberContext *const ctx,
		const uint32_t expected_handle)
{
	FIBER_REQUIRE(ctx != NULL, 'C');
	fiber_port_boot_check(&ctx->boot);
	const uint32_t *const frame = ctx->sp;
	FIBER_REQUIRE(frame != NULL, 'P');
	FIBER_REQUIRE((uintptr_t)frame ==
			(ctx->boot.stack_top - FIBER_PORT_INITIAL_CONTEXT_BYTES), 'S');
	FIBER_REQUIRE((uintptr_t)frame >= ctx->boot.stack_base, 'U');
	FIBER_REQUIRE(*(const volatile uint32_t *)frame == expected_handle, 'D');
	FIBER_REQUIRE(frame[1] == (uint32_t)ctx->boot.stack_base, 'L');
	FIBER_REQUIRE(frame[FIBER_PORT_EXC_RETURN_WORD_INDEX] ==
			FIBER_PORT_INITIAL_EXC_RETURN, 'x');
	FIBER_REQUIRE(frame[FIBER_PORT_SOFTWARE_FRAME_WORDS] ==
			(uint32_t)(uintptr_t)ctx->boot.arg, '0');
	FIBER_REQUIRE(frame[3] == 0u, '4');
	FIBER_REQUIRE(frame[4] == 0u, '5');
	FIBER_REQUIRE(frame[5] == 0u, '6');
	FIBER_REQUIRE(frame[6] == 0u, '7');
	FIBER_REQUIRE(frame[7] == 0u, '8');
	FIBER_REQUIRE(frame[9] == 0u, '1');
	FIBER_REQUIRE(frame[10] == 0u, '1');
	FIBER_REQUIRE(frame[12] == 0u, '1');
	FIBER_REQUIRE(frame[13] == 0u, '2');
	FIBER_REQUIRE(frame[14] == 0u, '3');
	FIBER_REQUIRE(frame[15] == 0u, '2');
	FIBER_REQUIRE(frame[FIBER_PORT_SOFTWARE_FRAME_WORDS + 5u] ==
			(((uint32_t)(uintptr_t)&fiber_internal_task_return) | 1u), 'R');
	FIBER_REQUIRE(frame[FIBER_PORT_SOFTWARE_FRAME_WORDS + 6u] ==
			fiber_port_stacked_pc((uintptr_t)ctx->boot.entry), 'x');
	FIBER_REQUIRE(frame[FIBER_PORT_SOFTWARE_FRAME_WORDS + 7u] ==
			fiber_port_initial_xpsr(), 'X');
#if FIBER_STACK_CANARY
	const uintptr_t canary_cell = fiber_word_align_up((uintptr_t)ctx->boot.begin);
	FIBER_REQUIRE(canary_cell <= (UINTPTR_MAX - sizeof(uint32_t)), 'c');
	FIBER_REQUIRE((canary_cell + sizeof(uint32_t)) <=
			ctx->boot.stack_base, 'c');
	FIBER_REQUIRE(*(const volatile uint32_t *)canary_cell ==
			FIBER_INTERNAL_STACK_CANARY_VALUE, 'c');
#endif
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_context_initial_frame_check(const FiberContext *const ctx)
{
	fiber_port_context_frame_check(ctx, fiber_portNO_SECURE_CONTEXT);
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_init_context_frame(FiberContext *const ctx,
		const uint32_t initial_r9)
{
	FIBER_REQUIRE(ctx != NULL, 'C');
	fiber_port_boot_record_check(&ctx->boot);

	uint32_t *const frame = (uint32_t *)ctx->boot.stack_top -
			19u;

	/* Exact FreeRTOS companion-aware non-MPU basic initial frame. The SecureContext
	 * handle remains zero until first-start allocation succeeds. */
	frame[0u] = fiber_portNO_SECURE_CONTEXT;
	frame[1u] = (uint32_t)ctx->boot.stack_base;
	frame[2u] = fiber_portINITIAL_EXC_RETURN;
	frame[3u] = 0u;
	frame[4u] = 0u;
	frame[5u] = 0u;
	frame[6u] = 0u;
	frame[7u] = 0u;
	frame[8u] = initial_r9;
	frame[9u] = 0u;
	frame[10u] = 0u;
	frame[11u] = (uint32_t)(uintptr_t)ctx->boot.arg;
	frame[12u] = 0u;
	frame[13u] = 0u;
	frame[14u] = 0u;
	frame[15u] = 0u;
	frame[16u] =
			((uint32_t)(uintptr_t)&fiber_internal_task_return) | 1u;
	frame[17u] =
			fiber_port_stacked_pc((uintptr_t)ctx->boot.entry);
	frame[18u] = fiber_port_initial_xpsr();

	ctx->sp = frame;
	{
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
		fiber_portCOMPILER_BARRIER();
	}
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_context_init(FiberContext *const ctx,
		void *const stack_begin,
		void *const stack_end,
		const entry_t entry,
		void *const arg)
{
	const uint32_t initial_r9 = fiber_port_read_r9();
	FIBER_RUNTIME_PORT_ABI_RETAIN_V1();
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

	ctx->boot = fiber_port_boot_create(stack_begin, stack_end, entry, arg);
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
	fiber_port_init_context_frame(ctx, initial_r9);

	FIBER_REQUIRE((uintptr_t)ctx->sp ==
			(ctx->boot.stack_top -
			 (uintptr_t)FIBER_PORT_INITIAL_CONTEXT_BYTES), 'S');
	FIBER_REQUIRE(((uintptr_t)ctx->sp & 7u) ==
			(uintptr_t)FIBER_PORT_SAVED_SP_MOD8, 'A');
	FIBER_REQUIRE((uintptr_t)ctx->sp >= ctx->boot.stack_base, 'U');
	fiber_port_context_initial_frame_check(ctx);
	FIBER_REQUIRE(ctx->sp[8u] == initial_r9, '9');
	{
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
		fiber_portCOMPILER_BARRIER();
	}
}

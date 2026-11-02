/* ARM_CM55 TrustZone Non-secure immutable boot metadata and construction. */

#include "fiber_portmacro.h"
#include "fiber_port_boot.h"
#include "fiber_port_private.h"
#include "../../../fiber_runtime_port_abi.h"

/* The mandatory runtime object supplies the exact context cohort provider. */

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

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_context_first_start_frame_check(const FiberContext *const ctx,
		const uint32_t expected_handle)
{
	fiber_port_context_frame_check(ctx, expected_handle);
	FIBER_REQUIRE((ctx->boot.secure_stack_bytes == 0u) ==
			(expected_handle == fiber_portNO_SECURE_CONTEXT), 'D');
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_running_context_check(const FiberContext *const ctx,
		const FiberPortRunningCpuState *const cpu)
{
	const uintptr_t begin = (uintptr_t)ctx;
	FIBER_REQUIRE(begin != 0u && (begin & (_Alignof(FiberContext) - 1u)) == 0u, 'C');
	FIBER_REQUIRE(begin <= UINTPTR_MAX - sizeof(*ctx), 'O');
	const uintptr_t end = begin + sizeof(*ctx);
	const uintptr_t low = (uintptr_t)__fiber_c55s_ns_msp_stack_start__;
	const uintptr_t high = (uintptr_t)__fiber_c55s_ns_msp_stack_end__;
	FIBER_REQUIRE(high > low && ((low | high) & 7u) == 0u, 'M');
	FIBER_REQUIRE(end <= low || begin >= high, 'C');
#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH
	FIBER_REQUIRE(fiber_addr_plausible_ram(begin, end) != 0, 'C');
	fiber_port_running_cpu_check(cpu);
#endif
#if FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH
	fiber_port_boot_record_check(&ctx->boot);
#else
	fiber_port_boot_record_fast_check(&ctx->boot);
#endif
	const uintptr_t raw_begin = (uintptr_t)ctx->boot.begin;
	const uintptr_t raw_end = (uintptr_t)ctx->boot.end;
	const uintptr_t word_begin = fiber_word_align_up(raw_begin);
	FIBER_REQUIRE(word_begin <= UINTPTR_MAX - FIBER_STACK_REDZONE_BYTES, 'o');
	const uintptr_t expected_base = fiber_stack_align_up(
			word_begin + FIBER_STACK_REDZONE_BYTES);
	FIBER_REQUIRE(ctx->boot.stack_base == expected_base &&
			ctx->boot.stack_top == fiber_stack_align_down(raw_end), 'Z');
	FIBER_REQUIRE(ctx->boot.avail >= FIBER_STACK_WITHOUT_REDZONE, 'h');
#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH
	FIBER_REQUIRE(fiber_addr_plausible_ram(raw_begin, raw_end) != 0, 'P');
	fiber_port_running_cpu_check(cpu);
	FIBER_REQUIRE(fiber_addr_plausible_ram(
			ctx->boot.stack_base, ctx->boot.stack_top) != 0, 'P');
	fiber_port_running_cpu_check(cpu);
#else
	(void)cpu;
#endif
	FIBER_REQUIRE(end <= (uintptr_t)ctx->boot.begin ||
			begin >= (uintptr_t)ctx->boot.end, 'C');
	FIBER_REQUIRE((uintptr_t)ctx->boot.end <= low ||
			(uintptr_t)ctx->boot.begin >= high, 'M');
#if FIBER_STACK_CANARY
	const uintptr_t raw = (uintptr_t)ctx->boot.begin;
	const uintptr_t canary = fiber_word_align_up(raw);
	FIBER_REQUIRE(canary >= raw && canary <= UINTPTR_MAX - sizeof(uint32_t), 'c');
	FIBER_REQUIRE(canary + sizeof(uint32_t) <= ctx->boot.stack_base &&
			canary + sizeof(uint32_t) <= (uintptr_t)ctx->boot.end, 'c');
#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH
	FIBER_REQUIRE(fiber_addr_plausible_ram(raw, ctx->boot.stack_base) != 0, 'c');
	fiber_port_running_cpu_check(cpu);
#endif
	FIBER_REQUIRE(*(const volatile uint32_t *)canary ==
			FIBER_INTERNAL_STACK_CANARY_VALUE, 'c');
#endif
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_running_exc_return_check(const uint32_t exc_return)
{
	/* ES=0 requires DCRS=1 even when S=1: DC is not an NS return token. */
	FIBER_REQUIRE(exc_return == fiber_portINITIAL_EXC_RETURN ||
			exc_return == FIBER_PORT_CM55_SECURE_ORIGIN_EXC_RETURN, 'x');
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_running_hardware_frame_check(const uintptr_t psp,
		const uintptr_t top, const FiberPortRunningCpuState *const cpu)
{
	FIBER_REQUIRE(psp <= top && top - psp >= FIBER_PORT_EXC_BASE_BYTES, 'X');
	const volatile uint32_t *const frame = (const volatile uint32_t *)psp;
	const uint32_t xpsr = frame[7];
	const uint32_t pc = frame[6];
	FIBER_REQUIRE((xpsr & 0x01000000u) != 0u && (xpsr & 0x1FFu) == 0u, 'X');
	if ((xpsr & 0x200u) != 0u) {
		FIBER_REQUIRE(top - psp >= FIBER_PORT_EXC_BASE_BYTES +
				FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES, 'X');
	}
	FIBER_REQUIRE(pc >= 2u && (pc & 1u) == 0u, 'x');
#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH
	FIBER_REQUIRE(fiber_addr_plausible_code((uintptr_t)pc) != 0, 'c');
	fiber_port_running_cpu_check(cpu);
#else
	(void)cpu;
#endif
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_context_live_frame_check(const FiberContext *const ctx,
		const uintptr_t psp, const uint32_t exc_return)
{
	FiberPortRunningCpuState cpu;
	fiber_port_running_cpu_capture(&cpu);
	fiber_port_running_exc_return_check(exc_return);
	fiber_port_running_context_check(ctx, &cpu);
	FIBER_REQUIRE(cpu.psp == psp && cpu.psplim == ctx->boot.stack_base, 'L');
	FIBER_REQUIRE((psp & 7u) == 0u, 'A');
	FIBER_REQUIRE(psp >= ctx->boot.stack_base && psp <= ctx->boot.stack_top, 'P');
	if ((exc_return & 0x40u) != 0u) {
		FIBER_REQUIRE(ctx->boot.secure_stack_bytes != 0u, 'D');
		FIBER_REQUIRE(psp - ctx->boot.stack_base >=
				FIBER_PORT_CM55_SECURE_HEADER_BYTES, 'X');
		/* No NS hardware frame or r4-r11 exists for Secure origin. */
	} else {
		FIBER_REQUIRE(psp - ctx->boot.stack_base >=
				FIBER_PORT_SOFTWARE_FRAME_BYTES, 'X');
		fiber_port_running_hardware_frame_check(psp, ctx->boot.stack_top, &cpu);
	}
	fiber_port_running_cpu_check(&cpu);
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_context_saved_frame_check(const FiberContext *const ctx)
{
	FiberPortRunningCpuState cpu;
	fiber_port_running_cpu_capture(&cpu);
	fiber_port_running_context_check(ctx, &cpu);
	const uintptr_t sp = (uintptr_t)ctx->sp;
	FIBER_REQUIRE((sp & 7u) == FIBER_PORT_SAVED_SP_MOD8, 'A');
	FIBER_REQUIRE(sp >= ctx->boot.stack_base && sp <= ctx->boot.stack_top, 'P');
	const uintptr_t available = ctx->boot.stack_top - sp;
	FIBER_REQUIRE(available >= FIBER_PORT_CM55_SECURE_HEADER_BYTES, 'X');
	const volatile uint32_t *const frame = (const volatile uint32_t *)sp;
	const uint32_t handle = frame[0];
	FIBER_REQUIRE(frame[1] == ctx->boot.stack_base, 'L');
	const uint32_t exc_return = frame[2];
	fiber_port_running_exc_return_check(exc_return);
	if (ctx->boot.secure_stack_bytes == 0u) {
		FIBER_REQUIRE(handle == 0u, 'D');
	}
	if ((exc_return & 0x40u) != 0u) {
		FIBER_REQUIRE(ctx->boot.secure_stack_bytes != 0u && handle != 0u, 'D');
	} else {
		FIBER_REQUIRE(available >= FIBER_PORT_INITIAL_CONTEXT_BYTES, 'X');
		fiber_port_running_hardware_frame_check(
				sp + FIBER_PORT_SOFTWARE_FRAME_BYTES, ctx->boot.stack_top, &cpu);
		if (ctx->boot.secure_stack_bytes != 0u && handle == 0u) {
			/* Only an exact attached cold image may allocate lazily. */
			fiber_port_context_initial_frame_check(ctx);
		}
	}
	fiber_port_running_cpu_check(&cpu);
	return exc_return;
}

enum FiberPortInitialFrameWord {
	fiber_portFRAME_SECURE_CONTEXT = 0,
	fiber_portFRAME_PSPLIM = 1,
	fiber_portFRAME_EXC_RETURN = 2,
	fiber_portFRAME_R4 = 3,
	fiber_portFRAME_R5 = 4,
	fiber_portFRAME_R6 = 5,
	fiber_portFRAME_R7 = 6,
	fiber_portFRAME_R8 = 7,
	fiber_portFRAME_R9 = 8,
	fiber_portFRAME_R10 = 9,
	fiber_portFRAME_R11 = 10,
	fiber_portFRAME_R0 = 11,
	fiber_portFRAME_R1 = 12,
	fiber_portFRAME_R2 = 13,
	fiber_portFRAME_R3 = 14,
	fiber_portFRAME_R12 = 15,
	fiber_portFRAME_LR = 16,
	fiber_portFRAME_PC = 17,
	fiber_portFRAME_XPSR = 18,
	fiber_portFRAME_WORD_COUNT = 19
};

FIBER_STATIC_ASSERT(fiber_portFRAME_EXC_RETURN ==
		FIBER_PORT_EXC_RETURN_WORD_INDEX,
		"[fiber]: ARM_CM55 EXC_RETURN offset changed");
FIBER_STATIC_ASSERT(fiber_portFRAME_R0 == FIBER_PORT_SOFTWARE_FRAME_WORDS,
		"[fiber]: ARM_CM55 hardware frame offset changed");
FIBER_STATIC_ASSERT(fiber_portFRAME_WORD_COUNT * sizeof(uint32_t) ==
		FIBER_PORT_INITIAL_CONTEXT_BYTES,
		"[fiber]: ARM_CM55 initial frame size changed");

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_init_context_frame(FiberContext *const ctx,
		const uint32_t initial_r9)
{
	FIBER_REQUIRE(ctx != NULL, 'C');
	fiber_port_boot_record_check(&ctx->boot);

	uint32_t *const frame = (uint32_t *)ctx->boot.stack_top -
			fiber_portFRAME_WORD_COUNT;

	/* Exact FreeRTOS companion-aware no-MPU/no-FPU frame. The SecureContext
	 * handle remains zero until first-start allocation succeeds. */
	frame[fiber_portFRAME_SECURE_CONTEXT] = fiber_portNO_SECURE_CONTEXT;
	frame[fiber_portFRAME_PSPLIM] = (uint32_t)ctx->boot.stack_base;
	frame[fiber_portFRAME_EXC_RETURN] = fiber_portINITIAL_EXC_RETURN;
	frame[fiber_portFRAME_R4] = 0u;
	frame[fiber_portFRAME_R5] = 0u;
	frame[fiber_portFRAME_R6] = 0u;
	frame[fiber_portFRAME_R7] = 0u;
	frame[fiber_portFRAME_R8] = 0u;
	frame[fiber_portFRAME_R9] = initial_r9;
	frame[fiber_portFRAME_R10] = 0u;
	frame[fiber_portFRAME_R11] = 0u;
	frame[fiber_portFRAME_R0] = (uint32_t)(uintptr_t)ctx->boot.arg;
	frame[fiber_portFRAME_R1] = 0u;
	frame[fiber_portFRAME_R2] = 0u;
	frame[fiber_portFRAME_R3] = 0u;
	frame[fiber_portFRAME_R12] = 0u;
	frame[fiber_portFRAME_LR] =
			((uint32_t)(uintptr_t)&fiber_internal_task_return) | 1u;
	frame[fiber_portFRAME_PC] =
			fiber_port_stacked_pc((uintptr_t)ctx->boot.entry);
	frame[fiber_portFRAME_XPSR] = fiber_port_initial_xpsr();

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
	FIBER_REQUIRE(ctx->sp[fiber_portFRAME_R9] == initial_r9, '9');
	{
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
		fiber_portCOMPILER_BARRIER();
	}
}

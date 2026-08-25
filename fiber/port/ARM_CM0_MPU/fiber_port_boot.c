/* ARM_CM0_MPU slice-2 construction and exact MPU-image mechanics.
 *
 * This source owns no exception handler, does not program MPU registers, and
 * does not enter the forward runtime ABI. It only builds and seals the exact
 * privileged image that a later Thumb-1 SVC/PendSV slice will consume.
 */

#include "fiber_port_boot.h"

#include "../../fiber_panic.h"

#define FIBER_CM0_MPU_BOOT \
	FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY

/* Slice 3 will define this as a port-owned unprivileged SVC-return veneer.
 * Keeping the unresolved reference here preserves the required initial LR
 * provenance without introducing a premature runtime implementation. */
extern FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_unprivileged_task_return(void);

static FIBER_CM0_MPU_BOOT
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

static FIBER_CM0_MPU_BOOT
int fiber_port_ranges_overlap(uintptr_t first_start,
		uintptr_t first_end,
		uintptr_t second_start,
		uintptr_t second_end)
{
	return (first_start < second_end) && (second_start < first_end);
}

static FIBER_CM0_MPU_BOOT
uintptr_t fiber_port_cm0_mpu_stack_align_down(uintptr_t value)
{
	return value & ~((uintptr_t)FIBER_PORT_STACK_ALIGNMENT - 1u);
}

static FIBER_CM0_MPU_BOOT
uintptr_t fiber_port_cm0_mpu_stack_align_up(uintptr_t value)
{
	const uintptr_t mask = (uintptr_t)FIBER_PORT_STACK_ALIGNMENT - 1u;
	FIBER_REQUIRE(value <= UINTPTR_MAX - mask, 'O');
	return (value + mask) & ~mask;
}

static FIBER_CM0_MPU_BOOT
int fiber_port_mpu_access_encoding_is_valid(uint32_t attributes)
{
	const uint32_t access = attributes & fiber_portMPU_RASR_AP_MASK;
	return (access == fiber_portMPU_REGION_PRIV_NA_UNPRIV_NA) ||
			(access == fiber_portMPU_REGION_PRIV_RW_UNPRIV_NA) ||
			(access == fiber_portMPU_REGION_PRIV_RW_UNPRIV_RO) ||
			(access == fiber_portMPU_REGION_PRIV_RW_UNPRIV_RW) ||
			(access == fiber_portMPU_REGION_PRIV_RO_UNPRIV_NA) ||
			(access == fiber_portMPU_REGION_PRIV_RO_UNPRIV_RO);
}

FIBER_CM0_MPU_BOOT
int fiber_port_mpu_try_encode_exact_region(uintptr_t start,
		uintptr_t end,
		uint32_t region_number,
		uint32_t attributes,
		FiberPortMpuRegionRegisters *encoded)
{
	const uint32_t allowed_attributes = fiber_portMPU_RASR_AP_MASK |
			fiber_portMPU_RASR_MEMORY_MASK |
			fiber_portMPU_REGION_EXECUTE_NEVER;

	if ((encoded == NULL) || (end <= start) ||
			(region_number >= fiber_portMPU_TOTAL_REGIONS) ||
			((attributes & ~allowed_attributes) != 0u) ||
			(fiber_port_mpu_access_encoding_is_valid(attributes) == 0)) {
		return 0;
	}

	const uintptr_t extent = end - start;
	if ((extent < (uintptr_t)fiber_portMPU_MIN_REGION_SIZE) ||
			(extent > (uintptr_t)fiber_portMPU_MAX_EXACT_REGION_SIZE) ||
			((extent & (extent - 1u)) != 0u) ||
			((start & (extent - 1u)) != 0u)) {
		return 0;
	}

	uint32_t encoded_size = fiber_portMPU_REGION_SIZE_256B;
	uint32_t represented_size = fiber_portMPU_MIN_REGION_SIZE;
	while ((uintptr_t)represented_size < extent) {
		represented_size <<= 1u;
		encoded_size += 2u;
	}
	if ((uintptr_t)represented_size != extent ||
			(encoded_size & ~fiber_portMPU_RASR_SIZE_MASK) != 0u) {
		return 0;
	}

	encoded->rbar = ((uint32_t)start & fiber_portMPU_RBAR_ADDRESS_MASK) |
			fiber_portMPU_RBAR_REGION_VALID | region_number;
	encoded->rasr = attributes | encoded_size |
			fiber_portMPU_RASR_REGION_ENABLE;
	return 1;
}

static FIBER_CM0_MPU_BOOT
void fiber_port_mpu_encode_exact_region(uintptr_t start,
		uintptr_t end,
		uint32_t region_number,
		uint32_t attributes,
		FiberPortMpuRegionRegisters *encoded)
{
	FIBER_REQUIRE(fiber_port_mpu_try_encode_exact_region(start, end,
			region_number, attributes, encoded) != 0, 'M');
}

static FIBER_CM0_MPU_BOOT
void fiber_port_mpu_disable_region(uint32_t region_number,
		FiberPortMpuRegionRegisters *encoded)
{
	FIBER_REQUIRE(encoded != NULL, 'M');
	FIBER_REQUIRE(region_number < fiber_portMPU_TOTAL_REGIONS, 'M');
	encoded->rbar = fiber_portMPU_RBAR_REGION_VALID | region_number;
	encoded->rasr = 0u;
}

static FIBER_CM0_MPU_BOOT
void fiber_port_context_pointer_check(const FiberContext *ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'C');
	const uintptr_t context_start = (uintptr_t)ctx;
	FIBER_REQUIRE((context_start & ((uintptr_t)_Alignof(FiberContext) - 1u)) ==
			0u, 'A');
	FIBER_REQUIRE(context_start <= UINTPTR_MAX - sizeof(*ctx), 'O');
}

FIBER_CM0_MPU_BOOT
uint32_t fiber_port_context_compute_seal(const FiberContext *ctx)
{
	/* This helper is selected-port surface, so preserve the same pointer
	 * precondition as the full checker before reading boot metadata. */
	fiber_port_context_pointer_check(ctx);
	const FiberPortBoot *const boot = &ctx->boot;
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
	hash = fiber_port_hash32_accum(hash, boot->abi_initial_control);
	hash = fiber_port_hash32_accum(hash, boot->abi_mpu_total_regions);
	hash = fiber_port_hash32_accum(hash, boot->abi_mpu_context_regions);
	hash = fiber_port_hash32_accum(hash, boot->abi_protected_context_words);
	hash = fiber_port_hash32_accum(hash, boot->magic);
	hash = fiber_port_hash32_accum(hash, (uint32_t)boot->version);
	hash = fiber_port_hash32_accum(hash, boot->guard_lo);
	hash = fiber_port_hash32_accum(hash, boot->guard_hi);

	for (uint32_t index = 0u;
			index < fiber_portMPU_CONTEXT_REGION_COUNT; ++index) {
		hash = fiber_port_hash32_accum(hash, ctx->mpu_regions[index].rbar);
		hash = fiber_port_hash32_accum(hash, ctx->mpu_regions[index].rasr);
	}
	return hash;
}

static FIBER_CM0_MPU_BOOT
void fiber_port_context_fast_check(const FiberContext *ctx)
{
	fiber_port_context_pointer_check(ctx);
	const FiberPortBoot *const boot = &ctx->boot;
	FIBER_REQUIRE(boot->magic == FIBER_PORT_BOOT_RECORD_MAGIC, 'm');
	FIBER_REQUIRE(boot->version == FIBER_PORT_BOOT_RECORD_VERSION, 'v');
	FIBER_REQUIRE(boot->sealed == 1u, 's');
	FIBER_REQUIRE(boot->guard_lo == FIBER_PORT_BOOT_RECORD_GUARD_LO, 'g');
	FIBER_REQUIRE(boot->guard_hi == FIBER_PORT_BOOT_RECORD_GUARD_HI, 'G');
	FIBER_REQUIRE(boot->abi_port_id == FIBER_PORT_CONTEXT_ABI_PORT_ID, 'q');
	FIBER_REQUIRE(boot->abi_layout_version ==
			FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION, 'q');
	FIBER_REQUIRE(boot->abi_context_size == (uint32_t)sizeof(*ctx), 'q');
	FIBER_REQUIRE(boot->abi_context_alignment ==
			(uint32_t)_Alignof(FiberContext), 'q');
	FIBER_REQUIRE(boot->abi_feature_mask ==
			FIBER_PORT_CONTEXT_ABI_FEATURE_MASK, 'q');
	FIBER_REQUIRE(boot->abi_initial_exc_return ==
			fiber_portINITIAL_EXC_RETURN, 'q');
	FIBER_REQUIRE(boot->abi_initial_control ==
			fiber_portINITIAL_CONTROL_UNPRIVILEGED, 'q');
	FIBER_REQUIRE(boot->abi_mpu_total_regions == fiber_portMPU_TOTAL_REGIONS,
			'q');
	FIBER_REQUIRE(boot->abi_mpu_context_regions ==
			fiber_portMPU_CONTEXT_REGION_COUNT, 'q');
	FIBER_REQUIRE(boot->abi_protected_context_words ==
			fiber_portPROTECTED_CONTEXT_WORDS, 'q');
	FIBER_REQUIRE(boot->begin != NULL, 'B');
	FIBER_REQUIRE(boot->end != NULL, 'T');
	FIBER_REQUIRE((uintptr_t)boot->end > (uintptr_t)boot->begin, 'N');
	FIBER_REQUIRE(boot->stack_top > boot->stack_base, 'S');
	FIBER_REQUIRE(boot->avail == (size_t)(boot->stack_top - boot->stack_base),
			'a');
	FIBER_REQUIRE(boot->entry != NULL, 'E');
	FIBER_REQUIRE((((uintptr_t)boot->entry) & 1u) != 0u, 'e');
}

FIBER_CM0_MPU_BOOT
void fiber_port_context_seal_check(const FiberContext *ctx)
{
	FiberPortMpuRegionRegisters expected_stack;
	fiber_port_context_fast_check(ctx);
	FIBER_REQUIRE(ctx->boot.hash == fiber_port_context_compute_seal(ctx), 'h');

	const uintptr_t context_start = (uintptr_t)ctx;
	const uintptr_t context_end = context_start + sizeof(*ctx);
	const uintptr_t raw_stack_start = (uintptr_t)ctx->boot.begin;
	const uintptr_t raw_stack_end = (uintptr_t)ctx->boot.end;
	FIBER_REQUIRE(!fiber_port_ranges_overlap(context_start, context_end,
			raw_stack_start, raw_stack_end), 'O');

	fiber_port_mpu_encode_exact_region(raw_stack_start, raw_stack_end,
			fiber_portMPU_STACK_REGION,
			fiber_portMPU_DEFAULT_STACK_ATTRIBUTES, &expected_stack);

	FIBER_REQUIRE(raw_stack_start <= UINTPTR_MAX -
			(uintptr_t)FIBER_STACK_REDZONE_BYTES, 'O');
	const uintptr_t expected_stack_base =
			fiber_port_cm0_mpu_stack_align_up(raw_stack_start +
					(uintptr_t)FIBER_STACK_REDZONE_BYTES);
	const uintptr_t expected_stack_top =
			fiber_port_cm0_mpu_stack_align_down(raw_stack_end);
	FIBER_REQUIRE(expected_stack_top > expected_stack_base, 'H');
	FIBER_REQUIRE(ctx->boot.stack_base == expected_stack_base, 'S');
	FIBER_REQUIRE(ctx->boot.stack_top == expected_stack_top, 'S');
	FIBER_REQUIRE(ctx->boot.avail >=
			(size_t)FIBER_PORT_CM0_MPU_STACK_REQUIRED_BYTES, 'H');

#if FIBER_STACK_CANARY
	FIBER_REQUIRE(raw_stack_start <= UINTPTR_MAX - sizeof(uint32_t), 'c');
	FIBER_REQUIRE((raw_stack_start + sizeof(uint32_t)) <=
			ctx->boot.stack_base, 'c');
	FIBER_REQUIRE(*(const volatile uint32_t *)raw_stack_start ==
			fiber_portSTACK_CANARY_VALUE, 'c');
#endif

	for (uint32_t index = fiber_portMPU_FIRST_CONFIGURABLE_REGION;
			index <= fiber_portMPU_LAST_CONFIGURABLE_REGION; ++index) {
		FIBER_REQUIRE(ctx->mpu_regions[index].rbar ==
				(fiber_portMPU_RBAR_REGION_VALID | index), 'M');
		FIBER_REQUIRE(ctx->mpu_regions[index].rasr == 0u, 'M');
	}
	FIBER_REQUIRE(ctx->mpu_regions[fiber_portMPU_STACK_REGION].rbar ==
			expected_stack.rbar, 'M');
	FIBER_REQUIRE(ctx->mpu_regions[fiber_portMPU_STACK_REGION].rasr ==
			expected_stack.rasr, 'M');
}

/* This check is constructor-only. The protected image becomes mutable once a
 * later PendSV implementation owns save/restore, so it must not become a
 * switch-time validator or part of the immutable seal. */
static FIBER_CM0_MPU_BOOT
void fiber_port_context_initial_image_check(const FiberContext *ctx,
		uintptr_t initial_psp,
		uintptr_t entry_address,
		void *arg,
		uint32_t initial_r9,
		uint32_t initial_return_address)
{
	const FiberPortProtectedContext *const image = &ctx->protected_context;
	const uint32_t initial_pc = (uint32_t)(entry_address &
			(uintptr_t)fiber_portSTART_ADDRESS_MASK);

	FIBER_REQUIRE(image->r4 == 0u, 'x');
	FIBER_REQUIRE(image->r5 == 0u, 'x');
	FIBER_REQUIRE(image->r6 == 0u, 'x');
	FIBER_REQUIRE(image->r7 == 0u, 'x');
	FIBER_REQUIRE(image->r8 == 0u, 'x');
	FIBER_REQUIRE(image->r9 == initial_r9, 'x');
	FIBER_REQUIRE(image->r10 == 0u, 'x');
	FIBER_REQUIRE(image->r11 == 0u, 'x');
	FIBER_REQUIRE(image->r0 == (uint32_t)(uintptr_t)arg, 'P');
	FIBER_REQUIRE(image->r1 == 0u, 'x');
	FIBER_REQUIRE(image->r2 == 0u, 'x');
	FIBER_REQUIRE(image->r3 == 0u, 'x');
	FIBER_REQUIRE(image->r12 == 0u, 'x');
	FIBER_REQUIRE(image->lr == initial_return_address, 'x');
	FIBER_REQUIRE(image->pc == initial_pc, 'x');
	FIBER_REQUIRE(image->xpsr == fiber_portINITIAL_XPSR, 'x');
	FIBER_REQUIRE(image->psp == (uint32_t)initial_psp, 'P');
	FIBER_REQUIRE(image->control ==
			fiber_portINITIAL_CONTROL_UNPRIVILEGED, 'q');
	FIBER_REQUIRE(image->exc_return == fiber_portINITIAL_EXC_RETURN, 'x');
	FIBER_REQUIRE(image->cursor_limit == 0u, 'P');
	FIBER_REQUIRE(ctx->protected_context_cursor == &image->cursor_limit, 'P');
	FIBER_REQUIRE(ctx->runtime_flags == 0u, 'q');
}

FIBER_CM0_MPU_BOOT
void fiber_port_context_init(FiberContext *ctx,
		void *stack_begin,
		void *stack_end,
		entry_t entry,
		void *arg)
{
	FiberPortMpuRegionRegisters stack_region;
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
	FIBER_REQUIRE(ctx != NULL, 'C');
	FIBER_REQUIRE(stack_begin != NULL, 'B');
	FIBER_REQUIRE(stack_end != NULL, 'T');
	FIBER_REQUIRE(entry != NULL, 'E');
	fiber_port_context_pointer_check(ctx);

	const uintptr_t context_start = (uintptr_t)ctx;
	const uintptr_t context_end = context_start + sizeof(*ctx);
	const uintptr_t raw_stack_start = (uintptr_t)stack_begin;
	const uintptr_t raw_stack_end = (uintptr_t)stack_end;
	const uintptr_t entry_address = (uintptr_t)entry;
	const uint32_t initial_r9 = fiber_port_read_r9();
	const uint32_t initial_return_address =
			((uint32_t)(uintptr_t)&fiber_port_unprivileged_task_return) | 1u;
	FIBER_REQUIRE(raw_stack_end > raw_stack_start, 'N');
	FIBER_REQUIRE((entry_address & 1u) != 0u, 'e');
	FIBER_REQUIRE((initial_return_address & 1u) != 0u, 'x');
	FIBER_REQUIRE(!fiber_port_ranges_overlap(context_start, context_end,
			raw_stack_start, raw_stack_end), 'O');

	fiber_port_mpu_encode_exact_region(raw_stack_start, raw_stack_end,
			fiber_portMPU_STACK_REGION,
			fiber_portMPU_DEFAULT_STACK_ATTRIBUTES, &stack_region);

	FIBER_REQUIRE(raw_stack_start <= UINTPTR_MAX -
			(uintptr_t)FIBER_STACK_REDZONE_BYTES, 'O');
	const uintptr_t stack_base = fiber_port_cm0_mpu_stack_align_up(
			raw_stack_start + (uintptr_t)FIBER_STACK_REDZONE_BYTES);
	const uintptr_t stack_top =
			fiber_port_cm0_mpu_stack_align_down(raw_stack_end);
	FIBER_REQUIRE(stack_top > stack_base, 'H');
	FIBER_REQUIRE((stack_top - stack_base) >=
			(uintptr_t)FIBER_PORT_CM0_MPU_STACK_REQUIRED_BYTES, 'H');
	FIBER_REQUIRE(stack_top >= (uintptr_t)FIBER_PORT_EXC_BASE_BYTES, 'H');
	const uintptr_t initial_psp = stack_top -
			(uintptr_t)FIBER_PORT_EXC_BASE_BYTES;
	FIBER_REQUIRE(initial_psp >= stack_base, 'H');
	FIBER_REQUIRE((initial_psp & 7u) == 0u, 'A');

	for (uint32_t index = fiber_portMPU_FIRST_CONFIGURABLE_REGION;
			index <= fiber_portMPU_LAST_CONFIGURABLE_REGION; ++index) {
		fiber_port_mpu_disable_region(index, &ctx->mpu_regions[index]);
	}
	ctx->mpu_regions[fiber_portMPU_STACK_REGION] = stack_region;

	/* Exact FreeRTOS ARM_CM0 MPU ulContext[20] word order. The complete
	 * initial basic frame stays protected here; it is not written to PSP. */
	ctx->protected_context.r4 = 0u;
	ctx->protected_context.r5 = 0u;
	ctx->protected_context.r6 = 0u;
	ctx->protected_context.r7 = 0u;
	ctx->protected_context.r8 = 0u;
	ctx->protected_context.r9 = initial_r9;
	ctx->protected_context.r10 = 0u;
	ctx->protected_context.r11 = 0u;
	ctx->protected_context.r0 = (uint32_t)(uintptr_t)arg;
	ctx->protected_context.r1 = 0u;
	ctx->protected_context.r2 = 0u;
	ctx->protected_context.r3 = 0u;
	ctx->protected_context.r12 = 0u;
	ctx->protected_context.lr = initial_return_address;
	ctx->protected_context.pc =
			(uint32_t)(entry_address & (uintptr_t)fiber_portSTART_ADDRESS_MASK);
	ctx->protected_context.xpsr = fiber_portINITIAL_XPSR;
	ctx->protected_context.psp = (uint32_t)initial_psp;
	ctx->protected_context.control = fiber_portINITIAL_CONTROL_UNPRIVILEGED;
	ctx->protected_context.exc_return = fiber_portINITIAL_EXC_RETURN;
	ctx->protected_context.cursor_limit = 0u;
	ctx->protected_context_cursor = &ctx->protected_context.cursor_limit;
	ctx->runtime_flags = 0u;

	ctx->boot.begin = stack_begin;
	ctx->boot.end = stack_end;
	ctx->boot.stack_base = stack_base;
	ctx->boot.stack_top = stack_top;
	ctx->boot.avail = (size_t)(stack_top - stack_base);
	ctx->boot.entry = entry;
	ctx->boot.arg = arg;
	ctx->boot.abi_port_id = FIBER_PORT_CONTEXT_ABI_PORT_ID;
	ctx->boot.abi_layout_version = FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION;
	ctx->boot.abi_context_size = (uint32_t)sizeof(*ctx);
	ctx->boot.abi_context_alignment = (uint32_t)_Alignof(FiberContext);
	ctx->boot.abi_feature_mask = FIBER_PORT_CONTEXT_ABI_FEATURE_MASK;
	ctx->boot.abi_initial_exc_return = fiber_portINITIAL_EXC_RETURN;
	ctx->boot.abi_initial_control = fiber_portINITIAL_CONTROL_UNPRIVILEGED;
	ctx->boot.abi_mpu_total_regions = fiber_portMPU_TOTAL_REGIONS;
	ctx->boot.abi_mpu_context_regions = fiber_portMPU_CONTEXT_REGION_COUNT;
	ctx->boot.abi_protected_context_words = fiber_portPROTECTED_CONTEXT_WORDS;
	ctx->boot.magic = FIBER_PORT_BOOT_RECORD_MAGIC;
	ctx->boot.version = FIBER_PORT_BOOT_RECORD_VERSION;
	ctx->boot.sealed = 0u;
	ctx->boot.guard_lo = FIBER_PORT_BOOT_RECORD_GUARD_LO;
	ctx->boot.guard_hi = FIBER_PORT_BOOT_RECORD_GUARD_HI;
	ctx->boot.hash = 0u;

#if FIBER_STACK_CANARY
	*(volatile uint32_t *)raw_stack_start = fiber_portSTACK_CANARY_VALUE;
#endif

	ctx->boot.hash = fiber_port_context_compute_seal(ctx);
	ctx->boot.sealed = 1u;
	__COMPILER_BARRIER();
	fiber_port_context_seal_check(ctx);
	fiber_port_context_initial_image_check(ctx, initial_psp, entry_address, arg,
			initial_r9, initial_return_address);
}

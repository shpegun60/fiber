/* ARM_CM3_MPU safe-default context construction and SVC-frame validation. */

#include "fiber_port_private.h"
#include "../../fiber_panic.h"

#define FIBER_CM3_MPU_PRIVILEGED \
	FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY \
	fiber_portPRIVILEGED_FUNCTION

static FIBER_CM3_MPU_PRIVILEGED
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

static FIBER_CM3_MPU_PRIVILEGED
int fiber_port_range_contains(uintptr_t outer_start,
		uintptr_t outer_end,
		uintptr_t inner_start,
		uintptr_t inner_end)
{
	return (outer_end > outer_start) &&
			(inner_end > inner_start) &&
			(inner_start >= outer_start) &&
			(inner_end <= outer_end);
}

static FIBER_CM3_MPU_PRIVILEGED
int fiber_port_ranges_overlap(uintptr_t first_start,
		uintptr_t first_end,
		uintptr_t second_start,
		uintptr_t second_end)
{
	return (first_start < second_end) && (second_start < first_end);
}

static FIBER_CM3_MPU_PRIVILEGED
int fiber_port_code_address_is_in_range(uintptr_t range_start,
		uintptr_t range_end,
		uintptr_t address)
{
	return (address <= UINTPTR_MAX - 2u) &&
			fiber_port_range_contains(range_start, range_end,
					address, address + 2u);
}

static FIBER_CM3_MPU_PRIVILEGED
uintptr_t fiber_port_function_address(uintptr_t address)
{
	return address & ~(uintptr_t)1u;
}

static FIBER_CM3_MPU_PRIVILEGED
int fiber_port_mpu_access_encoding_is_valid(uint32_t attributes)
{
	const uint32_t access = attributes & fiber_portMPU_REGION_ACCESS_MASK;
	return (access == fiber_portMPU_REGION_READ_WRITE) ||
			(access == fiber_portMPU_REGION_PRIVILEGED_READ_ONLY) ||
			(access == fiber_portMPU_REGION_READ_ONLY) ||
			(access == fiber_portMPU_REGION_PRIVILEGED_READ_WRITE) ||
			(access ==
				fiber_portMPU_REGION_PRIVILEGED_READ_WRITE_UNPRIV_READ_ONLY);
}

FIBER_CM3_MPU_PRIVILEGED
int fiber_port_mpu_try_encode_exact_region(uintptr_t start,
		uintptr_t end,
		uint32_t region_number,
		uint32_t attributes,
		FiberPortMpuRegionRegisters *encoded)
{
	const uint32_t allowed_attributes =
			fiber_portMPU_REGION_EXECUTE_NEVER |
			fiber_portMPU_REGION_MEMORY_MASK |
			fiber_portMPU_REGION_ACCESS_MASK;

	if ((encoded == NULL) || (end <= start) ||
			(region_number > fiber_portMPU_PRIVILEGED_DATA_REGION) ||
			((attributes & ~allowed_attributes) != 0u) ||
			(fiber_port_mpu_access_encoding_is_valid(attributes) == 0)) {
		return 0;
	}

	const uintptr_t extent = end - start;
	if ((extent < (uintptr_t)fiber_portMPU_MIN_REGION_SIZE) ||
			(extent > (uintptr_t)fiber_portMPU_MAX_REGION_SIZE) ||
			((extent & (extent - 1u)) != 0u) ||
			((start & (extent - 1u)) != 0u) ||
			((start & ~(uintptr_t)UINT32_MAX) != 0u)) {
		return 0;
	}

	const uint32_t size = (uint32_t)extent;
	const uint32_t log2_size = 31u - (uint32_t)__builtin_clz(size);
	const uint32_t size_field = (log2_size - 1u) << 1u;
	if ((size_field & ~fiber_portMPU_REGION_SIZE_MASK) != 0u) {
		return 0;
	}

	encoded->rbar = ((uint32_t)start & fiber_portMPU_REGION_ADDRESS_MASK) |
			fiber_portMPU_REGION_VALID | region_number;
	encoded->rasr = attributes | size_field | fiber_portMPU_REGION_ENABLE;
	return 1;
}

static FIBER_CM3_MPU_PRIVILEGED
void fiber_port_mpu_encode_exact_region(uintptr_t start,
		uintptr_t end,
		uint32_t region_number,
		uint32_t attributes,
		FiberPortMpuRegionRegisters *encoded)
{
	FIBER_REQUIRE(fiber_port_mpu_try_encode_exact_region(start, end,
			region_number, attributes, encoded) != 0, 'M');
}

static FIBER_CM3_MPU_PRIVILEGED
void fiber_port_mpu_disable_region(uint32_t region_number,
		FiberPortMpuRegionRegisters *encoded)
{
	FIBER_REQUIRE(encoded != NULL, 'M');
	FIBER_REQUIRE(region_number <= fiber_portMPU_PRIVILEGED_DATA_REGION, 'M');
	encoded->rbar = fiber_portMPU_REGION_VALID | region_number;
	encoded->rasr = 0u;
}

FIBER_CM3_MPU_PRIVILEGED
void fiber_port_mpu_load_linker_layout(FiberPortMpuMemoryLayout *layout)
{
	FIBER_REQUIRE(layout != NULL, 'L');
	layout->unprivileged_code_start =
			(uintptr_t)__fiber_mpu_unprivileged_code_start__;
	layout->unprivileged_code_end =
			(uintptr_t)__fiber_mpu_unprivileged_code_end__;
	layout->privileged_code_start =
			(uintptr_t)__fiber_mpu_privileged_code_start__;
	layout->privileged_code_end =
			(uintptr_t)__fiber_mpu_privileged_code_end__;
	layout->privileged_data_start =
			(uintptr_t)__fiber_mpu_privileged_data_start__;
	layout->privileged_data_end =
			(uintptr_t)__fiber_mpu_privileged_data_end__;
	layout->current_context_slot_start =
			(uintptr_t)__fiber_mpu_current_context_slot_start__;
	layout->current_context_slot_end =
			(uintptr_t)__fiber_mpu_current_context_slot_end__;
	layout->unprivileged_ram_start =
			(uintptr_t)__fiber_mpu_unprivileged_ram_start__;
	layout->unprivileged_ram_end =
			(uintptr_t)__fiber_mpu_unprivileged_ram_end__;
}

FIBER_CM3_MPU_PRIVILEGED
void fiber_port_mpu_linker_layout_check(
		const FiberPortMpuMemoryLayout *layout)
{
	FiberPortMpuRegionRegisters encoded;
	FIBER_REQUIRE(layout != NULL, 'L');

	fiber_port_mpu_encode_exact_region(layout->unprivileged_code_start,
			layout->unprivileged_code_end,
			fiber_portMPU_UNPRIVILEGED_CODE_REGION,
			fiber_portMPU_REGION_READ_ONLY |
			fiber_portMPU_REGION_CACHEABLE_BUFFERABLE,
			&encoded);
	fiber_port_mpu_encode_exact_region(layout->privileged_code_start,
			layout->privileged_code_end,
			fiber_portMPU_PRIVILEGED_CODE_REGION,
			fiber_portMPU_REGION_PRIVILEGED_READ_ONLY |
			fiber_portMPU_REGION_CACHEABLE_BUFFERABLE,
			&encoded);
	fiber_port_mpu_encode_exact_region(layout->privileged_data_start,
			layout->privileged_data_end,
			fiber_portMPU_PRIVILEGED_DATA_REGION,
			fiber_portMPU_REGION_PRIVILEGED_READ_WRITE |
			fiber_portMPU_REGION_CACHEABLE_BUFFERABLE |
			fiber_portMPU_REGION_EXECUTE_NEVER,
			&encoded);
	fiber_port_mpu_encode_exact_region(layout->current_context_slot_start,
			layout->current_context_slot_end,
			fiber_portMPU_CURRENT_CONTEXT_REGION,
			fiber_portMPU_REGION_PRIVILEGED_READ_WRITE_UNPRIV_READ_ONLY |
			fiber_portMPU_REGION_CACHEABLE_BUFFERABLE |
			fiber_portMPU_REGION_EXECUTE_NEVER,
			&encoded);
	FIBER_REQUIRE((layout->current_context_slot_end -
			layout->current_context_slot_start) ==
			fiber_portMPU_MIN_REGION_SIZE, 'L');

	FIBER_REQUIRE(layout->unprivileged_ram_end >
			layout->unprivileged_ram_start, 'L');
	FIBER_REQUIRE((layout->unprivileged_ram_start &
			(fiber_portMPU_MIN_REGION_SIZE - 1u)) == 0u, 'L');
	FIBER_REQUIRE((layout->unprivileged_ram_end &
			(fiber_portMPU_MIN_REGION_SIZE - 1u)) == 0u, 'L');
	FIBER_REQUIRE(!fiber_port_ranges_overlap(layout->privileged_data_start,
			layout->privileged_data_end,
			layout->current_context_slot_start,
			layout->current_context_slot_end), 'L');
	FIBER_REQUIRE(!fiber_port_ranges_overlap(layout->privileged_data_start,
			layout->privileged_data_end,
			layout->unprivileged_ram_start,
			layout->unprivileged_ram_end), 'L');
	FIBER_REQUIRE(!fiber_port_ranges_overlap(
			layout->current_context_slot_start,
			layout->current_context_slot_end,
			layout->unprivileged_ram_start,
			layout->unprivileged_ram_end), 'L');
	FIBER_REQUIRE(!fiber_port_ranges_overlap(
			layout->current_context_slot_start,
			layout->current_context_slot_end,
			layout->unprivileged_code_start,
			layout->unprivileged_code_end), 'L');
	FIBER_REQUIRE(!fiber_port_ranges_overlap(
			layout->current_context_slot_start,
			layout->current_context_slot_end,
			layout->privileged_code_start,
			layout->privileged_code_end), 'L');
	FIBER_REQUIRE(!fiber_port_ranges_overlap(layout->unprivileged_code_start,
			layout->unprivileged_code_end,
			layout->privileged_data_start,
			layout->privileged_data_end), 'L');
	FIBER_REQUIRE(!fiber_port_ranges_overlap(layout->privileged_code_start,
			layout->privileged_code_end,
			layout->privileged_data_start,
			layout->privileged_data_end), 'L');
	FIBER_REQUIRE(!fiber_port_ranges_overlap(layout->unprivileged_code_start,
			layout->unprivileged_code_end,
			layout->unprivileged_ram_start,
			layout->unprivileged_ram_end), 'L');
	FIBER_REQUIRE(!fiber_port_ranges_overlap(layout->privileged_code_start,
			layout->privileged_code_end,
			layout->unprivileged_ram_start,
			layout->unprivileged_ram_end), 'L');

	if (fiber_port_ranges_overlap(layout->unprivileged_code_start,
			layout->unprivileged_code_end,
			layout->privileged_code_start,
			layout->privileged_code_end)) {
		FIBER_REQUIRE(fiber_port_range_contains(
				layout->unprivileged_code_start,
				layout->unprivileged_code_end,
				layout->privileged_code_start,
				layout->privileged_code_end), 'L');
	}

	const uintptr_t context_init = fiber_port_function_address(
			(uintptr_t)&fiber_port_context_init);
	const uintptr_t layout_check = fiber_port_function_address(
			(uintptr_t)&fiber_port_mpu_linker_layout_check);
	const uintptr_t global_builder = fiber_port_function_address(
			(uintptr_t)&fiber_port_mpu_build_global_regions);
	const uintptr_t panic_target = fiber_port_function_address(
			(uintptr_t)&fiber_panic);
	const uintptr_t task_return_target = fiber_port_function_address(
			(uintptr_t)&fiber_internal_task_return);
	const uintptr_t svc_handler = fiber_port_function_address(
			(uintptr_t)&SVC_Handler);
	const uintptr_t pendsv_handler = fiber_port_function_address(
			(uintptr_t)&PendSV_Handler);
	const uintptr_t svc_dispatch = fiber_port_function_address(
			(uintptr_t)&fiber_port_svc_dispatch);
	const uintptr_t first_restore = fiber_port_function_address(
			(uintptr_t)&fiber_port_restore_first_context_from_svc);
	const uintptr_t first_start = fiber_port_function_address(
			(uintptr_t)&fiber_port_start_first_context);
	const uintptr_t schedule_veneer = fiber_port_function_address(
			(uintptr_t)&fiber_port_runtime_schedule);
	const uintptr_t return_target = fiber_port_function_address(
			(uintptr_t)&fiber_port_unprivileged_task_return);

	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->privileged_code_start, layout->privileged_code_end,
			context_init), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->privileged_code_start, layout->privileged_code_end,
			layout_check), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->privileged_code_start, layout->privileged_code_end,
			global_builder), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->privileged_code_start, layout->privileged_code_end,
			panic_target), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->privileged_code_start, layout->privileged_code_end,
			task_return_target), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->privileged_code_start, layout->privileged_code_end,
			svc_handler), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->privileged_code_start, layout->privileged_code_end,
			pendsv_handler), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->privileged_code_start, layout->privileged_code_end,
			svc_dispatch), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->privileged_code_start, layout->privileged_code_end,
			first_restore), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->privileged_code_start, layout->privileged_code_end,
			first_start), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->unprivileged_code_start, layout->unprivileged_code_end,
			schedule_veneer), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->unprivileged_code_start, layout->unprivileged_code_end,
			return_target), 'L');
	FIBER_REQUIRE(!fiber_port_code_address_is_in_range(
			layout->privileged_code_start, layout->privileged_code_end,
			schedule_veneer), 'L');
	FIBER_REQUIRE(!fiber_port_code_address_is_in_range(
			layout->privileged_code_start, layout->privileged_code_end,
			return_target), 'L');
}

FIBER_CM3_MPU_PRIVILEGED
void fiber_port_mpu_build_global_regions(
		FiberPortMpuGlobalRegionImage *image)
{
	FiberPortMpuMemoryLayout layout;
	FIBER_REQUIRE(image != NULL, 'M');
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);

	/* Region 4 is a 32-byte read-only aperture for portable fiber_current().
	 * It replaces the FreeRTOS blanket peripheral mapping. */
	fiber_port_mpu_encode_exact_region(layout.current_context_slot_start,
			layout.current_context_slot_end,
			fiber_portMPU_CURRENT_CONTEXT_REGION,
			fiber_portMPU_REGION_PRIVILEGED_READ_WRITE_UNPRIV_READ_ONLY |
			fiber_portMPU_REGION_CACHEABLE_BUFFERABLE |
			fiber_portMPU_REGION_EXECUTE_NEVER,
			&image->regions[0]);
	fiber_port_mpu_encode_exact_region(layout.unprivileged_code_start,
			layout.unprivileged_code_end,
			fiber_portMPU_UNPRIVILEGED_CODE_REGION,
			fiber_portMPU_REGION_READ_ONLY |
			fiber_portMPU_REGION_CACHEABLE_BUFFERABLE,
			&image->regions[1]);
	fiber_port_mpu_encode_exact_region(layout.privileged_code_start,
			layout.privileged_code_end,
			fiber_portMPU_PRIVILEGED_CODE_REGION,
			fiber_portMPU_REGION_PRIVILEGED_READ_ONLY |
			fiber_portMPU_REGION_CACHEABLE_BUFFERABLE,
			&image->regions[2]);
	fiber_port_mpu_encode_exact_region(layout.privileged_data_start,
			layout.privileged_data_end,
			fiber_portMPU_PRIVILEGED_DATA_REGION,
			fiber_portMPU_REGION_PRIVILEGED_READ_WRITE |
			fiber_portMPU_REGION_CACHEABLE_BUFFERABLE |
			fiber_portMPU_REGION_EXECUTE_NEVER,
			&image->regions[3]);
}

FIBER_CM3_MPU_PRIVILEGED
uint32_t fiber_port_context_compute_seal(const FiberContext *ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'n');
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
	hash = fiber_port_hash32_accum(hash, boot->abi_mpu_region_count);
	hash = fiber_port_hash32_accum(hash, boot->magic);
	hash = fiber_port_hash32_accum(hash, (uint32_t)boot->version);
	hash = fiber_port_hash32_accum(hash, boot->guard_lo);
	hash = fiber_port_hash32_accum(hash, boot->guard_hi);

	for (uint32_t index = 0u; index < fiber_portMPU_REGION_COUNT; ++index) {
		hash = fiber_port_hash32_accum(hash, ctx->mpu_regions[index].rbar);
		hash = fiber_port_hash32_accum(hash, ctx->mpu_regions[index].rasr);
	}
	return hash;
}

static FIBER_CM3_MPU_PRIVILEGED
void fiber_port_context_fast_check(const FiberContext *ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'N');
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
	FIBER_REQUIRE(boot->abi_mpu_region_count == fiber_portMPU_REGION_COUNT, 'q');
	FIBER_REQUIRE(boot->begin != NULL, 'B');
	FIBER_REQUIRE(boot->end != NULL, 'T');
	FIBER_REQUIRE((uintptr_t)boot->end > (uintptr_t)boot->begin, 'N');
	FIBER_REQUIRE(boot->stack_top > boot->stack_base, 'S');
	FIBER_REQUIRE(boot->avail ==
			(size_t)(boot->stack_top - boot->stack_base), 'a');
	FIBER_REQUIRE(boot->entry != NULL, 'E');
	FIBER_REQUIRE((((uintptr_t)boot->entry) & 1u) != 0u, 'e');
	FIBER_REQUIRE(boot->hash == fiber_port_context_compute_seal(ctx), 'h');
}

FIBER_CM3_MPU_PRIVILEGED
void fiber_port_context_seal_check(const FiberContext *ctx)
{
	FiberPortMpuMemoryLayout layout;
	FiberPortMpuRegionRegisters expected_stack;
	FIBER_REQUIRE(ctx != NULL, 'N');
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);

	const uintptr_t context_start = (uintptr_t)ctx;
	FIBER_REQUIRE(context_start <= UINTPTR_MAX - sizeof(*ctx), 'O');
	const uintptr_t context_end = context_start + sizeof(*ctx);
	FIBER_REQUIRE((context_start & (_Alignof(FiberContext) - 1u)) == 0u, 'A');
	FIBER_REQUIRE(fiber_port_range_contains(layout.privileged_data_start,
			layout.privileged_data_end, context_start, context_end), 'C');

	/* No context field is read before the selected privileged range proves the
	 * complete object extent. */
	fiber_port_context_fast_check(ctx);

	const uintptr_t stack_start = (uintptr_t)ctx->boot.begin;
	const uintptr_t stack_end = (uintptr_t)ctx->boot.end;
	const uintptr_t entry = fiber_port_function_address(
			(uintptr_t)ctx->boot.entry);

	FIBER_REQUIRE(fiber_port_range_contains(layout.unprivileged_ram_start,
			layout.unprivileged_ram_end, stack_start, stack_end), 'P');
	FIBER_REQUIRE(!fiber_port_ranges_overlap(context_start, context_end,
			stack_start, stack_end), 'O');
	FIBER_REQUIRE(!fiber_port_ranges_overlap(layout.privileged_data_start,
			layout.privileged_data_end, stack_start, stack_end), 'O');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout.unprivileged_code_start, layout.unprivileged_code_end,
			entry), 'c');
	FIBER_REQUIRE(!fiber_port_code_address_is_in_range(
			layout.privileged_code_start, layout.privileged_code_end,
			entry), 'c');

	FIBER_REQUIRE(stack_start <= UINTPTR_MAX -
			(uintptr_t)FIBER_STACK_REDZONE_BYTES, 'O');
	const uintptr_t expected_stack_base = fiber_stack_align_up(stack_start +
			(uintptr_t)FIBER_STACK_REDZONE_BYTES);
	const uintptr_t expected_stack_top = fiber_stack_align_down(stack_end);
	FIBER_REQUIRE(ctx->boot.stack_base == expected_stack_base, 'S');
	FIBER_REQUIRE(ctx->boot.stack_top == expected_stack_top, 'S');
	FIBER_REQUIRE(ctx->boot.avail >=
			(size_t)FIBER_STACK_WITHOUT_REDZONE, 'H');

#if FIBER_STACK_CANARY
	FIBER_REQUIRE(stack_start <= UINTPTR_MAX - sizeof(uint32_t), 'c');
	FIBER_REQUIRE((stack_start + sizeof(uint32_t)) <=
			ctx->boot.stack_base, 'c');
	FIBER_REQUIRE(*(const volatile uint32_t *)stack_start ==
			FIBER_INTERNAL_STACK_CANARY_VALUE, 'c');
#endif

	fiber_port_mpu_encode_exact_region(stack_start, stack_end,
			fiber_portMPU_STACK_REGION,
			fiber_portMPU_REGION_READ_WRITE |
			fiber_portMPU_REGION_CACHEABLE_BUFFERABLE |
			fiber_portMPU_REGION_EXECUTE_NEVER,
			&expected_stack);
	for (uint32_t index = fiber_portMPU_FIRST_CONFIGURABLE_REGION;
			index <= fiber_portMPU_LAST_CONFIGURABLE_REGION; ++index) {
		FIBER_REQUIRE(ctx->mpu_regions[index].rbar ==
				(fiber_portMPU_REGION_VALID | index), 'M');
		FIBER_REQUIRE(ctx->mpu_regions[index].rasr == 0u, 'M');
	}
	FIBER_REQUIRE(ctx->mpu_regions[fiber_portMPU_STACK_REGION].rbar ==
			expected_stack.rbar, 'M');
	FIBER_REQUIRE(ctx->mpu_regions[fiber_portMPU_STACK_REGION].rasr ==
			expected_stack.rasr, 'M');
}

static FIBER_CM3_MPU_PRIVILEGED
void fiber_port_validate_hardware_frame(const FiberContext *ctx,
		const uint32_t *hardware_frame,
		const FiberPortMpuMemoryLayout *layout)
{
	FIBER_REQUIRE(ctx != NULL, 'N');
	FIBER_REQUIRE(hardware_frame != NULL, 'P');
	FIBER_REQUIRE(layout != NULL, 'L');

	const uint32_t stacked_pc = hardware_frame[6];
	const uint32_t stacked_xpsr = hardware_frame[7];
	FIBER_REQUIRE((stacked_xpsr & fiber_portXPSR_THUMB_BIT) != 0u, 'x');
	FIBER_REQUIRE((stacked_xpsr & fiber_portXPSR_IPSR_MASK) == 0u, 'x');
	FIBER_REQUIRE((stacked_xpsr & fiber_portXPSR_STACK_ALIGN_BIT) == 0u, 'a');
	FIBER_REQUIRE((stacked_pc & 1u) == 0u, 'x');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->unprivileged_code_start,
			layout->unprivileged_code_end,
			(uintptr_t)stacked_pc), 'c');
	FIBER_REQUIRE(!fiber_port_code_address_is_in_range(
			layout->privileged_code_start,
			layout->privileged_code_end,
			(uintptr_t)stacked_pc), 'c');
}

FIBER_CM3_MPU_PRIVILEGED
void fiber_port_context_validate_restore(FiberContext *ctx)
{
	FiberPortMpuMemoryLayout layout;
	fiber_port_context_seal_check(ctx);
	fiber_port_mpu_load_linker_layout(&layout);

	FIBER_REQUIRE(ctx->protected_context_cursor ==
			&ctx->protected_context.cursor_limit, 'P');
	FIBER_REQUIRE(ctx->protected_context.control ==
			ctx->boot.abi_initial_control, 'q');
	FIBER_REQUIRE(ctx->protected_context.exc_return ==
			ctx->boot.abi_initial_exc_return, 'x');

	const uintptr_t psp = (uintptr_t)ctx->protected_context.psp;
	FIBER_REQUIRE((psp & 7u) == 0u, 'A');
	FIBER_REQUIRE(psp <= UINTPTR_MAX - FIBER_PORT_EXC_BASE_BYTES, 'O');
	FIBER_REQUIRE(psp >= ctx->boot.stack_base, 'P');
	FIBER_REQUIRE((psp + FIBER_PORT_EXC_BASE_BYTES) <=
			ctx->boot.stack_top, 'P');

	fiber_port_validate_hardware_frame(ctx,
			&ctx->protected_context.r0, &layout);
}

static FIBER_CM3_MPU_PRIVILEGED
void fiber_port_context_validate_running_frame(const FiberContext *ctx,
		const uint32_t *hardware_frame)
{
	FiberPortMpuMemoryLayout layout;
	fiber_port_context_seal_check(ctx);
	fiber_port_mpu_load_linker_layout(&layout);

	FIBER_REQUIRE(ctx->protected_context_cursor ==
			&ctx->protected_context.control, 'P');
	FIBER_REQUIRE(ctx->protected_context.control ==
			ctx->boot.abi_initial_control, 'q');
	FIBER_REQUIRE(ctx->protected_context.exc_return ==
			ctx->boot.abi_initial_exc_return, 'x');
	FIBER_REQUIRE((uintptr_t)hardware_frame == (uintptr_t)__get_PSP(), 'P');
	const uintptr_t frame_start = (uintptr_t)hardware_frame;
	FIBER_REQUIRE((frame_start & 7u) == 0u, 'A');
	FIBER_REQUIRE(frame_start <= UINTPTR_MAX - FIBER_PORT_EXC_BASE_BYTES,
			'O');
	FIBER_REQUIRE(frame_start >= ctx->boot.stack_base, 'P');
	FIBER_REQUIRE((frame_start + FIBER_PORT_EXC_BASE_BYTES) <=
			ctx->boot.stack_top, 'P');
	fiber_port_validate_hardware_frame(ctx, hardware_frame, &layout);
}

FIBER_CM3_MPU_PRIVILEGED
void fiber_port_context_validate_running_svc(const FiberContext *ctx,
		const uint32_t *hardware_frame)
{
	fiber_port_context_validate_running_frame(ctx, hardware_frame);
}

FIBER_CM3_MPU_PRIVILEGED
void fiber_port_context_validate_save_current(const FiberContext *ctx,
		const uint32_t *hardware_frame)
{
	fiber_port_context_validate_running_frame(ctx, hardware_frame);
}

FIBER_CM3_MPU_PRIVILEGED
void fiber_port_context_init(FiberContext *ctx,
		void *stack_begin,
		void *stack_end,
		entry_t entry,
		void *arg)
{
	FiberPortMpuMemoryLayout layout;
	FiberPortMpuRegionRegisters stack_region;
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
	FIBER_REQUIRE(ctx != NULL, 'C');
	FIBER_REQUIRE(stack_begin != NULL, 'B');
	FIBER_REQUIRE(stack_end != NULL, 'T');
	FIBER_REQUIRE(entry != NULL, 'E');

	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);

	const uintptr_t context_start = (uintptr_t)ctx;
	FIBER_REQUIRE(context_start <= UINTPTR_MAX - sizeof(*ctx), 'O');
	const uintptr_t context_end = context_start + sizeof(*ctx);
	const uintptr_t raw_stack_start = (uintptr_t)stack_begin;
	const uintptr_t raw_stack_end = (uintptr_t)stack_end;
	const uintptr_t entry_address = fiber_port_function_address((uintptr_t)entry);

	FIBER_REQUIRE((context_start & (_Alignof(FiberContext) - 1u)) == 0u, 'A');
	FIBER_REQUIRE(fiber_port_range_contains(layout.privileged_data_start,
			layout.privileged_data_end, context_start, context_end), 'C');
	FIBER_REQUIRE(fiber_port_range_contains(layout.unprivileged_ram_start,
			layout.unprivileged_ram_end, raw_stack_start, raw_stack_end), 'P');
	FIBER_REQUIRE(!fiber_port_ranges_overlap(context_start, context_end,
			raw_stack_start, raw_stack_end), 'O');
	FIBER_REQUIRE(!fiber_port_ranges_overlap(layout.privileged_data_start,
			layout.privileged_data_end, raw_stack_start, raw_stack_end), 'O');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout.unprivileged_code_start, layout.unprivileged_code_end,
			entry_address), 'c');
	FIBER_REQUIRE(!fiber_port_code_address_is_in_range(
			layout.privileged_code_start, layout.privileged_code_end,
			entry_address), 'c');

	fiber_port_mpu_encode_exact_region(raw_stack_start, raw_stack_end,
			fiber_portMPU_STACK_REGION,
			fiber_portMPU_REGION_READ_WRITE |
			fiber_portMPU_REGION_CACHEABLE_BUFFERABLE |
			fiber_portMPU_REGION_EXECUTE_NEVER,
			&stack_region);

	FIBER_REQUIRE(raw_stack_start <= UINTPTR_MAX -
			(uintptr_t)FIBER_STACK_REDZONE_BYTES, 'O');
	const uintptr_t stack_base = fiber_stack_align_up(raw_stack_start +
			(uintptr_t)FIBER_STACK_REDZONE_BYTES);
	const uintptr_t stack_top = fiber_stack_align_down(raw_stack_end);
	FIBER_REQUIRE(stack_top > stack_base, 'H');
	FIBER_REQUIRE((stack_top - stack_base) >=
			(uintptr_t)FIBER_STACK_WITHOUT_REDZONE, 'H');
	FIBER_REQUIRE(stack_top >= (uintptr_t)FIBER_EXC_BASE_BYTES, 'H');
	const uintptr_t initial_psp = stack_top - (uintptr_t)FIBER_EXC_BASE_BYTES;
	FIBER_REQUIRE(initial_psp >= stack_base, 'H');
	FIBER_REQUIRE((initial_psp & 7u) == 0u, 'A');

	for (uint32_t index = fiber_portMPU_FIRST_CONFIGURABLE_REGION;
			index <= fiber_portMPU_LAST_CONFIGURABLE_REGION; ++index) {
		fiber_port_mpu_disable_region(index, &ctx->mpu_regions[index]);
	}
	ctx->mpu_regions[fiber_portMPU_STACK_REGION] = stack_region;

	ctx->protected_context.control = fiber_portINITIAL_CONTROL_UNPRIVILEGED;
	ctx->protected_context.r4 = 0u;
	ctx->protected_context.r5 = 0u;
	ctx->protected_context.r6 = 0u;
	ctx->protected_context.r7 = 0u;
	ctx->protected_context.r8 = 0u;
	ctx->protected_context.r9 = 0u;
	ctx->protected_context.r10 = 0u;
	ctx->protected_context.r11 = 0u;
	ctx->protected_context.exc_return = fiber_portINITIAL_EXC_RETURN;
	ctx->protected_context.psp = (uint32_t)initial_psp;
	ctx->protected_context.r0 = (uint32_t)(uintptr_t)arg;
	ctx->protected_context.r1 = 0u;
	ctx->protected_context.r2 = 0u;
	ctx->protected_context.r3 = 0u;
	ctx->protected_context.r12 = 0u;
	ctx->protected_context.lr =
			(uint32_t)(uintptr_t)&fiber_port_unprivileged_task_return;
	ctx->protected_context.pc = (uint32_t)entry_address;
	ctx->protected_context.xpsr = fiber_portINITIAL_XPSR;
	ctx->protected_context.cursor_limit = 0u;
	ctx->protected_context_cursor = &ctx->protected_context.cursor_limit;

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
	ctx->boot.abi_mpu_region_count = fiber_portMPU_REGION_COUNT;
	ctx->boot.magic = FIBER_PORT_BOOT_RECORD_MAGIC;
	ctx->boot.version = FIBER_PORT_BOOT_RECORD_VERSION;
	ctx->boot.sealed = 0u;
	ctx->boot.guard_lo = FIBER_PORT_BOOT_RECORD_GUARD_LO;
	ctx->boot.guard_hi = FIBER_PORT_BOOT_RECORD_GUARD_HI;
	ctx->boot.hash = 0u;

#if FIBER_STACK_CANARY
	*(volatile uint32_t *)raw_stack_start = FIBER_INTERNAL_STACK_CANARY_VALUE;
#endif

	ctx->boot.hash = fiber_port_context_compute_seal(ctx);
	ctx->boot.sealed = 1u;
	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
	fiber_port_context_seal_check(ctx);

	FIBER_REQUIRE(ctx->protected_context_cursor ==
			&ctx->protected_context.cursor_limit, 'P');
	FIBER_REQUIRE(ctx->protected_context.control ==
			fiber_portINITIAL_CONTROL_UNPRIVILEGED, 'q');
	FIBER_REQUIRE(ctx->protected_context.exc_return ==
			fiber_portINITIAL_EXC_RETURN, 'x');
	FIBER_REQUIRE(ctx->protected_context.psp == (uint32_t)initial_psp, 'P');
	FIBER_REQUIRE(ctx->protected_context.pc == (uint32_t)entry_address, 'x');
	FIBER_REQUIRE((ctx->protected_context.lr & 1u) != 0u, 'x');
	FIBER_REQUIRE((ctx->protected_context.pc & 1u) == 0u, 'x');
	FIBER_REQUIRE((ctx->protected_context.xpsr & (1u << 24u)) != 0u, 'x');
}

#undef FIBER_CM3_MPU_PRIVILEGED

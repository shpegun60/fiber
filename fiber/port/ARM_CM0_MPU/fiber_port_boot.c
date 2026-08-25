/* ARM_CM0_MPU linker isolation, exact MPU image, and first-start mechanics.
 *
 * This source does not enter the forward runtime ABI. It validates linker-owned
 * placement, builds and seals the exact privileged image, and supplies the
 * first-image validation consumed by slice-4 SVC/MPU activation. A later
 * protected PendSV slice will own ordinary MPU replacement and switching.
 */

#include "fiber_port_private.h"

#include "../../fiber_panic.h"

#define FIBER_CM0_MPU_BOOT \
	FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY \
	fiber_portPRIVILEGED_FUNCTION

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
int fiber_port_range_contains(uintptr_t outer_start,
		uintptr_t outer_end,
		uintptr_t inner_start,
		uintptr_t inner_end)
{
	return (outer_end > outer_start) && (inner_end > inner_start) &&
			(inner_start >= outer_start) && (inner_end <= outer_end);
}

static FIBER_CM0_MPU_BOOT
uintptr_t fiber_port_function_address(uintptr_t address)
{
	return address & ~(uintptr_t)1u;
}

static FIBER_CM0_MPU_BOOT
int fiber_port_code_address_is_in_range(uintptr_t range_start,
		uintptr_t range_end,
		uintptr_t address)
{
	return (address <= UINTPTR_MAX - 2u) &&
			fiber_port_range_contains(range_start, range_end, address,
					address + 2u);
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

FIBER_CM0_MPU_BOOT
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

FIBER_CM0_MPU_BOOT
void fiber_port_mpu_linker_layout_check(
		const FiberPortMpuMemoryLayout *layout)
{
	FiberPortMpuRegionRegisters encoded;
	FIBER_REQUIRE(layout != NULL, 'L');

	fiber_port_mpu_encode_exact_region(layout->unprivileged_code_start,
			layout->unprivileged_code_end,
			fiber_portMPU_UNPRIVILEGED_CODE_REGION,
			fiber_portMPU_REGION_PRIV_RO_UNPRIV_RO |
			fiber_portMPU_DEFAULT_FLASH_MEMORY, &encoded);
	fiber_port_mpu_encode_exact_region(layout->privileged_code_start,
			layout->privileged_code_end,
			fiber_portMPU_PRIVILEGED_CODE_REGION,
			fiber_portMPU_REGION_PRIV_RO_UNPRIV_NA |
			fiber_portMPU_DEFAULT_FLASH_MEMORY, &encoded);
	fiber_port_mpu_encode_exact_region(layout->privileged_data_start,
			layout->privileged_data_end,
			fiber_portMPU_PRIVILEGED_DATA_REGION,
			fiber_portMPU_REGION_PRIV_RW_UNPRIV_NA |
			fiber_portMPU_DEFAULT_SRAM_MEMORY |
			fiber_portMPU_REGION_EXECUTE_NEVER, &encoded);
	fiber_port_mpu_encode_exact_region(layout->current_context_slot_start,
			layout->current_context_slot_end,
			fiber_portMPU_CURRENT_CONTEXT_REGION,
			fiber_portMPU_REGION_PRIV_RW_UNPRIV_RO |
			fiber_portMPU_DEFAULT_SRAM_MEMORY |
			fiber_portMPU_REGION_EXECUTE_NEVER, &encoded);
	FIBER_REQUIRE((layout->current_context_slot_end -
			layout->current_context_slot_start) ==
			fiber_portMPU_CURRENT_CONTEXT_APERTURE_BYTES, 'L');

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
	const uintptr_t seal_compute = fiber_port_function_address(
			(uintptr_t)&fiber_port_context_compute_seal);
	const uintptr_t seal_check = fiber_port_function_address(
			(uintptr_t)&fiber_port_context_seal_check);
	const uintptr_t initial_restore_check = fiber_port_function_address(
			(uintptr_t)&fiber_port_context_validate_initial_restore);
	const uintptr_t encoder = fiber_port_function_address(
			(uintptr_t)&fiber_port_mpu_try_encode_exact_region);
	const uintptr_t layout_load = fiber_port_function_address(
			(uintptr_t)&fiber_port_mpu_load_linker_layout);
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
	const uintptr_t svc_dispatch = fiber_port_function_address(
			(uintptr_t)&fiber_port_svc_dispatch);
	const uintptr_t first_prepare = fiber_port_function_address(
			(uintptr_t)&fiber_port_prepare_first_start);
	const uintptr_t first_start = fiber_port_function_address(
			(uintptr_t)&fiber_port_start_first_context);
	const uintptr_t first_restore = fiber_port_function_address(
			(uintptr_t)&fiber_port_restore_first_context_from_svc);
	const uintptr_t return_target = fiber_port_function_address(
			(uintptr_t)&fiber_port_unprivileged_task_return);
	const uintptr_t privileged_targets[] = {
		context_init, seal_compute, seal_check, initial_restore_check, encoder, layout_load,
		layout_check, global_builder, panic_target, task_return_target,
		svc_handler, svc_dispatch, first_prepare, first_start, first_restore
	};

	for (uint32_t index = 0u;
			index < (sizeof(privileged_targets) / sizeof(privileged_targets[0]));
			++index) {
		FIBER_REQUIRE(fiber_port_code_address_is_in_range(
				layout->privileged_code_start,
				layout->privileged_code_end, privileged_targets[index]), 'L');
	}
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->unprivileged_code_start,
			layout->unprivileged_code_end, return_target), 'L');
	FIBER_REQUIRE(!fiber_port_code_address_is_in_range(
			layout->privileged_code_start,
			layout->privileged_code_end, return_target), 'L');
}

FIBER_CM0_MPU_BOOT
void fiber_port_mpu_build_global_regions(
		FiberPortMpuGlobalRegionImage *image)
{
	FiberPortMpuMemoryLayout layout;
	FIBER_REQUIRE(image != NULL, 'M');
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);

	/* Region 4 replaces the FreeRTOS broad peripheral mapping. ARMv6-M needs a
	 * full 256-byte aperture even though the common current slot itself is one
	 * word, so nothing else may share the linker output section. */
	fiber_port_mpu_encode_exact_region(layout.current_context_slot_start,
			layout.current_context_slot_end,
			fiber_portMPU_CURRENT_CONTEXT_REGION,
			fiber_portMPU_REGION_PRIV_RW_UNPRIV_RO |
			fiber_portMPU_DEFAULT_SRAM_MEMORY |
			fiber_portMPU_REGION_EXECUTE_NEVER, &image->regions[0]);
	fiber_port_mpu_encode_exact_region(layout.unprivileged_code_start,
			layout.unprivileged_code_end,
			fiber_portMPU_UNPRIVILEGED_CODE_REGION,
			fiber_portMPU_REGION_PRIV_RO_UNPRIV_RO |
			fiber_portMPU_DEFAULT_FLASH_MEMORY, &image->regions[1]);
	fiber_port_mpu_encode_exact_region(layout.privileged_code_start,
			layout.privileged_code_end,
			fiber_portMPU_PRIVILEGED_CODE_REGION,
			fiber_portMPU_REGION_PRIV_RO_UNPRIV_NA |
			fiber_portMPU_DEFAULT_FLASH_MEMORY, &image->regions[2]);
	fiber_port_mpu_encode_exact_region(layout.privileged_data_start,
			layout.privileged_data_end,
			fiber_portMPU_PRIVILEGED_DATA_REGION,
			fiber_portMPU_REGION_PRIV_RW_UNPRIV_NA |
			fiber_portMPU_DEFAULT_SRAM_MEMORY |
			fiber_portMPU_REGION_EXECUTE_NEVER, &image->regions[3]);
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
	FiberPortMpuMemoryLayout layout;
	/* This helper is selected-port surface. Prove the complete privileged
	 * context extent before it reads immutable metadata, even when a future
	 * caller bypasses the full seal-check wrapper. */
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);
	fiber_port_context_pointer_check(ctx);
	const uintptr_t context_start = (uintptr_t)ctx;
	const uintptr_t context_end = context_start + sizeof(*ctx);
	FIBER_REQUIRE(fiber_port_range_contains(layout.privileged_data_start,
			layout.privileged_data_end, context_start, context_end), 'C');
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
	FiberPortMpuMemoryLayout layout;
	FiberPortMpuRegionRegisters expected_stack;
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);

	fiber_port_context_pointer_check(ctx);
	const uintptr_t context_start = (uintptr_t)ctx;
	const uintptr_t context_end = context_start + sizeof(*ctx);
	FIBER_REQUIRE(fiber_port_range_contains(layout.privileged_data_start,
			layout.privileged_data_end, context_start, context_end), 'C');
	/* Do not read metadata until the exact privileged-data range proves the
	 * complete context extent. */
	fiber_port_context_fast_check(ctx);
	FIBER_REQUIRE(ctx->boot.hash == fiber_port_context_compute_seal(ctx), 'h');
	const uintptr_t raw_stack_start = (uintptr_t)ctx->boot.begin;
	const uintptr_t raw_stack_end = (uintptr_t)ctx->boot.end;
	const uintptr_t entry_address = fiber_port_function_address(
			(uintptr_t)ctx->boot.entry);
	FIBER_REQUIRE(!fiber_port_ranges_overlap(context_start, context_end,
			raw_stack_start, raw_stack_end), 'O');
	FIBER_REQUIRE(fiber_port_range_contains(layout.unprivileged_ram_start,
			layout.unprivileged_ram_end, raw_stack_start, raw_stack_end), 'P');
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
void fiber_port_context_validate_initial_restore(const FiberContext *ctx)
{
	fiber_port_context_seal_check(ctx);
	const FiberPortProtectedContext *const image = &ctx->protected_context;
	const uintptr_t expected_psp = ctx->boot.stack_top -
			(uintptr_t)FIBER_PORT_EXC_BASE_BYTES;
	const uint32_t expected_return =
			((uint32_t)(uintptr_t)&fiber_port_unprivileged_task_return) | 1u;
	const uint32_t expected_pc = (uint32_t)((uintptr_t)ctx->boot.entry &
			(uintptr_t)fiber_portSTART_ADDRESS_MASK);

	FIBER_REQUIRE(ctx->boot.stack_top >= FIBER_PORT_EXC_BASE_BYTES, 'H');
	FIBER_REQUIRE((expected_psp & 7u) == 0u, 'A');
	FIBER_REQUIRE(expected_psp >= ctx->boot.stack_base, 'P');
	FIBER_REQUIRE((expected_psp + FIBER_PORT_EXC_BASE_BYTES) <=
			ctx->boot.stack_top, 'P');
	FIBER_REQUIRE(image->r4 == 0u && image->r5 == 0u &&
			image->r6 == 0u && image->r7 == 0u, 'x');
	FIBER_REQUIRE(image->r8 == 0u && image->r9 == fiber_port_read_r9() &&
			image->r10 == 0u &&
			image->r11 == 0u, 'x');
	FIBER_REQUIRE(image->r0 == (uint32_t)(uintptr_t)ctx->boot.arg, 'P');
	FIBER_REQUIRE(image->r1 == 0u && image->r2 == 0u &&
			image->r3 == 0u && image->r12 == 0u, 'x');
	FIBER_REQUIRE(image->lr == expected_return, 'x');
	FIBER_REQUIRE(image->pc == expected_pc, 'x');
	FIBER_REQUIRE(image->xpsr == fiber_portINITIAL_XPSR, 'x');
	FIBER_REQUIRE(image->psp == (uint32_t)expected_psp, 'P');
	FIBER_REQUIRE(image->control == fiber_portINITIAL_CONTROL_UNPRIVILEGED,
			'q');
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
	FiberPortMpuMemoryLayout layout;
	FiberPortMpuRegionRegisters stack_region;
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
	FIBER_REQUIRE(ctx != NULL, 'C');
	FIBER_REQUIRE(stack_begin != NULL, 'B');
	FIBER_REQUIRE(stack_end != NULL, 'T');
	FIBER_REQUIRE(entry != NULL, 'E');
	fiber_port_context_pointer_check(ctx);
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);

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
	FIBER_REQUIRE(fiber_port_range_contains(layout.privileged_data_start,
			layout.privileged_data_end, context_start, context_end), 'C');
	FIBER_REQUIRE(fiber_port_range_contains(layout.unprivileged_ram_start,
			layout.unprivileged_ram_end, raw_stack_start, raw_stack_end), 'P');
	FIBER_REQUIRE(!fiber_port_ranges_overlap(layout.privileged_data_start,
			layout.privileged_data_end, raw_stack_start, raw_stack_end), 'O');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout.unprivileged_code_start, layout.unprivileged_code_end,
			fiber_port_function_address(entry_address)), 'c');
	FIBER_REQUIRE(!fiber_port_code_address_is_in_range(
			layout.privileged_code_start, layout.privileged_code_end,
			fiber_port_function_address(entry_address)), 'c');

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

/* ARM_CM33_MPU/non_secure sealed construction and linker-owned MPU image. */

#include "fiber_port_boot.h"

#define FIBER_CM33_MPU_BOOT \
	FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY \
	fiber_portPRIVILEGED_FUNCTION

static FIBER_CM33_MPU_BOOT
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

static FIBER_CM33_MPU_BOOT
int fiber_port_range_contains(uintptr_t outer_start,
		uintptr_t outer_end,
		uintptr_t inner_start,
		uintptr_t inner_end)
{
	return (outer_end > outer_start) && (inner_end > inner_start) &&
			(inner_start >= outer_start) && (inner_end <= outer_end);
}

static FIBER_CM33_MPU_BOOT
int fiber_port_ranges_overlap(uintptr_t first_start,
		uintptr_t first_end,
		uintptr_t second_start,
		uintptr_t second_end)
{
	return (first_start < second_end) && (second_start < first_end);
}

static FIBER_CM33_MPU_BOOT
uintptr_t fiber_port_function_address(uintptr_t address)
{
	return address & ~(uintptr_t)1u;
}

static FIBER_CM33_MPU_BOOT
int fiber_port_code_address_is_in_range(uintptr_t range_start,
		uintptr_t range_end,
		uintptr_t address)
{
	return (address <= (UINTPTR_MAX - 2u)) &&
			fiber_port_range_contains(range_start, range_end,
					address, address + 2u);
}

static FIBER_CM33_MPU_BOOT
void fiber_port_require_32_byte_range(uintptr_t start,
		uintptr_t end,
		char code)
{
	FIBER_REQUIRE(end > start, code);
	FIBER_REQUIRE((start & ~(uintptr_t)fiber_portMPU_RBAR_ADDRESS_MASK) == 0u,
			code);
	FIBER_REQUIRE((end & ~(uintptr_t)fiber_portMPU_RLAR_ADDRESS_MASK) == 0u,
			code);
	FIBER_REQUIRE((end - start) >= 32u, code);
}

static FIBER_CM33_MPU_BOOT
int fiber_port_mpu_rbar_attributes_are_valid(uint32_t attributes)
{
	const uint32_t allowed = fiber_portMPU_RBAR_ACCESS_MASK |
			fiber_portMPU_RBAR_SHAREABILITY_MASK |
			fiber_portMPU_REGION_EXECUTE_NEVER;
	const uint32_t access = attributes & fiber_portMPU_RBAR_ACCESS_MASK;
	const uint32_t shareability =
			attributes & fiber_portMPU_RBAR_SHAREABILITY_MASK;

	if ((attributes & ~allowed) != 0u) {
		return 0;
	}
	if ((access != fiber_portMPU_REGION_PRIVILEGED_READ_WRITE) &&
			(access != fiber_portMPU_REGION_READ_WRITE) &&
			(access != fiber_portMPU_REGION_PRIVILEGED_READ_ONLY) &&
			(access != fiber_portMPU_REGION_READ_ONLY)) {
		return 0;
	}
	return (shareability == fiber_portMPU_REGION_NON_SHAREABLE) ||
			(shareability == fiber_portMPU_REGION_INNER_SHAREABLE) ||
			(shareability == fiber_portMPU_REGION_OUTER_SHAREABLE);
}

static FIBER_CM33_MPU_BOOT
int fiber_port_mpu_rlar_attributes_are_valid(uint32_t attributes)
{
	return ((attributes & ~fiber_portMPU_RLAR_ATTR_INDEX_MASK) == 0u) &&
			((attributes == fiber_portMPU_RLAR_ATTR_INDEX0) ||
			 (attributes == fiber_portMPU_RLAR_ATTR_INDEX1));
}

FIBER_CM33_MPU_BOOT
int fiber_port_mpu_try_encode_exact_region(uintptr_t start,
		uintptr_t end,
		uint32_t region_number,
		uint32_t rbar_attributes,
		uint32_t rlar_attributes,
		FiberPortMpuRegionRegisters *encoded)
{
	if ((encoded == NULL) || (end <= start) ||
			(region_number >= fiber_portMPU_TOTAL_REGIONS) ||
			((start & ~(uintptr_t)fiber_portMPU_RBAR_ADDRESS_MASK) != 0u) ||
			((end & ~(uintptr_t)fiber_portMPU_RLAR_ADDRESS_MASK) != 0u) ||
			((end - start) < 32u) ||
			(fiber_port_mpu_rbar_attributes_are_valid(rbar_attributes) == 0) ||
			(fiber_port_mpu_rlar_attributes_are_valid(rlar_attributes) == 0)) {
		return 0;
	}

	/* RLAR stores the final 32-byte block of the inclusive limit. The public
	 * contract is exclusive [start, end), so encode end - 1 after proving the
	 * exact 32-byte boundary above. */
	encoded->rbar = ((uint32_t)start & fiber_portMPU_RBAR_ADDRESS_MASK) |
			rbar_attributes;
	encoded->rlar = ((uint32_t)(end - 1u) &
			fiber_portMPU_RLAR_ADDRESS_MASK) |
			rlar_attributes | fiber_portMPU_RLAR_REGION_ENABLE;
	return 1;
}

static FIBER_CM33_MPU_BOOT
void fiber_port_mpu_encode_exact_region(uintptr_t start,
		uintptr_t end,
		uint32_t region_number,
		uint32_t rbar_attributes,
		uint32_t rlar_attributes,
		FiberPortMpuRegionRegisters *encoded)
{
	FIBER_REQUIRE(fiber_port_mpu_try_encode_exact_region(start, end,
				region_number, rbar_attributes, rlar_attributes, encoded) != 0,
			'M');
}

static FIBER_CM33_MPU_BOOT
void fiber_port_mpu_disable_context_region(FiberPortMpuRegionRegisters *encoded)
{
	FIBER_REQUIRE(encoded != NULL, 'M');
	encoded->rbar = 0u;
	encoded->rlar = 0u;
}

FIBER_CM33_MPU_BOOT
void fiber_port_mpu_load_linker_layout(FiberPortMpuMemoryLayout *layout)
{
	FIBER_REQUIRE(layout != NULL, 'L');
	layout->privileged_flash_start =
			(uintptr_t)__fiber_mpu_privileged_flash_start__;
	layout->privileged_flash_end =
			(uintptr_t)__fiber_mpu_privileged_flash_end__;
	layout->unprivileged_flash_start =
			(uintptr_t)__fiber_mpu_unprivileged_flash_start__;
	layout->unprivileged_flash_end =
			(uintptr_t)__fiber_mpu_unprivileged_flash_end__;
	layout->unprivileged_syscalls_start =
			(uintptr_t)__fiber_mpu_unprivileged_syscalls_start__;
	layout->unprivileged_syscalls_end =
			(uintptr_t)__fiber_mpu_unprivileged_syscalls_end__;
	layout->privileged_sram_start =
			(uintptr_t)__fiber_mpu_privileged_sram_start__;
	layout->privileged_sram_end =
			(uintptr_t)__fiber_mpu_privileged_sram_end__;
	layout->current_context_slot_start =
			(uintptr_t)__fiber_mpu_current_context_slot_start__;
	layout->current_context_slot_end =
			(uintptr_t)__fiber_mpu_current_context_slot_end__;
	layout->unprivileged_ram_start =
			(uintptr_t)__fiber_mpu_unprivileged_ram_start__;
	layout->unprivileged_ram_end =
			(uintptr_t)__fiber_mpu_unprivileged_ram_end__;
}

static FIBER_CM33_MPU_BOOT
void fiber_port_require_disjoint(uintptr_t first_start,
		uintptr_t first_end,
		uintptr_t second_start,
		uintptr_t second_end)
{
	FIBER_REQUIRE(!fiber_port_ranges_overlap(first_start, first_end,
				second_start, second_end), 'L');
}

FIBER_CM33_MPU_BOOT
void fiber_port_mpu_linker_layout_check(
		const FiberPortMpuMemoryLayout *layout)
{
	FiberPortMpuRegionRegisters encoded;
	FIBER_REQUIRE(layout != NULL, 'L');

	fiber_port_require_32_byte_range(layout->privileged_flash_start,
			layout->privileged_flash_end, 'L');
	fiber_port_require_32_byte_range(layout->unprivileged_flash_start,
			layout->unprivileged_flash_end, 'L');
	fiber_port_require_32_byte_range(layout->unprivileged_syscalls_start,
			layout->unprivileged_syscalls_end, 'L');
	fiber_port_require_32_byte_range(layout->privileged_sram_start,
			layout->privileged_sram_end, 'L');
	fiber_port_require_32_byte_range(layout->unprivileged_ram_start,
			layout->unprivileged_ram_end, 'L');

	fiber_port_mpu_encode_exact_region(layout->privileged_flash_start,
			layout->privileged_flash_end,
			fiber_portMPU_PRIVILEGED_FLASH_REGION_NUMBER,
			fiber_portMPU_REGION_NON_SHAREABLE |
			fiber_portMPU_REGION_PRIVILEGED_READ_ONLY,
			fiber_portMPU_RLAR_ATTR_INDEX0, &encoded);
	fiber_port_mpu_encode_exact_region(layout->unprivileged_flash_start,
			layout->unprivileged_flash_end,
			fiber_portMPU_UNPRIVILEGED_FLASH_REGION_NUMBER,
			fiber_portMPU_REGION_NON_SHAREABLE |
			fiber_portMPU_REGION_READ_ONLY,
			fiber_portMPU_RLAR_ATTR_INDEX0, &encoded);
	fiber_port_mpu_encode_exact_region(layout->unprivileged_syscalls_start,
			layout->unprivileged_syscalls_end,
			fiber_portMPU_UNPRIVILEGED_SYSCALLS_REGION_NUMBER,
			fiber_portMPU_REGION_NON_SHAREABLE |
			fiber_portMPU_REGION_READ_ONLY,
			fiber_portMPU_RLAR_ATTR_INDEX0, &encoded);
	fiber_port_mpu_encode_exact_region(layout->privileged_sram_start,
			layout->privileged_sram_end,
			fiber_portMPU_PRIVILEGED_DATA_REGION_NUMBER,
			fiber_portMPU_REGION_NON_SHAREABLE |
			fiber_portMPU_REGION_PRIVILEGED_READ_WRITE |
			fiber_portMPU_REGION_EXECUTE_NEVER,
			fiber_portMPU_RLAR_ATTR_INDEX0, &encoded);

	fiber_port_require_32_byte_range(layout->current_context_slot_start,
			layout->current_context_slot_end, 'L');
	FIBER_REQUIRE((layout->current_context_slot_end -
			layout->current_context_slot_start) ==
			fiber_portMPU_CURRENT_CONTEXT_APERTURE_BYTES, 'L');
	FIBER_REQUIRE(fiber_port_range_contains(layout->privileged_sram_start,
				layout->privileged_sram_end,
				layout->current_context_slot_start,
				layout->current_context_slot_end), 'L');
	/* RNR 5 overlays the global privileged-SRAM mapping. It is read-only for
	 * both privilege levels because ARMv8-M has no privileged-RW plus
	 * unprivileged-RO AP encoding; the protected switch updates this slot only
	 * while MPU_CTRL is disabled. */
	fiber_port_mpu_encode_exact_region(layout->current_context_slot_start,
			layout->current_context_slot_end,
			fiber_portMPU_CURRENT_CONTEXT_REGION_NUMBER,
			fiber_portMPU_REGION_NON_SHAREABLE |
			fiber_portMPU_REGION_READ_ONLY |
			fiber_portMPU_REGION_EXECUTE_NEVER,
			fiber_portMPU_RLAR_ATTR_INDEX0, &encoded);

	/* ARMv8-M region priority makes overlapping global mappings ambiguous for
	 * this fixed policy. Unlike the FreeRTOS generic task API, this base Fiber
	 * profile has no privileged task stack escape hatch. */
	fiber_port_require_disjoint(layout->privileged_flash_start,
			layout->privileged_flash_end, layout->unprivileged_flash_start,
			layout->unprivileged_flash_end);
	fiber_port_require_disjoint(layout->privileged_flash_start,
			layout->privileged_flash_end, layout->unprivileged_syscalls_start,
			layout->unprivileged_syscalls_end);
	fiber_port_require_disjoint(layout->privileged_flash_start,
			layout->privileged_flash_end, layout->privileged_sram_start,
			layout->privileged_sram_end);
	fiber_port_require_disjoint(layout->privileged_flash_start,
			layout->privileged_flash_end, layout->unprivileged_ram_start,
			layout->unprivileged_ram_end);
	fiber_port_require_disjoint(layout->unprivileged_flash_start,
			layout->unprivileged_flash_end, layout->unprivileged_syscalls_start,
			layout->unprivileged_syscalls_end);
	fiber_port_require_disjoint(layout->unprivileged_flash_start,
			layout->unprivileged_flash_end, layout->privileged_sram_start,
			layout->privileged_sram_end);
	fiber_port_require_disjoint(layout->unprivileged_flash_start,
			layout->unprivileged_flash_end, layout->unprivileged_ram_start,
			layout->unprivileged_ram_end);
	fiber_port_require_disjoint(layout->unprivileged_syscalls_start,
			layout->unprivileged_syscalls_end, layout->privileged_sram_start,
			layout->privileged_sram_end);
	fiber_port_require_disjoint(layout->unprivileged_syscalls_start,
			layout->unprivileged_syscalls_end, layout->unprivileged_ram_start,
			layout->unprivileged_ram_end);
	fiber_port_require_disjoint(layout->privileged_sram_start,
			layout->privileged_sram_end, layout->unprivileged_ram_start,
			layout->unprivileged_ram_end);

	const uintptr_t context_init = fiber_port_function_address(
			(uintptr_t)&fiber_port_context_init);
	const uintptr_t layout_load = fiber_port_function_address(
			(uintptr_t)&fiber_port_mpu_load_linker_layout);
	const uintptr_t layout_check = fiber_port_function_address(
			(uintptr_t)&fiber_port_mpu_linker_layout_check);
	const uintptr_t region_encoder = fiber_port_function_address(
			(uintptr_t)&fiber_port_mpu_try_encode_exact_region);
	const uintptr_t global_builder = fiber_port_function_address(
			(uintptr_t)&fiber_port_mpu_build_global_regions);
	const uintptr_t seal_compute = fiber_port_function_address(
			(uintptr_t)&fiber_port_context_compute_seal);
	const uintptr_t seal_check = fiber_port_function_address(
			(uintptr_t)&fiber_port_context_seal_check);
	const uintptr_t initial_check = fiber_port_function_address(
			(uintptr_t)&fiber_port_context_validate_initial_restore);
	const uintptr_t panic_target = fiber_port_function_address(
			(uintptr_t)&fiber_panic);
	const uintptr_t return_target = fiber_port_function_address(
			(uintptr_t)&fiber_port_unprivileged_task_return);

	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->privileged_flash_start, layout->privileged_flash_end,
			context_init), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->privileged_flash_start, layout->privileged_flash_end,
			layout_load), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->privileged_flash_start, layout->privileged_flash_end,
			layout_check), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->privileged_flash_start, layout->privileged_flash_end,
			region_encoder), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->privileged_flash_start, layout->privileged_flash_end,
			global_builder), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->privileged_flash_start, layout->privileged_flash_end,
			seal_compute), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->privileged_flash_start, layout->privileged_flash_end,
			seal_check), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->privileged_flash_start, layout->privileged_flash_end,
			initial_check), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->privileged_flash_start, layout->privileged_flash_end,
			panic_target), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->unprivileged_syscalls_start,
			layout->unprivileged_syscalls_end, return_target), 'L');
}

FIBER_CM33_MPU_BOOT
void fiber_port_mpu_build_global_regions(FiberPortMpuGlobalRegionImage *image)
{
	FiberPortMpuMemoryLayout layout;
	FIBER_REQUIRE(image != NULL, 'M');
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);

	fiber_port_mpu_encode_exact_region(layout.privileged_flash_start,
			layout.privileged_flash_end,
			fiber_portMPU_PRIVILEGED_FLASH_REGION_NUMBER,
			fiber_portMPU_REGION_NON_SHAREABLE |
			fiber_portMPU_REGION_PRIVILEGED_READ_ONLY,
			fiber_portMPU_RLAR_ATTR_INDEX0,
			&image->regions[fiber_portMPU_PRIVILEGED_FLASH_REGION_NUMBER]);
	fiber_port_mpu_encode_exact_region(layout.unprivileged_flash_start,
			layout.unprivileged_flash_end,
			fiber_portMPU_UNPRIVILEGED_FLASH_REGION_NUMBER,
			fiber_portMPU_REGION_NON_SHAREABLE |
			fiber_portMPU_REGION_READ_ONLY,
			fiber_portMPU_RLAR_ATTR_INDEX0,
			&image->regions[fiber_portMPU_UNPRIVILEGED_FLASH_REGION_NUMBER]);
	fiber_port_mpu_encode_exact_region(layout.unprivileged_syscalls_start,
			layout.unprivileged_syscalls_end,
			fiber_portMPU_UNPRIVILEGED_SYSCALLS_REGION_NUMBER,
			fiber_portMPU_REGION_NON_SHAREABLE |
			fiber_portMPU_REGION_READ_ONLY,
			fiber_portMPU_RLAR_ATTR_INDEX0,
			&image->regions[
				fiber_portMPU_UNPRIVILEGED_SYSCALLS_REGION_NUMBER]);
	fiber_port_mpu_encode_exact_region(layout.privileged_sram_start,
			layout.privileged_sram_end,
			fiber_portMPU_PRIVILEGED_DATA_REGION_NUMBER,
			fiber_portMPU_REGION_NON_SHAREABLE |
			fiber_portMPU_REGION_PRIVILEGED_READ_WRITE |
			fiber_portMPU_REGION_EXECUTE_NEVER,
			fiber_portMPU_RLAR_ATTR_INDEX0,
			&image->regions[fiber_portMPU_PRIVILEGED_DATA_REGION_NUMBER]);
}

static FIBER_CM33_MPU_BOOT
void fiber_port_context_pointer_check(const FiberContext *ctx,
		const FiberPortMpuMemoryLayout *layout)
{
	FIBER_REQUIRE(ctx != NULL, 'C');
	FIBER_REQUIRE(layout != NULL, 'L');
	const uintptr_t start = (uintptr_t)ctx;
	FIBER_REQUIRE((start & ((uintptr_t)_Alignof(FiberContext) - 1u)) == 0u,
			'A');
	FIBER_REQUIRE(start <= (UINTPTR_MAX - sizeof(*ctx)), 'O');
	const uintptr_t end = start + sizeof(*ctx);
	FIBER_REQUIRE(fiber_port_range_contains(layout->privileged_sram_start,
				layout->privileged_sram_end, start, end), 'C');
	FIBER_REQUIRE(!fiber_port_ranges_overlap(start, end,
				layout->current_context_slot_start,
				layout->current_context_slot_end), 'C');
}

static FIBER_CM33_MPU_BOOT
void fiber_port_context_fast_check(const FiberContext *ctx,
		const FiberPortMpuMemoryLayout *layout)
{
	fiber_port_context_pointer_check(ctx, layout);
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

	const uintptr_t raw_stack_start = (uintptr_t)boot->begin;
	const uintptr_t raw_stack_end = (uintptr_t)boot->end;
	FIBER_REQUIRE(raw_stack_end > raw_stack_start, 'N');
	fiber_port_require_32_byte_range(raw_stack_start, raw_stack_end, 'A');
	FIBER_REQUIRE(fiber_port_range_contains(layout->unprivileged_ram_start,
				layout->unprivileged_ram_end,
				raw_stack_start, raw_stack_end), 'P');
	FIBER_REQUIRE(raw_stack_start <= UINTPTR_MAX -
			(uintptr_t)FIBER_STACK_REDZONE_BYTES, 'O');
	const uintptr_t expected_stack_base = fiber_stack_align_up(
			raw_stack_start + (uintptr_t)FIBER_STACK_REDZONE_BYTES);
	const uintptr_t expected_stack_top = fiber_stack_align_down(raw_stack_end);
	FIBER_REQUIRE(expected_stack_top > expected_stack_base, 'H');
	FIBER_REQUIRE(boot->stack_base == expected_stack_base, 'Z');
	FIBER_REQUIRE(boot->stack_top == expected_stack_top, 'z');
	FIBER_REQUIRE(boot->avail ==
			(size_t)(expected_stack_top - expected_stack_base), 'a');
	FIBER_REQUIRE(boot->avail >=
			(size_t)FIBER_PORT_CM33_MPU_STACK_REQUIRED_BYTES, 'H');

	const uintptr_t entry_address = (uintptr_t)boot->entry;
	FIBER_REQUIRE(entry_address != 0u, 'E');
	FIBER_REQUIRE((entry_address & 1u) != 0u, 'e');
	const uintptr_t code_address = fiber_port_function_address(entry_address);
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->unprivileged_flash_start, layout->unprivileged_flash_end,
			code_address), 'c');
	FIBER_REQUIRE(!fiber_port_code_address_is_in_range(
			layout->privileged_flash_start, layout->privileged_flash_end,
			code_address), 'c');
	FIBER_REQUIRE(!fiber_port_code_address_is_in_range(
			layout->unprivileged_syscalls_start,
			layout->unprivileged_syscalls_end, code_address), 'c');

	FIBER_REQUIRE(ctx->mair0 == fiber_portMPU_MAIR0_DEFAULT, 'M');
	FiberPortMpuRegionRegisters expected_stack_region;
	FiberPortMpuRegionRegisters expected_current_context_region;
	fiber_port_mpu_encode_exact_region(raw_stack_start, raw_stack_end,
			fiber_portMPU_STACK_REGION_NUMBER,
			fiber_portMPU_REGION_NON_SHAREABLE |
			fiber_portMPU_REGION_READ_WRITE |
			fiber_portMPU_REGION_EXECUTE_NEVER,
			fiber_portMPU_RLAR_ATTR_INDEX0, &expected_stack_region);
	FIBER_REQUIRE(ctx->mpu_regions[fiber_portMPU_CONTEXT_STACK_INDEX].rbar ==
			expected_stack_region.rbar, 'M');
	FIBER_REQUIRE(ctx->mpu_regions[fiber_portMPU_CONTEXT_STACK_INDEX].rlar ==
			expected_stack_region.rlar, 'M');
	fiber_port_mpu_encode_exact_region(layout->current_context_slot_start,
			layout->current_context_slot_end,
			fiber_portMPU_CURRENT_CONTEXT_REGION_NUMBER,
			fiber_portMPU_REGION_NON_SHAREABLE |
			fiber_portMPU_REGION_READ_ONLY |
			fiber_portMPU_REGION_EXECUTE_NEVER,
			fiber_portMPU_RLAR_ATTR_INDEX0, &expected_current_context_region);
	FIBER_REQUIRE(ctx->mpu_regions[
			fiber_portMPU_CONTEXT_CURRENT_CONTEXT_INDEX].rbar ==
			expected_current_context_region.rbar, 'M');
	FIBER_REQUIRE(ctx->mpu_regions[
			fiber_portMPU_CONTEXT_CURRENT_CONTEXT_INDEX].rlar ==
			expected_current_context_region.rlar, 'M');
	for (uint32_t index = fiber_portMPU_CONTEXT_FIRST_CONFIGURABLE_INDEX;
			index <= fiber_portMPU_CONTEXT_LAST_CONFIGURABLE_INDEX; ++index) {
		FIBER_REQUIRE(ctx->mpu_regions[index].rbar == 0u, 'M');
		FIBER_REQUIRE(ctx->mpu_regions[index].rlar == 0u, 'M');
	}
}

FIBER_CM33_MPU_BOOT
uint32_t fiber_port_context_compute_seal(const FiberContext *ctx)
{
	FiberPortMpuMemoryLayout layout;
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);
	fiber_port_context_pointer_check(ctx, &layout);

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
	hash = fiber_port_hash32_accum(hash, ctx->mair0);
	for (uint32_t index = 0u;
			index < fiber_portMPU_CONTEXT_REGION_COUNT; ++index) {
		hash = fiber_port_hash32_accum(hash, ctx->mpu_regions[index].rbar);
		hash = fiber_port_hash32_accum(hash, ctx->mpu_regions[index].rlar);
	}
	return hash;
}

FIBER_CM33_MPU_BOOT
void fiber_port_context_seal_check(const FiberContext *ctx)
{
	FiberPortMpuMemoryLayout layout;
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);
	fiber_port_context_fast_check(ctx, &layout);
	FIBER_REQUIRE(ctx->boot.hash == fiber_port_context_compute_seal(ctx), 'h');
}

FIBER_CM33_MPU_BOOT
void fiber_port_context_validate_initial_restore(const FiberContext *ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'C');
	fiber_port_context_seal_check(ctx);
	const FiberPortProtectedContext *const image = &ctx->protected_context;
	FIBER_REQUIRE(ctx->protected_context_cursor == &image->cursor_limit, 'P');
	FIBER_REQUIRE(image->cursor_limit == 0u, 'P');
	FIBER_REQUIRE(image->r4 == 0u && image->r5 == 0u &&
			image->r6 == 0u && image->r7 == 0u &&
			image->r8 == 0u && image->r10 == 0u && image->r11 == 0u,
			'R');
	FIBER_REQUIRE(image->r0 == (uint32_t)(uintptr_t)ctx->boot.arg, '0');
	FIBER_REQUIRE(image->r1 == 0u && image->r2 == 0u &&
			image->r3 == 0u && image->r12 == 0u, 'R');
	FIBER_REQUIRE(image->lr ==
			(((uint32_t)(uintptr_t)&fiber_port_unprivileged_task_return) | 1u),
			'R');
	FIBER_REQUIRE(image->pc == ((uint32_t)(uintptr_t)ctx->boot.entry &
			fiber_portSTART_ADDRESS_MASK), 'x');
	FIBER_REQUIRE(image->xpsr == fiber_portINITIAL_XPSR, 'X');
	FIBER_REQUIRE(image->psplim == (uint32_t)ctx->boot.stack_base, 'L');
	FIBER_REQUIRE((image->psp &
			((uint32_t)FIBER_PORT_STACK_ALIGNMENT - 1u)) == 0u, 'A');
	FIBER_REQUIRE(image->psp >= ctx->boot.stack_base, 'P');
	FIBER_REQUIRE(image->psp <=
			(ctx->boot.stack_top - (uintptr_t)FIBER_PORT_EXC_BASE_BYTES), 'P');
	FIBER_REQUIRE(image->control ==
			fiber_portINITIAL_CONTROL_UNPRIVILEGED, 'q');
	FIBER_REQUIRE(image->exc_return == fiber_portINITIAL_EXC_RETURN, 'x');
	FIBER_REQUIRE(ctx->runtime_flags == 0u, 'F');
#if FIBER_STACK_CANARY
	FIBER_REQUIRE(*(const volatile uint32_t *)(uintptr_t)ctx->boot.begin ==
			FIBER_INTERNAL_STACK_CANARY_VALUE, 'c');
#endif
}

static FIBER_CM33_MPU_BOOT
void fiber_port_context_initial_image_check(const FiberContext *ctx,
		uintptr_t initial_psp,
		uintptr_t entry_address,
		void *arg,
		uint32_t initial_r9,
		uint32_t return_address)
{
	fiber_port_context_validate_initial_restore(ctx);
	const FiberPortProtectedContext *const image = &ctx->protected_context;
	FIBER_REQUIRE(image->r9 == initial_r9, '9');
	FIBER_REQUIRE(image->r0 == (uint32_t)(uintptr_t)arg, '0');
	FIBER_REQUIRE(image->lr == return_address, 'R');
	FIBER_REQUIRE(image->pc ==
			((uint32_t)entry_address & fiber_portSTART_ADDRESS_MASK), 'x');
	FIBER_REQUIRE(image->psp == (uint32_t)initial_psp, 'P');
}

FIBER_CM33_MPU_BOOT
void fiber_port_context_init(FiberContext *ctx,
		void *stack_begin,
		void *stack_end,
		entry_t entry,
		void *arg)
{
	FiberPortMpuMemoryLayout layout;
	FiberPortMpuRegionRegisters stack_region;
	FiberPortMpuRegionRegisters current_context_region;
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
	FIBER_REQUIRE(ctx != NULL, 'C');
	FIBER_REQUIRE(stack_begin != NULL, 'B');
	FIBER_REQUIRE(stack_end != NULL, 'T');
	FIBER_REQUIRE(entry != NULL, 'E');

	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);
	fiber_port_context_pointer_check(ctx, &layout);

	const uintptr_t context_start = (uintptr_t)ctx;
	const uintptr_t context_end = context_start + sizeof(*ctx);
	const uintptr_t raw_stack_start = (uintptr_t)stack_begin;
	const uintptr_t raw_stack_end = (uintptr_t)stack_end;
	const uintptr_t entry_address = (uintptr_t)entry;
	const uint32_t initial_r9 = fiber_port_read_r9();
	const uint32_t return_address =
			((uint32_t)(uintptr_t)&fiber_port_unprivileged_task_return) | 1u;

	FIBER_REQUIRE(raw_stack_end > raw_stack_start, 'N');
	fiber_port_require_32_byte_range(raw_stack_start, raw_stack_end, 'A');
	FIBER_REQUIRE(!fiber_port_ranges_overlap(context_start, context_end,
				raw_stack_start, raw_stack_end), 'O');
	FIBER_REQUIRE(fiber_port_range_contains(layout.unprivileged_ram_start,
				layout.unprivileged_ram_end,
				raw_stack_start, raw_stack_end), 'P');
	FIBER_REQUIRE((entry_address & 1u) != 0u, 'e');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout.unprivileged_flash_start, layout.unprivileged_flash_end,
			fiber_port_function_address(entry_address)), 'c');
	FIBER_REQUIRE(!fiber_port_code_address_is_in_range(
			layout.privileged_flash_start, layout.privileged_flash_end,
			fiber_port_function_address(entry_address)), 'c');
	FIBER_REQUIRE(!fiber_port_code_address_is_in_range(
			layout.unprivileged_syscalls_start,
			layout.unprivileged_syscalls_end,
			fiber_port_function_address(entry_address)), 'c');
	FIBER_REQUIRE((return_address & 1u) != 0u, 'R');

	fiber_port_mpu_encode_exact_region(raw_stack_start, raw_stack_end,
			fiber_portMPU_STACK_REGION_NUMBER,
			fiber_portMPU_REGION_NON_SHAREABLE |
			fiber_portMPU_REGION_READ_WRITE |
			fiber_portMPU_REGION_EXECUTE_NEVER,
			fiber_portMPU_RLAR_ATTR_INDEX0, &stack_region);
	fiber_port_mpu_encode_exact_region(layout.current_context_slot_start,
			layout.current_context_slot_end,
			fiber_portMPU_CURRENT_CONTEXT_REGION_NUMBER,
			fiber_portMPU_REGION_NON_SHAREABLE |
			fiber_portMPU_REGION_READ_ONLY |
			fiber_portMPU_REGION_EXECUTE_NEVER,
			fiber_portMPU_RLAR_ATTR_INDEX0, &current_context_region);

	FIBER_REQUIRE(raw_stack_start <= UINTPTR_MAX -
			(uintptr_t)FIBER_STACK_REDZONE_BYTES, 'O');
	const uintptr_t stack_base = fiber_stack_align_up(raw_stack_start +
			(uintptr_t)FIBER_STACK_REDZONE_BYTES);
	const uintptr_t stack_top = fiber_stack_align_down(raw_stack_end);
	FIBER_REQUIRE(stack_top > stack_base, 'H');
	FIBER_REQUIRE((stack_top - stack_base) >=
			(uintptr_t)FIBER_PORT_CM33_MPU_STACK_REQUIRED_BYTES, 'H');
	FIBER_REQUIRE(stack_top >= (uintptr_t)FIBER_PORT_EXC_BASE_BYTES, 'H');
	const uintptr_t initial_psp = stack_top -
			(uintptr_t)FIBER_PORT_EXC_BASE_BYTES;
	FIBER_REQUIRE(initial_psp >= stack_base, 'H');
	FIBER_REQUIRE((initial_psp &
			((uintptr_t)FIBER_PORT_STACK_ALIGNMENT - 1u)) == 0u, 'A');

	ctx->mair0 = fiber_portMPU_MAIR0_DEFAULT;
	for (uint32_t index = 0u;
			index < fiber_portMPU_CONTEXT_REGION_COUNT; ++index) {
		fiber_port_mpu_disable_context_region(&ctx->mpu_regions[index]);
	}
	ctx->mpu_regions[fiber_portMPU_CONTEXT_STACK_INDEX] = stack_region;
	ctx->mpu_regions[fiber_portMPU_CONTEXT_CURRENT_CONTEXT_INDEX] =
			current_context_region;

	/* FreeRTOS-compatible no-TrustZone protected-image layout. The hardware
	 * frame is stored in privileged FiberContext memory, never prewritten on
	 * user PSP. Fiber deliberately uses deterministic zero seeds for scratch
	 * registers and preserves r9 for platform/static-base ABI compatibility;
	 * FreeRTOS uses debug marker constants for those initial register values. */
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
	ctx->protected_context.lr = return_address;
	ctx->protected_context.pc =
			(uint32_t)(entry_address & (uintptr_t)fiber_portSTART_ADDRESS_MASK);
	ctx->protected_context.xpsr = fiber_portINITIAL_XPSR;
	ctx->protected_context.psp = (uint32_t)initial_psp;
	ctx->protected_context.psplim = (uint32_t)stack_base;
	ctx->protected_context.control =
			fiber_portINITIAL_CONTROL_UNPRIVILEGED;
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
	*(volatile uint32_t *)raw_stack_start = FIBER_INTERNAL_STACK_CANARY_VALUE;
#endif

	ctx->boot.hash = fiber_port_context_compute_seal(ctx);
	ctx->boot.sealed = 1u;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_portCOMPILER_BARRIER();
	fiber_port_context_seal_check(ctx);
	fiber_port_context_initial_image_check(ctx, initial_psp, entry_address, arg,
			initial_r9, return_address);
}

#undef FIBER_CM33_MPU_BOOT

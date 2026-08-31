/*
 * ARM_CM55_MVEF_MPU/non_secure protected MVE-FP PendSV component.
 *
 * This source owns the later runtime form of the frozen 54-word protected
 * context image. It follows the MPU plus FPU/MVE branch of FreeRTOS
 * GCC/ARM_CM55_NTZ/non_secure/portasm.c exactly where state moves:
 *
 *   extended save:
 *     s16-s31, copied s0-s15/FPSCR, r4-r11, copied basic frame,
 *     PSP/PSPLIM/CONTROL/EXC_RETURN
 *
 *   extended restore:
 *     special registers, copied basic frame, r4-r11,
 *     copied s0-s15/FPSCR, s16-s31
 *
 * MVE changes the exact compiler/cohort contract, but this pinned FreeRTOS
 * branch has no VPR software slot or VPR transfer.
 *
 * The backing storage is intentionally overlapping. A basic first start uses
 * words 0..19 and cursor word 20. An extended save overwrites words 0..52 and
 * advances the cursor to word 53. The mandatory SVC/runtime object owns the
 * forward ABI and retains this separate handler component through its unique
 * bundle anchor.
 */

#include "fiber_port_private.h"
#include "../../../fiber_panic.h"

#define FIBER_CM55_MVEF_MPU_PENDSV \
	FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY \
	fiber_portPRIVILEGED_FUNCTION

/* The mandatory SVC/runtime object calls this one-shot private bundle anchor.
 * It forces this archive member independently of startup weak aliases and
 * retains the reverse ABI plus exact context-cohort relocations without adding
 * either read to the PendSV hot path. */
FIBER_CM55_MVEF_MPU_PENDSV
void fiber_port_arm_cm55_mvef_mpu_pendsv_handler_component_v1_anchor(void)
{
	FIBER_RUNTIME_PORT_ABI_RETAIN_V1();
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
}

static FIBER_CM55_MVEF_MPU_PENDSV
uintptr_t fiber_port_code_address(uintptr_t address)
{
	return address & ~(uintptr_t)1u;
}

static FIBER_CM55_MVEF_MPU_PENDSV
int fiber_port_range_contains(uintptr_t outer_start,
		uintptr_t outer_end,
		uintptr_t inner_start,
		uintptr_t inner_end)
{
	return (outer_end > outer_start) && (inner_end > inner_start) &&
			(inner_start >= outer_start) && (inner_end <= outer_end);
}

static FIBER_CM55_MVEF_MPU_PENDSV
int fiber_port_code_address_is_in_range(uintptr_t range_start,
		uintptr_t range_end,
		uintptr_t address)
{
	return (address <= (UINTPTR_MAX - 2u)) &&
			fiber_port_range_contains(range_start, range_end,
					address, address + 2u);
}

static FIBER_CM55_MVEF_MPU_PENDSV
void fiber_port_require_mpu_geometry(void)
{
	FIBER_REQUIRE((fiber_portMPU_TYPE_REG & fiber_portMPU_TYPE_DREGION_MASK) ==
			fiber_portMPU_EXPECTED_TYPE, 'M');
}

static FIBER_CM55_MVEF_MPU_PENDSV
void fiber_port_mpu_write_region(uint32_t region_number,
		const FiberPortMpuRegionRegisters *region)
{
	FIBER_REQUIRE(region != NULL, 'M');
	FIBER_REQUIRE(region_number < fiber_portMPU_TOTAL_REGIONS, 'M');
	fiber_portMPU_RNR_REG = region_number;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_portMPU_RNR_REG == region_number, 'M');
	fiber_portMPU_RBAR_REG = region->rbar;
	fiber_portMPU_RLAR_REG = region->rlar;
}

static FIBER_CM55_MVEF_MPU_PENDSV
void fiber_port_mpu_validate_region_readback(uint32_t region_number,
		const FiberPortMpuRegionRegisters *expected)
{
	FIBER_REQUIRE(expected != NULL, 'M');
	FIBER_REQUIRE(region_number < fiber_portMPU_TOTAL_REGIONS, 'M');
	fiber_portMPU_RNR_REG = region_number;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_portMPU_RNR_REG == region_number, 'M');
	FIBER_REQUIRE(fiber_portMPU_RBAR_REG == expected->rbar, 'M');
	FIBER_REQUIRE(fiber_portMPU_RLAR_REG == expected->rlar, 'M');
}

static FIBER_CM55_MVEF_MPU_PENDSV
uint32_t fiber_port_context_saved_form(const FiberContext *ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'N');
	const FiberPortProtectedContext *const image = &ctx->protected_context;
	if (ctx->protected_context_cursor == &image->basic.cursor_limit) {
		FIBER_REQUIRE(image->basic.cursor_limit == 0u, 'P');
		return 0u;
	}
	if (ctx->protected_context_cursor == &image->extended.cursor_limit) {
		FIBER_REQUIRE(image->extended.cursor_limit == 0u, 'P');
		return 1u;
	}
	fiber_panic('P');
	FIBER_API_UNREACHABLE();
}

static FIBER_CM55_MVEF_MPU_PENDSV
void fiber_port_validate_stack_canary(const FiberContext *ctx)
{
#if FIBER_STACK_CANARY
	FIBER_REQUIRE(ctx != NULL, 'C');
	FIBER_REQUIRE(*(const volatile uint32_t *)(uintptr_t)ctx->boot.begin ==
			FIBER_INTERNAL_STACK_CANARY_VALUE, 'c');
#else
	(void)ctx;
#endif
}

static FIBER_CM55_MVEF_MPU_PENDSV
void fiber_port_validate_saved_hardware_frame(const FiberContext *ctx,
		const FiberPortMpuMemoryLayout *layout,
		uint32_t extended)
{
	FIBER_REQUIRE(ctx != NULL, 'N');
	FIBER_REQUIRE(layout != NULL, 'L');
	const FiberPortProtectedContext *const image = &ctx->protected_context;
	const uint32_t stacked_pc = extended != 0u
			? image->extended.pc
			: image->basic.pc;
	const uint32_t stacked_xpsr = extended != 0u
			? image->extended.xpsr
			: image->basic.xpsr;

	FIBER_REQUIRE(stacked_pc >= 2u, 'x');
	FIBER_REQUIRE((stacked_pc & 1u) == 0u, 'x');
	FIBER_REQUIRE((stacked_xpsr & fiber_portXPSR_THUMB_BIT) != 0u, 'x');
	FIBER_REQUIRE((stacked_xpsr & fiber_portXPSR_IPSR_MASK) == 0u, 'x');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->unprivileged_flash_start, layout->unprivileged_flash_end,
			(uintptr_t)stacked_pc), 'c');
	FIBER_REQUIRE(!fiber_port_code_address_is_in_range(
			layout->privileged_flash_start, layout->privileged_flash_end,
			(uintptr_t)stacked_pc), 'c');
	FIBER_REQUIRE(!fiber_port_code_address_is_in_range(
			layout->unprivileged_syscalls_start,
			layout->unprivileged_syscalls_end, (uintptr_t)stacked_pc), 'c');
}

FIBER_CM55_MVEF_MPU_PENDSV
void fiber_port_context_validate_restore(FiberContext *ctx)
{
	FiberPortMpuMemoryLayout layout;
	FIBER_REQUIRE(ctx != NULL, 'N');
	fiber_port_context_seal_check(ctx);
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);
	fiber_port_fpu_require_configured();

	const uint32_t extended = fiber_port_context_saved_form(ctx);
	const FiberPortProtectedContext *const image = &ctx->protected_context;
	const uint32_t psp = extended != 0u
			? image->extended.psp
			: image->basic.psp;
	const uint32_t psplim = extended != 0u
			? image->extended.psplim
			: image->basic.psplim;
	const uint32_t control = extended != 0u
			? image->extended.control
			: image->basic.control;
	const uint32_t exc_return = extended != 0u
			? image->extended.exc_return
			: image->basic.exc_return;
	const uint32_t stacked_xpsr = extended != 0u
			? image->extended.xpsr
			: image->basic.xpsr;

	FIBER_REQUIRE(ctx->runtime_flags == 0u, 'F');
	FIBER_REQUIRE(psplim == (uint32_t)ctx->boot.stack_base, 'L');
	FIBER_REQUIRE((control & 3u) ==
			fiber_portINITIAL_CONTROL_UNPRIVILEGED, 'q');
	if (extended != 0u) {
		FIBER_REQUIRE((control & 4u) != 0u, 'q');
		FIBER_REQUIRE(exc_return == fiber_portEXTENDED_EXC_RETURN, 'x');
	} else {
		FIBER_REQUIRE((control & 4u) == 0u, 'q');
		FIBER_REQUIRE(exc_return == fiber_portINITIAL_EXC_RETURN, 'x');
	}

	const uintptr_t raw_psp = (uintptr_t)psp;
	FIBER_REQUIRE((raw_psp &
			((uintptr_t)FIBER_PORT_STACK_ALIGNMENT - 1u)) == 0u, 'A');
	FIBER_REQUIRE(raw_psp >= ctx->boot.stack_base, 'P');
	uintptr_t frame_bytes = (uintptr_t)FIBER_PORT_EXC_BASE_BYTES;
	if (extended != 0u) {
		frame_bytes += (uintptr_t)FIBER_PORT_EXC_FP_EXT_BYTES;
	}
	if ((stacked_xpsr & fiber_portXPSR_STACK_ALIGN_BIT) != 0u) {
		frame_bytes += (uintptr_t)FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES;
	}
	FIBER_REQUIRE(raw_psp <= UINTPTR_MAX - frame_bytes, 'O');
	FIBER_REQUIRE((raw_psp + frame_bytes) <= ctx->boot.stack_top, 'P');
	fiber_port_validate_stack_canary(ctx);
	fiber_port_validate_saved_hardware_frame(ctx, &layout, extended);
}

static FIBER_CM55_MVEF_MPU_PENDSV
void fiber_port_validate_running_context_frame(const FiberContext *current,
		const uint32_t *hardware_frame,
		uint32_t exc_return)
{
	FIBER_REQUIRE(current != NULL, 'C');
	FIBER_REQUIRE(hardware_frame != NULL, 'P');
	fiber_port_context_seal_check(current);
	fiber_port_fpu_require_configured();

	const FiberPortProtectedContext *const image =
			&current->protected_context;
	FIBER_REQUIRE(current->protected_context_cursor == &image->words[0], 'P');
	FIBER_REQUIRE(current->runtime_flags == 0u, 'F');
	FIBER_REQUIRE((__get_CONTROL() & 3u) ==
			fiber_portINITIAL_CONTROL_UNPRIVILEGED, 'l');
	FIBER_REQUIRE(__get_PSPLIM() == (uint32_t)current->boot.stack_base, 'L');
	if (exc_return == fiber_portINITIAL_EXC_RETURN) {
		FIBER_REQUIRE((__get_CONTROL() & 4u) == 0u, 'l');
	} else if (exc_return == fiber_portEXTENDED_EXC_RETURN) {
		FIBER_REQUIRE((__get_CONTROL() & 4u) != 0u, 'l');
	} else {
		fiber_panic('l');
		FIBER_API_UNREACHABLE();
	}

	const uintptr_t raw_frame = (uintptr_t)hardware_frame;
	FIBER_REQUIRE((raw_frame &
			((uintptr_t)FIBER_PORT_STACK_ALIGNMENT - 1u)) == 0u, 'A');
	FIBER_REQUIRE(raw_frame == (uintptr_t)__get_PSP(), 'P');
	/* Unlike the ordinary PSP-resident MVE-FP port, FreeRTOS MPU PendSV
	 * treats PSP as the copied basic frame and places s0-s15/FPSCR after it.
	 * Its `add r2, r2, #0x20` / `vldmia r2, {s0-s16}` sequence is the frozen
	 * layout proof. Do not apply the non-MPU extended-frame offset here. */
	const uint32_t *const core_frame = (const uint32_t *)raw_frame;
	const uint32_t stacked_xpsr = core_frame[7];
	uintptr_t frame_bytes = (uintptr_t)FIBER_PORT_EXC_BASE_BYTES;
	if (exc_return == fiber_portEXTENDED_EXC_RETURN) {
		frame_bytes += (uintptr_t)FIBER_PORT_EXC_FP_EXT_BYTES;
	}
	if ((stacked_xpsr & fiber_portXPSR_STACK_ALIGN_BIT) != 0u) {
		frame_bytes += (uintptr_t)FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES;
	}
	FIBER_REQUIRE(raw_frame <= UINTPTR_MAX - frame_bytes, 'O');
	FIBER_REQUIRE(fiber_port_range_contains(current->boot.stack_base,
				current->boot.stack_top, raw_frame,
				raw_frame + frame_bytes), 'P');
	FIBER_REQUIRE((stacked_xpsr & fiber_portXPSR_THUMB_BIT) != 0u, 'x');
	FIBER_REQUIRE((stacked_xpsr & fiber_portXPSR_IPSR_MASK) == 0u, 'x');
	FIBER_REQUIRE((core_frame[6] & 1u) == 0u, 'x');
	fiber_port_validate_stack_canary(current);
}

FIBER_CM55_MVEF_MPU_PENDSV
void fiber_port_mpu_validate_active_context(const FiberContext *ctx)
{
	FiberPortMpuGlobalRegionImage global;
	FIBER_REQUIRE(ctx != NULL, 'N');
	fiber_port_context_seal_check(ctx);
	fiber_port_fpu_require_configured();
	fiber_port_require_mpu_geometry();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == fiber_portMPU_CTRL_REQUIRED, 'M');
	FIBER_REQUIRE((fiber_portSCB_SHCSR_REG &
			fiber_portSCB_MEMFAULTENA_BIT) != 0u, 'M');
	FIBER_REQUIRE(fiber_portMPU_MAIR0_REG == ctx->mair0, 'M');
	fiber_port_mpu_build_global_regions(&global);

	for (uint32_t region = 0u; region < fiber_portMPU_GLOBAL_REGION_COUNT;
			++region) {
		fiber_port_mpu_validate_region_readback(region, &global.regions[region]);
	}
	for (uint32_t index = 0u; index < fiber_portMPU_CONTEXT_REGION_COUNT;
			++index) {
		fiber_port_mpu_validate_region_readback(
				fiber_portMPU_STACK_REGION_NUMBER + index,
				&ctx->mpu_regions[index]);
	}

	fiber_portMPU_RNR_REG = fiber_portMPU_LAST_CONTEXT_BLOCK_REGION;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_portMPU_RNR_REG ==
			fiber_portMPU_LAST_CONTEXT_BLOCK_REGION, 'M');
}

FIBER_CM55_MVEF_MPU_PENDSV
void fiber_port_pendsv_validate_save_current(FiberContext *current,
		uint32_t *hardware_frame,
		uint32_t exc_return)
{
	FIBER_REQUIRE(__get_IPSR() == 14u, 'j');
	FIBER_REQUIRE((exc_return == fiber_portINITIAL_EXC_RETURN) ||
			(exc_return == fiber_portEXTENDED_EXC_RETURN), 'l');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
	fiber_port_validate_running_context_frame(current, hardware_frame,
			exc_return);
	fiber_port_mpu_validate_active_context(current);
}

typedef struct FiberPortMpuSchedulerCpuState {
	uint32_t primask;
	uint32_t basepri;
	uint32_t faultmask;
	uint32_t control;
	uint32_t ipsr;
	uint32_t psp;
	uint32_t psplim;
	uintptr_t vector_base;
	uint32_t svc_priority;
	uint32_t pendsv_priority;
	uint32_t pendsv_pending;
	uint32_t cpacr;
	uint32_t fpccr;
	uint32_t mpu_ctrl;
	uint32_t mpu_rnr;
	uint32_t mair0;
	uint32_t memfault_enabled;
	FiberPortMpuRegionRegisters mpu_regions[fiber_portMPU_TOTAL_REGIONS];
} FiberPortMpuSchedulerCpuState;

static FIBER_CM55_MVEF_MPU_PENDSV
void fiber_port_capture_scheduler_mpu_image(
		FiberPortMpuSchedulerCpuState *state)
{
	FIBER_REQUIRE(state != NULL, 'C');
	FIBER_REQUIRE(state->mpu_rnr < fiber_portMPU_TOTAL_REGIONS, 'M');
	for (uint32_t region = 0u; region < fiber_portMPU_TOTAL_REGIONS;
			++region) {
		fiber_portMPU_RNR_REG = region;
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
		FIBER_REQUIRE(fiber_portMPU_RNR_REG == region, 'M');
		state->mpu_regions[region].rbar = fiber_portMPU_RBAR_REG;
		state->mpu_regions[region].rlar = fiber_portMPU_RLAR_REG;
	}
	fiber_portMPU_RNR_REG = state->mpu_rnr;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_portMPU_RNR_REG == state->mpu_rnr, 'M');
}

static FIBER_CM55_MVEF_MPU_PENDSV
void fiber_port_validate_scheduler_mpu_image(
		const FiberPortMpuSchedulerCpuState *before)
{
	FIBER_REQUIRE(before != NULL, 'C');
	FIBER_REQUIRE(before->mpu_rnr < fiber_portMPU_TOTAL_REGIONS, 'M');
	for (uint32_t region = 0u; region < fiber_portMPU_TOTAL_REGIONS;
			++region) {
		fiber_portMPU_RNR_REG = region;
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
		FIBER_REQUIRE(fiber_portMPU_RNR_REG == region, 'M');
		FIBER_REQUIRE(fiber_portMPU_RBAR_REG ==
				before->mpu_regions[region].rbar, 'M');
		FIBER_REQUIRE(fiber_portMPU_RLAR_REG ==
				before->mpu_regions[region].rlar, 'M');
	}
	fiber_portMPU_RNR_REG = before->mpu_rnr;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_portMPU_RNR_REG == before->mpu_rnr, 'M');
}

static FIBER_CM55_MVEF_MPU_PENDSV
void fiber_port_capture_scheduler_cpu_state(
		FiberPortMpuSchedulerCpuState *state)
{
	FIBER_REQUIRE(state != NULL, 'C');
	fiber_portCOMPILER_BARRIER();
	state->primask = __get_PRIMASK();
	state->basepri = fiber_port_basepri_read();
	state->faultmask = __get_FAULTMASK();
	state->control = __get_CONTROL();
	state->ipsr = __get_IPSR();
	state->psp = __get_PSP();
	state->psplim = __get_PSPLIM();
	state->vector_base = fiber_port_vectors_base_addr();
	state->svc_priority = NVIC_GetPriority(SVCall_IRQn);
	state->pendsv_priority = NVIC_GetPriority(PendSV_IRQn);
	state->pendsv_pending = fiber_portNVIC_INT_CTRL_REG &
			fiber_portNVIC_PENDSVSET_BIT;
	FIBER_REQUIRE(state->pendsv_pending == 0u, 'J');
	state->cpacr = fiber_portCPACR_REG;
	state->fpccr = fiber_portFPCCR_REG;
	state->mpu_ctrl = fiber_portMPU_CTRL_REG;
	state->mpu_rnr = fiber_portMPU_RNR_REG;
	state->mair0 = fiber_portMPU_MAIR0_REG;
	state->memfault_enabled = fiber_portSCB_SHCSR_REG &
			fiber_portSCB_MEMFAULTENA_BIT;
	fiber_port_capture_scheduler_mpu_image(state);
	fiber_portCOMPILER_BARRIER();
}

static FIBER_CM55_MVEF_MPU_PENDSV
void fiber_port_validate_scheduler_cpu_state(
		const FiberPortMpuSchedulerCpuState *before)
{
	FIBER_REQUIRE(before != NULL, 'C');
	fiber_portCOMPILER_BARRIER();
	FIBER_REQUIRE(__get_PRIMASK() == before->primask, 'r');
	FIBER_REQUIRE(fiber_port_basepri_read() == before->basepri, 'B');
	FIBER_REQUIRE(__get_FAULTMASK() == before->faultmask, 't');
	FIBER_REQUIRE(__get_CONTROL() == before->control, 'l');
	FIBER_REQUIRE(__get_IPSR() == before->ipsr, 'i');
	FIBER_REQUIRE(__get_PSP() == before->psp, 'P');
	FIBER_REQUIRE(__get_PSPLIM() == before->psplim, 'L');
	FIBER_REQUIRE(fiber_port_vectors_base_addr() == before->vector_base, 'V');
	FIBER_REQUIRE(NVIC_GetPriority(SVCall_IRQn) == before->svc_priority, 'w');
	FIBER_REQUIRE(NVIC_GetPriority(PendSV_IRQn) == before->pendsv_priority,
			'P');
	FIBER_REQUIRE((fiber_portNVIC_INT_CTRL_REG &
			fiber_portNVIC_PENDSVSET_BIT) == before->pendsv_pending, 'J');
	FIBER_REQUIRE(fiber_portCPACR_REG == before->cpacr, 'e');
	FIBER_REQUIRE(fiber_portFPCCR_REG == before->fpccr, 'E');
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == before->mpu_ctrl, 'M');
	FIBER_REQUIRE(fiber_portMPU_RNR_REG == before->mpu_rnr, 'M');
	FIBER_REQUIRE(fiber_portMPU_MAIR0_REG == before->mair0, 'M');
	FIBER_REQUIRE((fiber_portSCB_SHCSR_REG &
			fiber_portSCB_MEMFAULTENA_BIT) == before->memfault_enabled, 'M');
	fiber_port_validate_scheduler_mpu_image(before);
	fiber_port_fpu_require_configured();
	fiber_portCOMPILER_BARRIER();
}

FIBER_CM55_MVEF_MPU_PENDSV
FiberContext *fiber_port_scheduler_pick_first_from_start(void)
{
	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
	FIBER_REQUIRE(__get_CONTROL() == 0u, 'l');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
	fiber_port_fpu_require_ready();
	fiber_port_require_mpu_geometry();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');

	const uint32_t previous = fiber_port_primask_save_disable();
	FIBER_REQUIRE(previous == 0u, 'p');
	FiberPortMpuSchedulerCpuState cpu_state;
	fiber_port_capture_scheduler_cpu_state(&cpu_state);
	FiberContext *const first =
			fiber_internal_runtime_select_scheduler_candidate(NULL);
	fiber_port_validate_scheduler_cpu_state(&cpu_state);
	fiber_port_context_validate_initial_restore(first);
	fiber_port_primask_restore(previous);
	return first;
}

FIBER_CM55_MVEF_MPU_PENDSV
FiberContext *fiber_port_scheduler_pick_next_from_pendsv(
		FiberContext *current)
{
	FIBER_REQUIRE(current != NULL, 'C');
	FIBER_REQUIRE(__get_IPSR() == 14u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() ==
			FIBER_PORT_SCHEDULER_BASEPRI, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
	FIBER_REQUIRE((__get_CONTROL() & 3u) ==
			fiber_portINITIAL_CONTROL_UNPRIVILEGED, 'l');
	fiber_port_fpu_require_configured();

	FiberPortMpuSchedulerCpuState cpu_state;
	fiber_port_capture_scheduler_cpu_state(&cpu_state);
	FiberContext *const next =
			fiber_internal_runtime_select_scheduler_candidate(current);
	fiber_port_validate_scheduler_cpu_state(&cpu_state);
	fiber_port_context_validate_restore(next);
	return next;
}

FIBER_CM55_MVEF_MPU_PENDSV
void fiber_port_mpu_switch_to_context(FiberContext *next)
{
	FIBER_REQUIRE(next != NULL, 'N');
	FIBER_REQUIRE(__get_IPSR() == 14u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() != 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() ==
			FIBER_PORT_SCHEDULER_BASEPRI, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
	FIBER_REQUIRE((__get_CONTROL() & 3u) ==
			fiber_portINITIAL_CONTROL_UNPRIVILEGED, 'l');
	fiber_port_context_validate_restore(next);
	fiber_port_fpu_require_configured();
	fiber_port_require_mpu_geometry();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == fiber_portMPU_CTRL_REQUIRED, 'M');

	/* The published pointer changes only while the selected current-slot MPU
	 * aperture is temporarily covered by the privileged global SRAM image. */
	fiber_portDATA_SYNC_BARRIER();
	fiber_portMPU_CTRL_REG = 0u;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');

	fiber_portMPU_MAIR0_REG = next->mair0;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_portMPU_MAIR0_REG == next->mair0, 'M');
	for (uint32_t index = 0u; index < fiber_portMPU_CONTEXT_REGION_COUNT;
			++index) {
		fiber_port_mpu_write_region(
				fiber_portMPU_STACK_REGION_NUMBER + index,
				&next->mpu_regions[index]);
	}

	fiber_internal_runtime_publish_current_context(next);

	fiber_portMPU_CTRL_REG = fiber_portMPU_CTRL_REQUIRED;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == fiber_portMPU_CTRL_REQUIRED, 'M');
	fiber_port_mpu_validate_active_context(next);
}

FIBER_ATTR_NAKED_ASM fiber_portPRIVILEGED_FUNCTION
void PendSV_Handler(void)
{
	fiber_portASM volatile(
			".syntax unified                                      \n"
			/* Only the selected Non-secure Thread/PSP basic or extended
			 * exception return forms may enter the protected engine. */
			"mrs   r3, ipsr                                       \n"
			"cmp   r3, #14                                        \n"
			"bne   90f                                            \n"
			"mvn   r3, #67                                        \n" /* 0xFFFFFFBC */
			"cmp   lr, r3                                         \n"
			"beq   1f                                             \n"
			"bic   r3, r3, #0x10                                  \n" /* 0xFFFFFFAC */
			"cmp   lr, r3                                         \n"
			"bne   90f                                            \n"
			"1:                                                   \n"
			"tst   lr, #4                                         \n"
			"beq   90f                                            \n"

			"mrs   r0, psp                                        \n"
			"tst   r0, #7                                         \n"
			"bne   91f                                            \n"
			"ldr   r1, =fiber_internal_runtime_current_context_slot \n"
			"ldr   r1, [r1]                                       \n"
			"cmp   r1, #0                                         \n"
			"beq   92f                                            \n"

			/* C validates the pointer, sealed immutable metadata, live basic or
			 * extended hardware frame, FPU policy, and active MPU image before
			 * this naked path reads the mutable protected cursor. */
			"push  {r0, r1, r2, lr}                               \n"
			"mov   r2, lr                                         \n"
			"mov   r3, r0                                         \n"
			"mov   r0, r1                                         \n"
			"mov   r1, r3                                         \n"
			"bl    fiber_port_pendsv_validate_save_current        \n"
			"pop   {r0, r1, r2, lr}                               \n"

			/* Exact FreeRTOS protected save ordering. The copied low FP hardware
			 * state deliberately occupies words 16..32 of the same 54-word image. */
			"mov   r2, r1                                         \n"
			"ldr   r1, [r2, #0]                                   \n"
			"adds  r0, #0x20                                      \n"
			"tst   lr, #0x10                                      \n"
			"bne   2f                                             \n"
			"vstmia r1!, {s16-s31}                                \n"
			"vldmia r0, {s0-s16}                                  \n"
			"vstmia r1!, {s0-s16}                                 \n"
			"2:                                                   \n"
			"subs  r0, #0x20                                      \n"
			"stmia r1!, {r4-r11}                                  \n"
			"ldmia r0, {r4-r11}                                   \n"
			"stmia r1!, {r4-r11}                                  \n"
			"mrs   r3, psplim                                     \n"
			"mrs   r4, control                                    \n"
			"stmia r1!, {r0, r3, r4, lr}                           \n"
			"str   r1, [r2, #0]                                   \n"

			/* The common scheduler decides only policy. Its complete call graph is
			 * general-registers-only and must preserve the captured CPU/MPU image. */
			"movs  r0, #%c[sched_basepri]                          \n"
			fiber_portASM_WRITE_BASEPRI_R0_SYNC
			"mov   r0, r2                                         \n"
			"bl    fiber_port_scheduler_pick_next_from_pendsv     \n"

			/* PRIMASK covers the brief disabled-MPU window. BASEPRI remains at the
			 * scheduler threshold until the new context image is fully validated. */
			"cpsid i                                               \n"
			"dsb                                                   \n"
			"isb                                                   \n"
			"push  {r0, lr}                                       \n"
			"bl    fiber_port_mpu_switch_to_context               \n"
			"pop   {r2, lr}                                       \n"
			"movs  r0, #0                                         \n"
			fiber_portASM_WRITE_BASEPRI_R0_SYNC
			"mrs   r3, " fiber_portBASEPRI_SYM "                  \n"
			"cmp   r3, #0                                         \n"
			"bne   93f                                            \n"

			/* Exact inverse protected restore: special words, copied basic frame,
			 * callee-saved core registers, copied low FP state, then s16-s31. */
			"ldr   r1, [r2, #0]                                   \n"
			"ldmdb r1!, {r0, r3, r4, lr}                           \n"
			"msr   psp, r0                                        \n"
			"isb                                                   \n"
			"mrs   r5, psp                                        \n"
			"cmp   r5, r0                                         \n"
			"bne   91f                                            \n"
			"msr   psplim, r3                                     \n"
			"isb                                                   \n"
			"mrs   r5, psplim                                     \n"
			"cmp   r5, r3                                         \n"
			"bne   94f                                            \n"
			"msr   control, r4                                    \n"
			"isb                                                   \n"
			"mrs   r5, control                                    \n"
			"and   r5, r5, #7                                     \n"
			"cmp   r5, r4                                         \n"
			"bne   90f                                            \n"
			"ldmdb r1!, {r4-r11}                                  \n"
			"stmia r0!, {r4-r11}                                  \n"
			"ldmdb r1!, {r4-r11}                                  \n"
			"tst   lr, #0x10                                      \n"
			"bne   3f                                             \n"
			"vldmdb r1!, {s0-s16}                                 \n"
			"vstmia r0!, {s0-s16}                                 \n"
			"vldmdb r1!, {s16-s31}                                \n"
			"3:                                                   \n"
			"str   r1, [r2, #0]                                   \n"
			"mrs   r3, primask                                    \n"
			"cmp   r3, #1                                         \n"
			"bne   90f                                            \n"
			"mrs   r3, faultmask                                  \n"
			"cmp   r3, #0                                         \n"
			"bne   90f                                            \n"
			"cpsie i                                               \n"
			"dsb                                                   \n"
			"isb                                                   \n"
			"bx    lr                                              \n"

			"90:                                                   \n"
			"movs  r0, #108                                       \n" /* 'l' */
			"bl    fiber_panic                                    \n"
			"b     90b                                            \n"
			"91:                                                   \n"
			"movs  r0, #80                                        \n" /* 'P' */
			"bl    fiber_panic                                    \n"
			"b     91b                                            \n"
			"92:                                                   \n"
			"movs  r0, #67                                        \n" /* 'C' */
			"bl    fiber_panic                                    \n"
			"b     92b                                            \n"
			"93:                                                   \n"
			"movs  r0, #98                                        \n" /* 'b' */
			"bl    fiber_panic                                    \n"
			"b     93b                                            \n"
			"94:                                                   \n"
			"movs  r0, #76                                        \n" /* 'L' */
			"bl    fiber_panic                                    \n"
			"b     94b                                            \n"
			".ltorg                                                \n"
			:
			: [sched_basepri] "i" (FIBER_PORT_SCHEDULER_BASEPRI)
			: "memory", "cc");
}

#undef FIBER_CM55_MVEF_MPU_PENDSV

/*
 * ARM_CM0_MPU protected first-start service.
 *
 * This slice owns the strong SVC handler, its native start/return services,
 * one-time MPU programming, and the Thumb-1 first restore. It deliberately
 * owns no PendSV handler or forward runtime ABI operation yet: unprivileged
 * yield must arrive together with the protected save/switch/restore path.
 */

#include "fiber_port_private.h"
#include "../../fiber_panic.h"

#define fiber_portSTRINGIFY2(_value) #_value
#define fiber_portSTRINGIFY(_value) fiber_portSTRINGIFY2(_value)

#define FIBER_CM0_MPU_PRIVILEGED \
	FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY \
	fiber_portPRIVILEGED_FUNCTION

#define FIBER_CM0_MPU_UNPRIVILEGED \
	FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY \
	fiber_portUNPRIVILEGED_FUNCTION

FIBER_PORT_CONTEXT_COHORT_DEFINE();

static FIBER_CM0_MPU_PRIVILEGED
uintptr_t fiber_port_code_address(uintptr_t address)
{
	return address & ~(uintptr_t)1u;
}

static FIBER_CM0_MPU_PRIVILEGED
int fiber_port_range_contains(uintptr_t outer_start,
		uintptr_t outer_end,
		uintptr_t inner_start,
		uintptr_t inner_end)
{
	return (outer_end > outer_start) && (inner_end > inner_start) &&
			(inner_start >= outer_start) && (inner_end <= outer_end);
}

static FIBER_CM0_MPU_PRIVILEGED
uint32_t fiber_port_primask_save_disable(void)
{
	uint32_t primask;
	fiber_portASM volatile(
			"mrs %0, primask\n"
			"cpsid i"
			: "=r"(primask)
			:
			: "memory");
	__DSB();
	__ISB();
	return primask;
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_primask_restore(uint32_t primask)
{
	__DSB();
	__ISB();
	fiber_portASM volatile("msr primask, %0" :: "r"(primask) : "memory");
	__DSB();
	__ISB();
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_require_privileged_thread_msp(void)
{
	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
	FIBER_REQUIRE(__get_CONTROL() == 0u, 'l');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_validate_svc_vector(void)
{
#if FIBER_PORT_HAS_VTOR
	const uintptr_t first = (uintptr_t)fiber_portSCB_VTOR_REG;
	__DSB();
	__ISB();
	const uintptr_t second = (uintptr_t)fiber_portSCB_VTOR_REG;
	FIBER_REQUIRE(first == second, 'V');
	FIBER_REQUIRE((first & (fiber_portVECTOR_ALIGNMENT - 1u)) == 0u, 'V');
#endif

	const uintptr_t actual = (uintptr_t)fiber_port_read_vector_slot(
			fiber_portVECTOR_INDEX_SVC);
	const uintptr_t expected = (uintptr_t)&SVC_Handler;
	FIBER_REQUIRE((actual & 1u) != 0u, 'y');
	FIBER_REQUIRE(fiber_port_code_address(actual) ==
			fiber_port_code_address(expected), 'y');
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_configure_svc_priority(void)
{
	const uint32_t previous = fiber_port_primask_save_disable();
	FIBER_REQUIRE(previous == 0u, 'p');
	fiber_portNVIC_SHPR2_REG &= ~(fiber_portNVIC_PRIORITY_BYTE_MASK <<
			fiber_portNVIC_SVC_PRIORITY_SHIFT);
	__DSB();
	__ISB();
	FIBER_REQUIRE(((fiber_portNVIC_SHPR2_REG >>
			fiber_portNVIC_SVC_PRIORITY_SHIFT) &
			fiber_portNVIC_PRIORITY_BYTE_MASK) == 0u, 'w');
	fiber_port_primask_restore(previous);
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_validate_svc_cpu_state(void)
{
	FIBER_REQUIRE(__get_IPSR() == 11u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_validate_svc_frame_shape(const uint32_t *hardware_frame)
{
	FIBER_REQUIRE(hardware_frame != NULL, 'P');
	FIBER_REQUIRE((((uintptr_t)hardware_frame) & 7u) == 0u, 'A');
	const uint32_t stacked_pc = hardware_frame[6];
	const uint32_t stacked_xpsr = hardware_frame[7];
	FIBER_REQUIRE(stacked_pc >= 2u, 'x');
	FIBER_REQUIRE((stacked_pc & 1u) == 0u, 'x');
	FIBER_REQUIRE((stacked_xpsr & fiber_portXPSR_THUMB_BIT) != 0u, 'x');
	FIBER_REQUIRE((stacked_xpsr & fiber_portXPSR_IPSR_MASK) == 0u, 'x');
	FIBER_REQUIRE((stacked_xpsr & fiber_portXPSR_STACK_ALIGN_BIT) == 0u, 'a');
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_validate_start_svc_frame(const uint32_t *hardware_frame,
		const FiberPortMpuMemoryLayout *layout)
{
	FIBER_REQUIRE(hardware_frame != NULL, 'P');
	FIBER_REQUIRE(layout != NULL, 'L');
	const uintptr_t frame_start = (uintptr_t)hardware_frame;
	FIBER_REQUIRE(frame_start <= UINTPTR_MAX - FIBER_PORT_EXC_BASE_BYTES, 'O');
	FIBER_REQUIRE(fiber_port_range_contains(layout->privileged_data_start,
			layout->privileged_data_end, frame_start,
			frame_start + FIBER_PORT_EXC_BASE_BYTES), 'P');
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_validate_return_svc_frame(const FiberContext *current,
		const uint32_t *hardware_frame)
{
	FIBER_REQUIRE(current != NULL, 'C');
	FIBER_REQUIRE(hardware_frame != NULL, 'P');
	fiber_port_context_seal_check(current);
	const uintptr_t frame_start = (uintptr_t)hardware_frame;
	FIBER_REQUIRE(frame_start == (uintptr_t)__get_PSP(), 'P');
	FIBER_REQUIRE(frame_start <= UINTPTR_MAX - FIBER_PORT_EXC_BASE_BYTES, 'O');
	FIBER_REQUIRE(frame_start >= current->boot.stack_base, 'P');
	FIBER_REQUIRE((frame_start + FIBER_PORT_EXC_BASE_BYTES) <=
			current->boot.stack_top, 'P');
}

static FIBER_CM0_MPU_PRIVILEGED
uint32_t fiber_port_decode_svc_number(const uint32_t *hardware_frame,
		const FiberPortMpuMemoryLayout *layout)
{
	FIBER_REQUIRE(hardware_frame != NULL, 'P');
	FIBER_REQUIRE(layout != NULL, 'L');
	const uintptr_t pc = (uintptr_t)hardware_frame[6];
	FIBER_REQUIRE(pc >= 2u, 'u');
	const int in_privileged = fiber_port_range_contains(
			layout->privileged_code_start, layout->privileged_code_end,
			pc - 2u, pc);
	const int in_unprivileged = fiber_port_range_contains(
			layout->unprivileged_code_start, layout->unprivileged_code_end,
			pc - 2u, pc);
	FIBER_REQUIRE((in_privileged != 0) || (in_unprivileged != 0), 'u');

	const volatile uint8_t *const instruction =
			(const volatile uint8_t *)(pc - 2u);
	FIBER_REQUIRE(instruction[1] == 0xDFu, 'u');
	return instruction[0];
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_validate_exact_svc_site(uint32_t stacked_pc,
		const unsigned char *expected_site,
		char panic_code)
{
	FIBER_REQUIRE(expected_site != NULL, panic_code);
	FIBER_REQUIRE((uintptr_t)stacked_pc ==
			fiber_port_code_address((uintptr_t)expected_site), panic_code);
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_mpu_write_region(const FiberPortMpuRegionRegisters *region)
{
	FIBER_REQUIRE(region != NULL, 'M');
	fiber_portMPU_RBAR_REG = region->rbar;
	fiber_portMPU_RASR_REG = region->rasr;
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_mpu_validate_region_readback(uint32_t region_number,
		const FiberPortMpuRegionRegisters *expected)
{
	FIBER_REQUIRE(expected != NULL, 'M');
	FIBER_REQUIRE(region_number < fiber_portMPU_TOTAL_REGIONS, 'M');
	fiber_portMPU_RNR_REG = region_number;
	__DSB();
	__ISB();
	FIBER_REQUIRE(fiber_portMPU_RNR_REG == region_number, 'M');
	FIBER_REQUIRE((fiber_portMPU_RBAR_REG & fiber_portMPU_RBAR_ADDRESS_MASK) ==
			(expected->rbar & fiber_portMPU_RBAR_ADDRESS_MASK), 'M');
	FIBER_REQUIRE(fiber_portMPU_RASR_REG == expected->rasr, 'M');
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_mpu_validate_active_context(const FiberContext *ctx)
{
	FiberPortMpuGlobalRegionImage global;
	FIBER_REQUIRE(ctx != NULL, 'N');
	FIBER_REQUIRE(fiber_portMPU_TYPE_REG == fiber_portMPU_EXPECTED_TYPE, 'M');
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == fiber_portMPU_CTRL_REQUIRED, 'M');
	fiber_port_mpu_build_global_regions(&global);

	for (uint32_t index = 0u; index < fiber_portMPU_CONTEXT_REGION_COUNT;
			++index) {
		fiber_port_mpu_validate_region_readback(index, &ctx->mpu_regions[index]);
	}
	for (uint32_t index = 0u; index < fiber_portMPU_GLOBAL_REGION_COUNT;
			++index) {
		fiber_port_mpu_validate_region_readback(
				index + fiber_portMPU_CURRENT_CONTEXT_REGION,
				&global.regions[index]);
	}

	/* RBAR.VALID owns selection for writes. Make diagnostics deterministic. */
	fiber_portMPU_RNR_REG = 0u;
	__DSB();
	__ISB();
	FIBER_REQUIRE(fiber_portMPU_RNR_REG == 0u, 'M');
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_mpu_activate_first_context(FiberContext *first)
{
	FiberPortMpuGlobalRegionImage global;
	FIBER_REQUIRE(first != NULL, 'N');
	FIBER_REQUIRE(__get_IPSR() == 11u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() != 0u, 'p');
	FIBER_REQUIRE(fiber_portMPU_TYPE_REG == fiber_portMPU_EXPECTED_TYPE, 'M');
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');
	fiber_port_mpu_build_global_regions(&global);

	/* FreeRTOS disables the MPU while replacing task regions. Fiber keeps
	 * PRIMASK asserted and proves every register write/readback before any
	 * unprivileged exception return. */
	__DMB();
	fiber_portMPU_CTRL_REG = 0u;
	__DSB();
	__ISB();
	FIBER_REQUIRE((fiber_portMPU_CTRL_REG & fiber_portMPU_CTRL_ENABLE) == 0u,
			'M');

	for (uint32_t index = 0u; index < fiber_portMPU_CONTEXT_REGION_COUNT;
			++index) {
		fiber_port_mpu_write_region(&first->mpu_regions[index]);
	}
	for (uint32_t index = 0u; index < fiber_portMPU_GLOBAL_REGION_COUNT;
			++index) {
		fiber_port_mpu_write_region(&global.regions[index]);
	}

	fiber_portMPU_CTRL_REG = fiber_portMPU_CTRL_REQUIRED;
	__DSB();
	__ISB();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == fiber_portMPU_CTRL_REQUIRED, 'M');
	fiber_port_mpu_validate_active_context(first);
}

FIBER_CM0_MPU_PRIVILEGED
void fiber_port_prepare_first_start(FiberContext *first)
{
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
	FIBER_REQUIRE(first != NULL, 'N');
	fiber_port_require_privileged_thread_msp();
	FIBER_REQUIRE(fiber_portMPU_TYPE_REG == fiber_portMPU_EXPECTED_TYPE, 'M');
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');
	fiber_port_context_validate_initial_restore(first);
	fiber_port_validate_svc_vector();
	fiber_port_configure_svc_priority();
	fiber_port_validate_svc_vector();
	fiber_port_require_privileged_thread_msp();
}

FIBER_CM0_MPU_PRIVILEGED
void fiber_port_svc_dispatch(uint32_t *hardware_frame,
		uint32_t exc_return,
		FiberContext *current)
{
	FiberPortMpuMemoryLayout layout;
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
	fiber_port_validate_svc_cpu_state();
	FIBER_REQUIRE((exc_return == fiber_portEXC_RETURN_THREAD_MSP) ||
			(exc_return == fiber_portINITIAL_EXC_RETURN), 'l');
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);

	if (exc_return == fiber_portEXC_RETURN_THREAD_MSP) {
		FIBER_REQUIRE(__get_CONTROL() == 0u, 'l');
		fiber_port_validate_start_svc_frame(hardware_frame, &layout);
	} else {
		FIBER_REQUIRE(__get_CONTROL() ==
				fiber_portINITIAL_CONTROL_UNPRIVILEGED, 'l');
		fiber_port_validate_return_svc_frame(current, hardware_frame);
	}
	fiber_port_validate_svc_frame_shape(hardware_frame);

	const uint32_t service = fiber_port_decode_svc_number(hardware_frame,
			&layout);
	switch (service) {
	case fiber_portSVC_START: {
		FIBER_REQUIRE(exc_return == fiber_portEXC_RETURN_THREAD_MSP, 'l');
		fiber_port_validate_exact_svc_site(hardware_frame[6],
				fiber_port_svc_start_return_site, 'u');
		FIBER_REQUIRE(current != NULL, 'C');
		fiber_port_context_validate_initial_restore(current);
		const uint32_t previous = fiber_port_primask_save_disable();
		FIBER_REQUIRE(previous == 0u, 'p');
		fiber_port_mpu_activate_first_context(current);
		fiber_port_restore_first_context_from_svc(current);
		FIBER_API_UNREACHABLE();
	}

	case fiber_portSVC_RETURN:
		FIBER_REQUIRE(exc_return == fiber_portINITIAL_EXC_RETURN, 'l');
		fiber_port_validate_exact_svc_site(hardware_frame[6],
				fiber_port_svc_return_return_site, 'u');
		FIBER_REQUIRE(current != NULL, 'C');
		fiber_internal_task_return();
		FIBER_API_UNREACHABLE();

	/* Yield is deliberately reserved, not accepted, until the matching PendSV
	 * owner exists. A stray service therefore fails closed rather than reaching
	 * a startup-vector default handler. */
	case fiber_portSVC_YIELD:
	default:
		fiber_panic('u');
	}
}

FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM
fiber_portPRIVILEGED_FUNCTION
void fiber_port_start_first_context(FiberContext *first FIBER_ATTR_UNUSED_PARAM)
{
	__ASM volatile(
			".syntax unified                                      \n"
			"bl    fiber_port_prepare_first_start                 \n"
			"mrs   r3, ipsr                                       \n"
			"cmp   r3, #0                                         \n"
			"bne   90f                                            \n"
			"mrs   r3, control                                    \n"
			"cmp   r3, #0                                         \n"
			"bne   90f                                            \n"
			"mrs   r3, primask                                    \n"
			"cmp   r3, #0                                         \n"
			"bne   91f                                            \n"
			"cpsid i                                               \n"
			"dsb                                                   \n"
			"isb                                                   \n"
			"ldr   r3, =0xE000ED04                                \n"
			"ldr   r2, =0x08000000                                \n"
			"str   r2, [r3]                                       \n"
			"dsb                                                   \n"
			"isb                                                   \n"
			"cpsie i                                               \n"
			"dsb                                                   \n"
			"isb                                                   \n"
			"svc   #" fiber_portSTRINGIFY(fiber_portSVC_START) "  \n"
			".global fiber_port_svc_start_return_site             \n"
			"fiber_port_svc_start_return_site:                     \n"
			"movs  r0, #121                                       \n"
			"bl    fiber_panic                                    \n"
			"b     .                                               \n"
			"90:                                                   \n"
			"movs  r0, #108                                       \n"
			"bl    fiber_panic                                    \n"
			"b     90b                                             \n"
			"91:                                                   \n"
			"movs  r0, #112                                       \n"
			"bl    fiber_panic                                    \n"
			"b     91b                                             \n"
			".ltorg                                                \n"
			:
			:
			: "memory", "cc");
}

FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM
fiber_portPRIVILEGED_FUNCTION
void fiber_port_restore_first_context_from_svc(
		FiberContext *first FIBER_ATTR_UNUSED_PARAM)
{
	__ASM volatile(
			".syntax unified                                      \n"
			"cpsid i                                               \n"
			"dsb                                                   \n"
			"isb                                                   \n"
			"ldr   r1, [r0, #0]                                   \n"
			"subs  r1, #12                                        \n"
			"ldmia r1!, {r2-r4}                                   \n"
			"mov   r5, r4                                         \n"
			"subs  r1, #12                                        \n"
			"msr   psp, r2                                        \n"
			"isb                                                   \n"
			"mrs   r4, psp                                        \n"
			"cmp   r4, r2                                         \n"
			"bne   90f                                            \n"
			"msr   control, r3                                    \n"
			"isb                                                   \n"
			"mrs   r4, control                                    \n"
			"movs  r6, #3                                         \n"
			"cmp   r4, r6                                         \n"
			"bne   90f                                            \n"
			"mov   lr, r5                                         \n"
			"movs  r4, #2                                         \n"
			"mvns  r4, r4                                         \n"
			"cmp   lr, r4                                         \n"
			"bne   90f                                            \n"
			"subs  r1, #32                                        \n"
			"ldmia r1!, {r4-r7}                                   \n"
			"stmia r2!, {r4-r7}                                   \n"
			"ldmia r1!, {r4-r7}                                   \n"
			"stmia r2!, {r4-r7}                                   \n"
			"subs  r1, #48                                        \n"
			"ldmia r1!, {r4-r7}                                   \n"
			"mov   r8, r4                                         \n"
			"mov   r9, r5                                         \n"
			"mov   r10, r6                                        \n"
			"mov   r11, r7                                        \n"
			"subs  r1, #32                                        \n"
			"ldmia r1!, {r4-r7}                                   \n"
			"subs  r1, #16                                        \n"
			"str   r1, [r0, #0]                                   \n"
			"dsb                                                   \n"
			"isb                                                   \n"
			"cpsie i                                               \n"
			"dsb                                                   \n"
			"isb                                                   \n"
			"bx    lr                                              \n"
			"90:                                                   \n"
			"movs  r0, #80                                        \n"
			"bl    fiber_panic                                    \n"
			"b     90b                                             \n"
			".ltorg                                                \n"
			:
			:
			: "memory", "cc");
}

FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM
FIBER_CM0_MPU_UNPRIVILEGED
void fiber_port_unprivileged_task_return(void)
{
	__ASM volatile(
			".syntax unified                                      \n"
			"svc   #" fiber_portSTRINGIFY(fiber_portSVC_RETURN) " \n"
			".global fiber_port_svc_return_return_site            \n"
			"fiber_port_svc_return_return_site:                    \n"
			"1: b 1b                                               \n"
			:
			:
			: "memory", "cc");
}

FIBER_ATTR_NAKED_ASM fiber_portPRIVILEGED_FUNCTION
void SVC_Handler(void)
{
	__ASM volatile(
			".syntax unified                                      \n"
			"mrs   r2, ipsr                                       \n"
			"cmp   r2, #11                                        \n"
			"bne   90f                                            \n"
			"mov   r1, lr                                         \n"
			"movs  r3, #4                                         \n"
			"tst   r1, r3                                         \n"
			"beq   1f                                             \n"
			"mrs   r0, psp                                        \n"
			"b     2f                                             \n"
			"1:                                                    \n"
			"mrs   r0, msp                                        \n"
			"2:                                                    \n"
			"ldr   r2, =fiber_internal_runtime_current_context_slot \n"
			"ldr   r2, [r2]                                       \n"
			/* A narrow Thumb-1 B reaches only a short span. LTO may place the
			 * non-naked C dispatcher beyond that span, so preserve the exact
			 * r0/r1/r2 ABI and tail-branch through an explicit Thumb address. */
			"ldr   r3, =fiber_port_svc_dispatch + 1               \n"
			"bx    r3                                              \n"
			"90:                                                   \n"
			"movs  r0, #105                                       \n"
			"bl    fiber_panic                                    \n"
			"b     90b                                             \n"
			".ltorg                                                \n"
			:
			:
			: "memory", "cc");
}

#undef FIBER_CM0_MPU_UNPRIVILEGED
#undef FIBER_CM0_MPU_PRIVILEGED
#undef fiber_portSTRINGIFY
#undef fiber_portSTRINGIFY2

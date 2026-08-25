/*
 * Type-only public storage for the staged ARM_CM0_MPU profile.
 *
 * The layout preserves the 20-word protected restore image from the pinned
 * FreeRTOS GCC ARM_CM0 MPU branch. It is compile-only in this slice: there is
 * no selected runtime, handler, or public MPU feature API yet.
 */

#ifndef FIBER_PORT_ARM_CM0_MPU_FIBER_PORT_TYPES_H_
#define FIBER_PORT_ARM_CM0_MPU_FIBER_PORT_TYPES_H_

#include <stdint.h>

#include "../../fiber_api_types.h"
#include "fiber_port_boot_types.h"

#ifdef FIBER_PORT_NAME
# undef FIBER_PORT_NAME
#endif
#define FIBER_PORT_NAME "ARM_CM0_MPU"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct FiberPortMpuRegionRegisters {
	uint32_t rbar;
	uint32_t rasr;
} FiberPortMpuRegionRegisters;

/*
 * Exact FreeRTOS ARM_CM0 MPU ulContext[20] word order. The cursor limit is
 * the final one-past save/restore cursor target, not an architectural register.
 */
typedef struct FiberPortProtectedContext {
	uint32_t r4;
	uint32_t r5;
	uint32_t r6;
	uint32_t r7;
	uint32_t r8;
	uint32_t r9;
	uint32_t r10;
	uint32_t r11;
	uint32_t r0;
	uint32_t r1;
	uint32_t r2;
	uint32_t r3;
	uint32_t r12;
	uint32_t lr;
	uint32_t pc;
	uint32_t xpsr;
	uint32_t psp;
	uint32_t control;
	uint32_t exc_return;
	uint32_t cursor_limit;
} FiberPortProtectedContext;

#if !defined(__GNUC__) && !defined(__clang__)
# error "[fiber]: ARM_CM0_MPU type layout currently supports GCC-compatible compilers only"
#endif

/*
 * The first 120 bytes deliberately track a Fiber-adapted xMPU_SETTINGS:
 * cursor, four per-context RBAR/RASR pairs, 20-word protected image, and
 * mutable runtime flags. Region four is a read-only current-context aperture;
 * it replaces the reference port's broad peripheral region.
 */
struct __attribute__((aligned(8))) FiberContext {
	uint32_t *protected_context_cursor;
	FiberPortMpuRegionRegisters mpu_regions[4];
	FiberPortProtectedContext protected_context;
	uint32_t runtime_flags;
	FiberPortBoot boot;
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM0_MPU_FIBER_PORT_TYPES_H_ */

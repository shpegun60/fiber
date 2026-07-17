/*
 * fiber_port_types.h
 *
 * Type-only public storage layout for the future ARM_CM3_MPU profile.
 * Application code may allocate this type but must not inspect, copy, or
 * mutate an initialized context. MPU placement will enforce that contract for
 * unprivileged fibers when the runtime implementation is enabled.
 */

#ifndef FIBER_PORT_ARM_CM3_MPU_FIBER_PORT_TYPES_H_
#define FIBER_PORT_ARM_CM3_MPU_FIBER_PORT_TYPES_H_

#include <stdint.h>

#include "../../fiber_api_types.h"
#include "fiber_port_boot_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct FiberPortMpuRegionRegisters {
	uint32_t rbar;
	uint32_t rasr;
} FiberPortMpuRegionRegisters;

/*
 * Protected Cortex-M3 context image, equivalent to the 20-word FreeRTOS
 * ARM_CM3_MPU ulContext geometry. cursor_limit is the one-past restore cursor
 * target and is not an architectural register.
 */
typedef struct FiberPortProtectedContext {
	uint32_t control;
	uint32_t r4;
	uint32_t r5;
	uint32_t r6;
	uint32_t r7;
	uint32_t r8;
	uint32_t r9;
	uint32_t r10;
	uint32_t r11;
	uint32_t exc_return;
	uint32_t psp;
	uint32_t r0;
	uint32_t r1;
	uint32_t r2;
	uint32_t r3;
	uint32_t r12;
	uint32_t lr;
	uint32_t pc;
	uint32_t xpsr;
	uint32_t cursor_limit;
} FiberPortProtectedContext;

/* This first implementation is the GCC Cortex-M3 compiler port. */
#if !defined(__GNUC__) && !defined(__clang__)
# error "[fiber]: ARM_CM3_MPU type layout currently supports GCC-compatible compilers only"
#endif

struct __attribute__((aligned(8))) FiberContext {
	uint32_t *protected_context_cursor;
	FiberPortMpuRegionRegisters mpu_regions[4];
	FiberPortProtectedContext protected_context;
	FiberPortBoot boot;
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM3_MPU_FIBER_PORT_TYPES_H_ */

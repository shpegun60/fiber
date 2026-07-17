/*
 * Type-only public storage for the staged ARM_CM4_MPU profile.
 *
 * The layout follows the protected-context geometry of the pinned FreeRTOS
 * GCC ARM_CM4_MPU port. It is not runtime-selectable in implementation slice
 * 1. Application code may allocate a selected FiberContext but must not
 * inspect, copy, or mutate it after initialization.
 */

#ifndef FIBER_PORT_ARM_CM4_MPU_FIBER_PORT_TYPES_H_
#define FIBER_PORT_ARM_CM4_MPU_FIBER_PORT_TYPES_H_

#include <stdint.h>

#include "../../fiber_api_types.h"
#include "fiber_port_boot_types.h"

#ifndef FIBER_PORT_CM4_MPU_TOTAL_REGIONS
# error "[fiber]: ARM_CM4_MPU requires an explicit 8- or 16-region MPU manifest"
#endif

#if (FIBER_PORT_CM4_MPU_TOTAL_REGIONS != 8) && \
		(FIBER_PORT_CM4_MPU_TOTAL_REGIONS != 16)
# error "[fiber]: ARM_CM4_MPU supports exactly 8 or 16 MPU regions"
#endif

#define FIBER_PORT_CM4_MPU_CONTEXT_REGION_COUNT \
	(FIBER_PORT_CM4_MPU_TOTAL_REGIONS - 4)

#ifdef FIBER_PORT_NAME
# undef FIBER_PORT_NAME
#endif
#define FIBER_PORT_NAME "ARM_CM4_MPU"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct FiberPortMpuRegionRegisters {
	uint32_t rbar;
	uint32_t rasr;
} FiberPortMpuRegionRegisters;

/* CONTROL, r4-r11, and EXC_RETURN. */
typedef struct FiberPortProtectedCoreContext {
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
} FiberPortProtectedCoreContext;

/* PSP followed by the copied basic hardware exception frame. */
typedef struct FiberPortProtectedHardwareFrame {
	uint32_t psp;
	uint32_t r0;
	uint32_t r1;
	uint32_t r2;
	uint32_t r3;
	uint32_t r12;
	uint32_t lr;
	uint32_t pc;
	uint32_t xpsr;
} FiberPortProtectedHardwareFrame;

/* Initial/basic view: 19 active words, one cursor target, 33 reserved words. */
typedef struct FiberPortProtectedBasicContext {
	FiberPortProtectedCoreContext core;
	FiberPortProtectedHardwareFrame hardware;
	uint32_t cursor_limit;
	uint32_t reserved[33];
} FiberPortProtectedBasicContext;

/* Maximum FP view: 16 + 17 + 10 + 9 active words and one cursor target. */
typedef struct FiberPortProtectedExtendedContext {
	uint32_t high_fp_s16_s31[16];
	uint32_t low_fp_s0_s15_fpscr[17];
	FiberPortProtectedCoreContext core;
	FiberPortProtectedHardwareFrame hardware;
	uint32_t cursor_limit;
} FiberPortProtectedExtendedContext;

typedef union FiberPortProtectedContext {
	uint32_t words[53];
	FiberPortProtectedBasicContext basic;
	FiberPortProtectedExtendedContext extended;
} FiberPortProtectedContext;

#if !defined(__GNUC__) && !defined(__clang__)
# error "[fiber]: ARM_CM4_MPU type layout currently supports GCC-compatible compilers only"
#endif

struct __attribute__((aligned(8))) FiberContext {
	uint32_t *protected_context_cursor;
	FiberPortMpuRegionRegisters
		mpu_regions[FIBER_PORT_CM4_MPU_CONTEXT_REGION_COUNT];
	FiberPortProtectedContext protected_context;
	uint32_t runtime_flags;
	FiberPortBoot boot;
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM4_MPU_FIBER_PORT_TYPES_H_ */

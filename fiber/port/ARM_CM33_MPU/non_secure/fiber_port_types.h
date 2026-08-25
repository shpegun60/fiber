/*
 * Public storage for the build-selected ARM_CM33_MPU/non_secure profile.
 *
 * This first no-FPU/no-SecureContext cohort preserves the protected ARMv8-M
 * Mainline context geometry from FreeRTOS. Applications may allocate the type
 * but must not inspect, copy, or mutate it after initialization.
 */
#ifndef FIBER_PORT_ARM_CM33_MPU_NON_SECURE_FIBER_PORT_TYPES_H_
#define FIBER_PORT_ARM_CM33_MPU_NON_SECURE_FIBER_PORT_TYPES_H_

#include <stdint.h>

#include "../../../fiber_api_types.h"
#include "fiber_port_boot_types.h"

#ifndef FIBER_PORT_CM33_MPU_TOTAL_REGIONS
# error "[fiber]: ARM_CM33_MPU requires an explicit 8- or 16-region MPU manifest"
#endif

#if (FIBER_PORT_CM33_MPU_TOTAL_REGIONS != 8) && \
		(FIBER_PORT_CM33_MPU_TOTAL_REGIONS != 16)
# error "[fiber]: ARM_CM33_MPU supports exactly 8 or 16 MPU regions"
#endif

#define FIBER_PORT_CM33_MPU_CONTEXT_REGION_COUNT \
	(FIBER_PORT_CM33_MPU_TOTAL_REGIONS - 4)

#ifdef FIBER_PORT_NAME
# undef FIBER_PORT_NAME
#endif
#define FIBER_PORT_NAME "ARM_CM33_MPU"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct FiberPortMpuRegionRegisters {
	uint32_t rbar;
	uint32_t rlar;
} FiberPortMpuRegionRegisters;

/*
 * Exact FreeRTOS ARM_CM33_NTZ no-FPU/no-TrustZone/no-PAC
 * ulContext[MAX_CONTEXT_SIZE == 21] word order. Twenty words are active;
 * cursor_limit is the one-past save/restore cursor target and is not an
 * architectural register. SecureContext is absent from this cohort.
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
	uint32_t psplim;
	uint32_t control;
	uint32_t exc_return;
	uint32_t cursor_limit;
} FiberPortProtectedContext;

#if !defined(__GNUC__) && !defined(__clang__)
# error "[fiber]: ARM_CM33_MPU type layout currently supports GCC-compatible compilers only"
#endif

struct __attribute__((aligned(8))) FiberContext {
	uint32_t *protected_context_cursor;
	uint32_t mair0;
	FiberPortMpuRegionRegisters
		mpu_regions[FIBER_PORT_CM33_MPU_CONTEXT_REGION_COUNT];
	FiberPortProtectedContext protected_context;
	uint32_t runtime_flags;
	FiberPortBoot boot;
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM33_MPU_NON_SECURE_FIBER_PORT_TYPES_H_ */

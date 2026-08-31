/*
 * Public storage for the build-selected ARM_CM55_MVEF_MPU/non_secure profile.
 *
 * The protected image mirrors FreeRTOS ARM_CM55_NTZ with MPU plus MVE-FP.
 * Its basic and extended forms intentionally overlap in one 54-word array:
 * a basic first-start image occupies words 0..19 and its cursor is word 20;
 * an extended saved image occupies words 0..52 and its cursor is word 53.
 * Application code allocates this type but never inspects or mutates it.
 */
#ifndef FIBER_PORT_ARM_CM55_MVEF_MPU_NON_SECURE_FIBER_PORT_TYPES_H_
#define FIBER_PORT_ARM_CM55_MVEF_MPU_NON_SECURE_FIBER_PORT_TYPES_H_

#include <stdint.h>

#include "../../../fiber_api_types.h"
#include "fiber_port_boot_types.h"

#ifndef FIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS
# error "[fiber]: ARM_CM55_MVEF_MPU requires an explicit 8- or 16-region MPU manifest"
#endif

#if (FIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS != 8) && \
		(FIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS != 16)
# error "[fiber]: ARM_CM55_MVEF_MPU supports exactly 8 or 16 MPU regions"
#endif

#define FIBER_PORT_CM55_MVEF_MPU_CONTEXT_REGION_COUNT \
	(FIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS - 4)

#ifdef FIBER_PORT_NAME
# undef FIBER_PORT_NAME
#endif
#define FIBER_PORT_NAME "ARM_CM55_MVEF_MPU"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct FiberPortMpuRegionRegisters {
	uint32_t rbar;
	uint32_t rlar;
} FiberPortMpuRegionRegisters;

/* This is the FreeRTOS basic ulContext view. It is valid only before the
 * first extended FP save. cursor_limit is a one-past save cursor target. */
typedef struct FiberPortProtectedBasicContext {
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
	uint32_t reserved[33];
} FiberPortProtectedBasicContext;

/* This is the exact maximum FreeRTOS ulContext[MAX_CONTEXT_SIZE == 54]
 * view. Low FP state stores s0-s15 plus FPSCR; the reserved hardware-frame
 * word remains on the user PSP and is not copied into privileged storage.
 * The pinned MVE-FP MPU branch owns no separate VPR software word. */
typedef struct FiberPortProtectedExtendedContext {
	uint32_t high_fp_s16_s31[16];
	uint32_t low_fp_s0_s15_fpscr[17];
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
} FiberPortProtectedExtendedContext;

typedef union FiberPortProtectedContext {
	uint32_t words[54];
	FiberPortProtectedBasicContext basic;
	FiberPortProtectedExtendedContext extended;
} FiberPortProtectedContext;

#if !defined(__GNUC__) && !defined(__clang__)
# error "[fiber]: ARM_CM55_MVEF_MPU type layout currently supports GCC-compatible compilers only"
#endif

struct __attribute__((aligned(8))) FiberContext {
	uint32_t *protected_context_cursor;
	uint32_t mair0;
	FiberPortMpuRegionRegisters
		mpu_regions[FIBER_PORT_CM55_MVEF_MPU_CONTEXT_REGION_COUNT];
	FiberPortProtectedContext protected_context;
	uint32_t runtime_flags;
	FiberPortBoot boot;
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM55_MVEF_MPU_NON_SECURE_FIBER_PORT_TYPES_H_ */

/* Frozen revision-1 CM33_MPU public storage for stale-consumer tests. Its
 * 216/280-byte allocations matched revision 2 when this test was introduced.
 * Boot metadata is copied from 5c34785, never imported from the live port.
 * The assertions below pin historical ARM geometry when live layouts evolve. */
#ifndef FIBER_CONSUMER_COHORT_V1_TYPES_H_
#define FIBER_CONSUMER_COHORT_V1_TYPES_H_

#include <stddef.h>
#include <stdint.h>
#include "fiber_api_types.h"

#ifndef FIBER_PORT_CM33_MPU_TOTAL_REGIONS
# error "[fiber]: stale fixture requires an explicit 8- or 16-region manifest"
#elif (FIBER_PORT_CM33_MPU_TOTAL_REGIONS != 8) && \
		(FIBER_PORT_CM33_MPU_TOTAL_REGIONS != 16)
# error "[fiber]: stale fixture supports exactly 8 or 16 MPU regions"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct FiberPortBoot {
	void *begin;
	void *end;
	uintptr_t stack_base;
	uintptr_t stack_top;
	size_t avail;
	entry_t entry;
	void *arg;
	uint32_t abi_port_id;
	uint32_t abi_layout_version;
	uint32_t abi_context_size;
	uint32_t abi_context_alignment;
	uint32_t abi_feature_mask;
	uint32_t abi_initial_exc_return;
	uint32_t abi_initial_control;
	uint32_t abi_mpu_total_regions;
	uint32_t abi_mpu_context_regions;
	uint32_t abi_protected_context_words;
	uint32_t magic;
	uint16_t version;
	uint16_t sealed;
	uint32_t guard_lo;
	uint32_t guard_hi;
	uint32_t hash;
} FiberPortBoot;

typedef struct FiberPortMpuRegionRegisters {
	uint32_t rbar;
	uint32_t rlar;
} FiberPortMpuRegionRegisters;

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

struct __attribute__((aligned(8))) FiberContext {
	uint32_t *protected_context_cursor;
	uint32_t mair0;
	FiberPortMpuRegionRegisters
		mpu_regions[FIBER_PORT_CM33_MPU_TOTAL_REGIONS - 4];
	FiberPortProtectedContext protected_context;
	uint32_t runtime_flags;
	FiberPortBoot boot;
};

#ifdef __cplusplus
}
# define FIBER_CONSUMER_V1_ASSERT static_assert
#else
# define FIBER_CONSUMER_V1_ASSERT _Static_assert
#endif

FIBER_CONSUMER_V1_ASSERT(sizeof(void *) == 4u,
		"historical storage fixture requires the 32-bit ARM ABI");
FIBER_CONSUMER_V1_ASSERT(sizeof(FiberPortBoot) == 88u &&
		offsetof(FiberPortBoot, hash) == 84u,
		"historical boot metadata geometry changed");
FIBER_CONSUMER_V1_ASSERT(sizeof(FiberPortProtectedContext) == 84u,
		"historical protected image geometry changed");
FIBER_CONSUMER_V1_ASSERT(offsetof(FiberContext, boot) ==
		((FIBER_PORT_CM33_MPU_TOTAL_REGIONS == 8) ? 128u : 192u),
		"historical boot metadata offset changed");
FIBER_CONSUMER_V1_ASSERT(sizeof(FiberContext) ==
		((FIBER_PORT_CM33_MPU_TOTAL_REGIONS == 8) ? 216u : 280u) &&
		__alignof__(FiberContext) == 8u,
		"historical caller allocation geometry changed");
#undef FIBER_CONSUMER_V1_ASSERT

#define FIBER_PORT_STORAGE_COHORT_PORT arm_cm33_mpu
#define FIBER_PORT_STORAGE_COHORT_REVISION 1
#if defined(FIBER_PORT_CM33_MPU_TOTAL_REGIONS) && \
		(FIBER_PORT_CM33_MPU_TOTAL_REGIONS == 8)
# define FIBER_PORT_STORAGE_COHORT_REGIONS 8
#else
# define FIBER_PORT_STORAGE_COHORT_REGIONS 16
#endif
#include "fiber_port_storage_cohort.h"
#endif

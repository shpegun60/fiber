/*
 * fiber_port_selected.h
 *
 * Selected Cortex-M port facade.
 *
 * fiber_port_select.h normally decides which port profile is active. This
 * header then includes exactly one concrete port interface and applies common
 * trait checks for the selected port.
 *
 * In FIBER_PORT_BUILD_SELECTED mode, the build system provides the selected
 * port include path and this facade includes fiber_portmacro.h, matching the
 * FreeRTOS portmacro.h pattern. Common runtime code should include this facade
 * instead of including concrete architecture headers directly.
 */

#ifndef FIBER_FIBER_PORT_SELECTED_H_
#define FIBER_FIBER_PORT_SELECTED_H_

#include "fiber_settings.h"
#include "fiber_compiler.h"
#include "fiber_port_select.h"
#include "../fiber_types.h"

#if FIBER_PORT_BUILD_SELECTED
# include "fiber_portmacro.h"
#elif FIBER_PORT_ARMV6M
# include "armv6m/fiber_portmacro.h"
#elif FIBER_PORT_ARMV7M
# include "armv7m/fiber_portmacro.h"
#elif FIBER_PORT_ARMV7EM
# if !defined(__CORTEX_M)
#  error "[fiber]: ARMv7E-M selection requires CMSIS __CORTEX_M"
# elif (__CORTEX_M == 7)
#  ifndef FIBER_CORTEX_M7_R0P1_ERRATA_837070
#   define FIBER_CORTEX_M7_R0P1_ERRATA_837070 1
#  endif
#  include "ARM_CM7/r0p1/fiber_portmacro.h"
# elif (__CORTEX_M == 4)
#  include "armv7em/fiber_portmacro.h"
# else
#  error "[fiber]: selected ARMv7E-M core has no concrete fiber port"
# endif
#else
# include "transitional_v8m/fiber_portmacro.h"
#endif

#include "fiber_port_traits.h"
#include "fiber_feature_policy.h"

/* -------------------------------------------------------------------------- */
/* Common post-port sanity                                                     */
/* -------------------------------------------------------------------------- */
#ifndef FIBER_STACK_ALIGN
# error "[fiber]: FIBER_STACK_ALIGN is not defined. Provide it in fiber_settings.h or selected fiber_portmacro.h."
#endif

FIBER_STATIC_ASSERT((FIBER_PENDSV_VECTOR_DIRECT == 0) ||
		(FIBER_PENDSV_VECTOR_DIRECT == 1),
		"[fiber]: FIBER_PENDSV_VECTOR_DIRECT must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_SVC_VECTOR_DIRECT == 0) ||
		(FIBER_SVC_VECTOR_DIRECT == 1),
		"[fiber]: FIBER_SVC_VECTOR_DIRECT must be 0 or 1");

FIBER_STATIC_ASSERT((FIBER_STACK_ALIGN & (FIBER_STACK_ALIGN - 1u)) == 0u,
		"[fiber]: FIBER_STACK_ALIGN must be power of two.");
FIBER_STATIC_ASSERT(FIBER_STACK_ALIGN >= 8u,
		"[fiber]: FIBER_STACK_ALIGN must be at least 8.");
FIBER_STATIC_ASSERT((FIBER_STACK_ALIGN % 8u) == 0u,
		"[fiber]: stack alignment must be a multiple of 8");
FIBER_STATIC_ASSERT((FIBER_STACK_REDZONE_BYTES % 8u) == 0u,
		"[fiber]: FIBER_STACK_REDZONE_BYTES must be a multiple of 8");

FIBER_STATIC_ASSERT(FIBER_EXC_LEVELS_ON_PSP >= 1u,
		"[fiber]: FIBER_EXC_LEVELS_ON_PSP must be >= 1");
FIBER_STATIC_ASSERT((FIBER_BOOT_EXTRA_BYTES % 4u) == 0u,
		"[fiber]: FIBER_BOOT_EXTRA_BYTES must be 4-byte aligned");

FIBER_STATIC_ASSERT(sizeof(void*) == 4,
		"[fiber]: 32-bit pointers expected");
FIBER_STATIC_ASSERT(sizeof(uintptr_t) == 4,
		"[fiber]: Cortex-M expects 32-bit uintptr_t");
FIBER_STATIC_ASSERT(sizeof(size_t) >= 4,
		"[fiber]: size_t must be at least 32-bit.");

FIBER_STATIC_ASSERT((FIBER_INITIAL_EXC_RETURN & 0x0Cu) == 0x0Cu,
		"[fiber]: initial EXC_RETURN must use Thread mode with PSP");
FIBER_STATIC_ASSERT((FIBER_INITIAL_EXC_RETURN & 0x10u) != 0u,
		"[fiber]: initial EXC_RETURN must use a basic frame");

/* -------------------------------------------------------------------------- */
/* Common stack and hardware exception-frame layout                            */
/* -------------------------------------------------------------------------- */
enum {
	FIBER_EXC_BASE_BYTES = FIBER_PORT_EXC_BASE_BYTES,
	FIBER_EXC_FP_EXT_BYTES = FIBER_PORT_EXC_FP_EXT_BYTES,
	FIBER_EXC_PER_LEVEL = FIBER_PORT_EXC_PER_LEVEL_BYTES,
	FIBER_STACK_WITHOUT_REDZONE =
			FIBER_EXC_PER_LEVEL * FIBER_EXC_LEVELS_ON_PSP +
			FIBER_BOOT_EXTRA_BYTES,
	FIBER_STACK_MIN_BOOT =
			FIBER_STACK_REDZONE_BYTES + FIBER_STACK_WITHOUT_REDZONE
};

static const uintptr_t FIBER_STACK_MASK = (uintptr_t)FIBER_STACK_ALIGN - 1u;
static const uintptr_t FIBER_WORD_MASK = (uintptr_t)sizeof(uintptr_t) - 1u;

__STATIC_FORCEINLINE uintptr_t fiber_stack_align_down(const uintptr_t x)
{
	return x & ~FIBER_STACK_MASK;
}

__STATIC_FORCEINLINE uintptr_t fiber_stack_align_up(const uintptr_t x)
{
	FIBER_REQUIRE(x <= (UINTPTR_MAX - FIBER_STACK_MASK), 'O');
	return (x + FIBER_STACK_MASK) & ~FIBER_STACK_MASK;
}

__STATIC_FORCEINLINE uintptr_t fiber_word_align_down(const uintptr_t x)
{
	return x & ~FIBER_WORD_MASK;
}

__STATIC_FORCEINLINE uintptr_t fiber_word_align_up(const uintptr_t x)
{
	FIBER_REQUIRE(x <= (UINTPTR_MAX - FIBER_WORD_MASK), 'O');
	return (x + FIBER_WORD_MASK) & ~FIBER_WORD_MASK;
}

FIBER_STATIC_ASSERT(FIBER_STACK_WITHOUT_REDZONE >= FIBER_EXC_PER_LEVEL,
		"[fiber]: >= one exc level");

#endif /* FIBER_FIBER_PORT_SELECTED_H_ */

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
FIBER_STATIC_ASSERT((FIBER_PENDSV_VECTOR_DIRECT == 0) ||
		(FIBER_PENDSV_VECTOR_DIRECT == 1),
		"[fiber]: FIBER_PENDSV_VECTOR_DIRECT must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_SVC_VECTOR_DIRECT == 0) ||
		(FIBER_SVC_VECTOR_DIRECT == 1),
		"[fiber]: FIBER_SVC_VECTOR_DIRECT must be 0 or 1");

FIBER_STATIC_ASSERT((FIBER_PORT_STACK_ALIGNMENT &
		(FIBER_PORT_STACK_ALIGNMENT - 1u)) == 0u,
		"[fiber]: selected-port stack alignment must be a power of two");
FIBER_STATIC_ASSERT(FIBER_PORT_STACK_ALIGNMENT >= 8u,
		"[fiber]: selected-port stack alignment must be at least 8");
FIBER_STATIC_ASSERT((FIBER_PORT_STACK_ALIGNMENT % 8u) == 0u,
		"[fiber]: stack alignment must be a multiple of 8");
FIBER_STATIC_ASSERT((FIBER_STACK_REDZONE_BYTES %
		FIBER_PORT_STACK_ALIGNMENT) == 0u,
		"[fiber]: FIBER_STACK_REDZONE_BYTES must be a multiple of selected-port stack alignment");
FIBER_STATIC_ASSERT((FIBER_STACK_CANARY == 0) ||
		(FIBER_STACK_REDZONE_BYTES >= 8u),
		"[fiber]: enabled stack canary requires at least 8 bytes of red zone");

FIBER_STATIC_ASSERT(sizeof(void*) == 4,
		"[fiber]: 32-bit pointers expected");
FIBER_STATIC_ASSERT(sizeof(uintptr_t) == 4,
		"[fiber]: Cortex-M expects 32-bit uintptr_t");
FIBER_STATIC_ASSERT(sizeof(size_t) >= 4,
		"[fiber]: size_t must be at least 32-bit.");

FIBER_STATIC_ASSERT((FIBER_PORT_INITIAL_EXC_RETURN & 0x0Cu) == 0x0Cu,
		"[fiber]: initial EXC_RETURN must use Thread mode with PSP");
FIBER_STATIC_ASSERT((FIBER_PORT_INITIAL_EXC_RETURN & 0x10u) != 0u,
		"[fiber]: initial EXC_RETURN must use a basic frame");

/* -------------------------------------------------------------------------- */
/* Common stack and hardware exception-frame layout                            */
/* -------------------------------------------------------------------------- */
enum {
	FIBER_EXC_BASE_BYTES = FIBER_PORT_EXC_BASE_BYTES,
	FIBER_EXC_FP_EXT_BYTES = FIBER_PORT_EXC_FP_EXT_BYTES,
	FIBER_EXC_PER_LEVEL = FIBER_PORT_EXC_PER_LEVEL_BYTES,
	FIBER_HIGH_FP_SOFTWARE_BYTES =
			FIBER_PORT_HIGH_FP_SOFTWARE_BYTES,
	FIBER_EXCEPTION_ALIGNMENT_PAD_BYTES =
			FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES,
	FIBER_STACK_WITHOUT_REDZONE =
			(FIBER_PORT_MAX_SAVED_CONTEXT_BYTES +
			 FIBER_PORT_STACK_ALIGNMENT - 1u) &
			~(FIBER_PORT_STACK_ALIGNMENT - 1u),
	FIBER_STACK_MIN_BOOT =
			FIBER_STACK_REDZONE_BYTES + FIBER_STACK_WITHOUT_REDZONE
};

FIBER_STATIC_ASSERT(FIBER_STACK_WITHOUT_REDZONE >=
		FIBER_PORT_MAX_SAVED_CONTEXT_BYTES,
		"[fiber]: aligned stack minimum must cover the maximum saved context");
FIBER_STATIC_ASSERT((FIBER_STACK_WITHOUT_REDZONE %
		FIBER_PORT_STACK_ALIGNMENT) == 0u,
		"[fiber]: usable stack minimum must satisfy selected-port alignment");
FIBER_STATIC_ASSERT((((8u - (FIBER_PORT_INITIAL_CONTEXT_BYTES & 7u)) & 7u)) ==
		FIBER_PORT_SAVED_SP_MOD8,
		"[fiber]: initial frame layout disagrees with saved-SP alignment trait");

static const uintptr_t FIBER_STACK_MASK =
		(uintptr_t)FIBER_PORT_STACK_ALIGNMENT - 1u;
static const uintptr_t FIBER_WORD_MASK = (uintptr_t)sizeof(uintptr_t) - 1u;

#ifdef FIBER_INTERNAL_STACK_CANARY_VALUE
# error "[fiber]: FIBER_INTERNAL_STACK_CANARY_VALUE is runtime-owned"
#endif
#define FIBER_INTERNAL_STACK_CANARY_VALUE UINT32_C(0xDEADBEEF)

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
		"[fiber]: saved-context area must cover one hardware exception frame");

#endif /* FIBER_FIBER_PORT_SELECTED_H_ */

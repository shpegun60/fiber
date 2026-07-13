/*
 * fiber_port_geometry.h
 *
 * Trait-derived geometry used only by selected port code and explicit
 * port-aware integration code. The public core API never includes this file.
 */

#ifndef FIBER_PORT_FIBER_PORT_GEOMETRY_H_
#define FIBER_PORT_FIBER_PORT_GEOMETRY_H_

#include <stddef.h>
#include <stdint.h>

#include "fiber_compiler.h"
#include "../fiber_panic.h"

#ifndef FIBER_PORT_NAME
# error "[fiber]: selected port traits must precede fiber_port_geometry.h"
#endif

FIBER_STATIC_ASSERT((FIBER_PORT_STACK_ALIGNMENT &
		(FIBER_PORT_STACK_ALIGNMENT - 1u)) == 0u,
		"[fiber]: selected-port stack alignment must be a power of two");
FIBER_STATIC_ASSERT(FIBER_PORT_STACK_ALIGNMENT >= 8u,
		"[fiber]: selected-port stack alignment must be at least 8");
FIBER_STATIC_ASSERT((FIBER_PORT_STACK_ALIGNMENT % 8u) == 0u,
		"[fiber]: selected-port stack alignment must be a multiple of 8");
FIBER_STATIC_ASSERT((FIBER_STACK_REDZONE_BYTES %
		FIBER_PORT_STACK_ALIGNMENT) == 0u,
		"[fiber]: FIBER_STACK_REDZONE_BYTES must be a multiple of selected-port stack alignment");
FIBER_STATIC_ASSERT((FIBER_STACK_CANARY == 0) ||
		(FIBER_STACK_REDZONE_BYTES >= 8u),
		"[fiber]: enabled stack canary requires at least 8 bytes of red zone");
FIBER_STATIC_ASSERT(sizeof(void *) == 4u,
		"[fiber]: 32-bit pointers expected");
FIBER_STATIC_ASSERT(sizeof(uintptr_t) == 4u,
		"[fiber]: Cortex-M expects 32-bit uintptr_t");
FIBER_STATIC_ASSERT(sizeof(size_t) >= 4u,
		"[fiber]: size_t must be at least 32-bit");
FIBER_STATIC_ASSERT((FIBER_PORT_INITIAL_EXC_RETURN & 0x0Cu) == 0x0Cu,
		"[fiber]: initial EXC_RETURN must use Thread mode with PSP");
FIBER_STATIC_ASSERT((FIBER_PORT_INITIAL_EXC_RETURN & 0x10u) != 0u,
		"[fiber]: initial EXC_RETURN must use a basic frame");

enum {
	FIBER_EXC_BASE_BYTES = FIBER_PORT_EXC_BASE_BYTES,
	FIBER_EXC_FP_EXT_BYTES = FIBER_PORT_EXC_FP_EXT_BYTES,
	FIBER_EXC_PER_LEVEL = FIBER_PORT_EXC_PER_LEVEL_BYTES,
	FIBER_HIGH_FP_SOFTWARE_BYTES = FIBER_PORT_HIGH_FP_SOFTWARE_BYTES,
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
FIBER_STATIC_ASSERT(FIBER_STACK_WITHOUT_REDZONE >= FIBER_EXC_PER_LEVEL,
		"[fiber]: saved-context area must cover one hardware exception frame");

#ifdef FIBER_INTERNAL_STACK_CANARY_VALUE
# error "[fiber]: FIBER_INTERNAL_STACK_CANARY_VALUE is runtime-owned"
#endif
#define FIBER_INTERNAL_STACK_CANARY_VALUE UINT32_C(0xDEADBEEF)

static const uintptr_t FIBER_STACK_MASK =
		(uintptr_t)FIBER_PORT_STACK_ALIGNMENT - 1u;
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

#endif /* FIBER_PORT_FIBER_PORT_GEOMETRY_H_ */

/*
 * fiber_port_selected.h
 *
 * Selected Cortex-M port facade.
 *
 * fiber_port_select.h decides which port profile is active. This header then
 * includes exactly one concrete port interface and applies common trait checks
 * for the selected port. Common runtime code should include this facade instead
 * of including concrete architecture headers directly.
 */

#ifndef FIBER_PORT_FIBER_PORT_SELECTED_H_
#define FIBER_PORT_FIBER_PORT_SELECTED_H_

#include "../target/fiber_target.h"
#include "fiber_port_types.h"

#if FIBER_PORT_ARMV6M
# include "armv6m/fiber_port_armv6m.h"
#elif FIBER_PORT_ARMV7EM
# include "armv7em/fiber_port_armv7em.h"
#else
/*
 * Transitional selected-port interface for profiles whose concrete source split
 * is not finished. ARMv7-M and v8-M profiles must replace this fallback with a
 * real port-owned header before any runtime support claim is made.
 */
#ifdef __cplusplus
extern "C" {
#endif

enum {
	FIBER_PORT_SOFTWARE_FRAME_WORDS = 9u,
	FIBER_PORT_SOFTWARE_FRAME_BYTES = FIBER_PORT_SOFTWARE_FRAME_WORDS * 4u,
	FIBER_PORT_EXC_RETURN_WORD_INDEX = FIBER_PORT_IS_BASELINE ? 0u : 8u
};

void fiber_port_init_context_frame(FiberContext *ctx);

FIBER_ATTR_NAKED_ASM
void fiber_pendsv(void);

#if FIBER_START_USE_SVC
FIBER_NORETURN
void fiber_port_start_first_context(uintptr_t msp_top);

FIBER_ATTR_NAKED_ASM
void fiber_svc(void);
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif

enum {
	FIBER_PORT_SAVED_SP_MOD8 =
		(8u - (FIBER_PORT_SOFTWARE_FRAME_BYTES & 7u)) & 7u
};

BT_STATIC_ASSERT((FIBER_PORT_SOFTWARE_FRAME_BYTES % 4u) == 0u,
		"[fiber]: port software frame size must be word aligned");
BT_STATIC_ASSERT(FIBER_PORT_SOFTWARE_FRAME_WORDS > 0u,
		"[fiber]: port software frame must contain at least one word");
BT_STATIC_ASSERT(FIBER_PORT_SOFTWARE_FRAME_BYTES == (FIBER_PORT_SOFTWARE_FRAME_WORDS * 4u),
		"[fiber]: port software frame bytes/words mismatch");
BT_STATIC_ASSERT(FIBER_PORT_EXC_RETURN_WORD_INDEX < FIBER_PORT_SOFTWARE_FRAME_WORDS,
		"[fiber]: port EXC_RETURN index must point inside the software frame");
BT_STATIC_ASSERT(FIBER_PORT_SAVED_SP_MOD8 < 8u,
		"[fiber]: saved SP modulo must be a byte offset inside 8-byte alignment");

#endif /* FIBER_PORT_FIBER_PORT_SELECTED_H_ */

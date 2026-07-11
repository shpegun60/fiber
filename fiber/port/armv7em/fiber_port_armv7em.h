/*
 * fiber_port_armv7em.h
 *
 * ARMv7E-M selected port interface.
 */

#ifndef FIBER_PORT_ARMV7EM_FIBER_PORT_ARMV7EM_H_
#define FIBER_PORT_ARMV7EM_FIBER_PORT_ARMV7EM_H_

#include "../../target/fiber_target.h"
#include "../fiber_port_types.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
	FIBER_PORT_SOFTWARE_FRAME_WORDS = 9u,
	FIBER_PORT_SOFTWARE_FRAME_BYTES = FIBER_PORT_SOFTWARE_FRAME_WORDS * 4u,
	FIBER_PORT_EXC_RETURN_WORD_INDEX = 8u
};

void fiber_port_init_context_frame(FiberContext *ctx);

#if FIBER_START_USE_SVC
FIBER_NORETURN
void fiber_port_start_first_context(uintptr_t msp_top);

FIBER_ATTR_NAKED_ASM
void fiber_svc(void);
#endif

FIBER_ATTR_NAKED_ASM
void fiber_pendsv(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARMV7EM_FIBER_PORT_ARMV7EM_H_ */

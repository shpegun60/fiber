/*
 * fiber_port_transitional_v8m.h
 *
 * Transitional selected-port interface for v8-M profiles that do not yet have
 * concrete FreeRTOS-style port sources.
 */

#ifndef FIBER_PORT_TRANSITIONAL_V8M_FIBER_PORT_TRANSITIONAL_V8M_H_
#define FIBER_PORT_TRANSITIONAL_V8M_FIBER_PORT_TRANSITIONAL_V8M_H_

#include "../../target/fiber_target.h"
#include "../fiber_port_types.h"

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

#endif /* FIBER_PORT_TRANSITIONAL_V8M_FIBER_PORT_TRANSITIONAL_V8M_H_ */

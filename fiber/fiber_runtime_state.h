/*
 * fiber_runtime_state.h
 *
 * Common-private scheduler/runtime state. Selected ports must include only
 * fiber_runtime_port_abi.h and may not include this header.
 */

#ifndef FIBER_FIBER_RUNTIME_STATE_H_
#define FIBER_FIBER_RUNTIME_STATE_H_

#include "fiber_api_attributes.h"
#include "fiber_api_types.h"
#include "port/fiber_port_runtime_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The slot declaration is intentionally common-private. Selected-port C has
 * no lvalue declaration and assembly may only load the frozen symbol name.
 */
extern FiberContext *volatile
fiber_internal_runtime_current_context_slot;

void fiber_internal_scheduler_store_pick_next(FiberSchedulerPickNextFn pick_next,
		void *user);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_THREAD_FUNCTION
FiberContext *fiber_internal_runtime_load_current_context(void);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_internal_scheduler_is_configured(void);

/* Common-private lifecycle state used only by the optional context-feature
 * guard. Selected ports must keep using the separate optional ABI header. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_runtime_close_context_configuration(void);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_internal_runtime_context_configuration_is_open(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_FIBER_RUNTIME_STATE_H_ */

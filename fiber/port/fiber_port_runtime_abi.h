/*
 * fiber_port_runtime_abi.h
 *
 * Opaque callable ABI between the common cooperative runtime and one selected
 * Cortex-M port. This header intentionally exposes no CPU traits, CMSIS
 * registers, frame geometry, or FiberContext layout.
 */

#ifndef FIBER_PORT_FIBER_PORT_RUNTIME_ABI_H_
#define FIBER_PORT_FIBER_PORT_RUNTIME_ABI_H_

#include <stdint.h>

#include "../fiber_api_attributes.h"
#include "../fiber_api_types.h"

#ifdef __cplusplus
extern "C" {
#endif

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_context_init(FiberContext *ctx,
		void *stack_begin,
		void *stack_end,
		entry_t entry,
		void *arg);

/* CPU barriers and terminal wait behavior are port-owned so common runtime
 * objects remain buildable without CMSIS or special-register declarations. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_memory_barrier(void);

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_panic_wait(void);

/* Frozen common-core-freeze-v1 runtime operations. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_require_scheduler_configuration_environment(void);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_prepare_start(void);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_port_runtime_select_first(void);

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_start_first(FiberContext *first);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_schedule(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_FIBER_PORT_RUNTIME_ABI_H_ */

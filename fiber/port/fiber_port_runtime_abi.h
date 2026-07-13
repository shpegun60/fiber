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

void fiber_port_context_init(FiberContext *ctx,
		void *stack_begin,
		void *stack_end,
		entry_t entry,
		void *arg);

/* CPU barriers and terminal wait behavior are port-owned so common runtime
 * objects remain buildable without CMSIS or special-register declarations. */
FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_memory_barrier(void);

FIBER_API_NORETURN FIBER_GENERAL_REGS_ONLY
void fiber_port_panic_wait(void);

FIBER_GENERAL_REGS_ONLY
void fiber_port_context_validate_restore(FiberContext *ctx);

/* Validate the running context metadata and live PSP before PendSV assembly
 * reads selected context fields to save it. This deliberately does not read
 * ctx->sp: while a context is running, that field names its older saved frame. */
FIBER_GENERAL_REGS_ONLY
void fiber_port_context_validate_save_current(const FiberContext *ctx);

uintptr_t fiber_port_context_prepare_first_start(FiberContext *ctx);
void fiber_port_require_start_environment(void);
void fiber_port_require_start_interrupt_state(void);
void fiber_port_runtime_prepare(void);

void fiber_port_require_schedule_environment(void);
void fiber_port_request_schedule(void);

void fiber_port_scheduler_set_pick_next(FiberSchedulerPickNextFn pick_next,
		void *user);

FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_port_scheduler_pick_first_from_start(void);

FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_port_scheduler_pick_next_from_pendsv(FiberContext *current);

void fiber_exception_runtime_check(void);
void fiber_pendsv_init_lowest_priority(void);

FIBER_API_NORETURN
void fiber_port_start_first_context(uintptr_t msp_top);

void fiber_svc(void);
void fiber_pendsv(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_FIBER_PORT_RUNTIME_ABI_H_ */

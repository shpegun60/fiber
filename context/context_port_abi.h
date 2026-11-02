/* Unchanged eight-operation forward port ABI, with canonical Context types. */
#ifndef CTXRT_CONTEXT_PORT_ABI_H_
#define CTXRT_CONTEXT_PORT_ABI_H_

#include <stdint.h>
#include "context_api_attributes.h"
#include "context_api_types.h"

#ifdef __cplusplus
extern "C" {
#endif

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void fiber_port_context_init(CtxrtContextV1 *context,
        void *stack_begin,
        void *stack_end,
        CtxrtEntryFnV1 entry,
        void *arg);

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void fiber_port_runtime_memory_barrier(void);

CTXRT_API_NORETURN CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void fiber_port_panic_wait(void);

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void fiber_port_require_scheduler_configuration_environment(void);

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void fiber_port_runtime_prepare_start(void);

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
CtxrtContextV1 *fiber_port_runtime_select_first(void);

CTXRT_API_NORETURN CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void fiber_port_runtime_start_first(CtxrtContextV1 *first);

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void fiber_port_runtime_schedule(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CTXRT_CONTEXT_PORT_ABI_H_ */

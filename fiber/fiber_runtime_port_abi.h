/*
 * fiber_runtime_port_abi.h
 *
 * Frozen common-runtime services callable by one selected CPU port. This
 * header is CPU-neutral and deliberately exposes no common-owned scheduler
 * storage as a C lvalue.
 */

#ifndef FIBER_FIBER_RUNTIME_PORT_ABI_H_
#define FIBER_FIBER_RUNTIME_PORT_ABI_H_

#include "fiber_api_attributes.h"
#include "fiber_api_types.h"
#include "fiber_panic.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FIBER_RUNTIME_PORT_ABI_VERSION 1u

/* Every mandatory selected-port object retains a relocation to this exact
 * spelling. An incompatible bidirectional ABI removes the old anchor. */
extern const unsigned char fiber_internal_runtime_port_abi_v1_anchor;

/* Force a real relocation that survives optimization and LTO. The volatile
 * read executes only in one-shot port start preparation, never in PendSV. */
#define FIBER_RUNTIME_PORT_ABI_RETAIN_V1() \
	((void)*(volatile const unsigned char *) \
			&fiber_internal_runtime_port_abi_v1_anchor)

/* Assembly-visible only; deliberately no C declaration:
 * fiber_internal_runtime_current_context_slot
 */

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_internal_runtime_select_scheduler_candidate(
		FiberContext *current);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_runtime_publish_current_context(FiberContext *next);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_runtime_require_current_context(void);

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_task_return(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_FIBER_RUNTIME_PORT_ABI_H_ */

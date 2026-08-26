/*
 * fiber_runtime_context_configuration_abi.h
 *
 * Optional common lifecycle service for a selected-port feature that mutates
 * one sealed context before runtime start. This is not part of fiber_core.h,
 * the mandatory forward port ABI, or the mandatory reverse port ABI.
 */

#ifndef FIBER_FIBER_RUNTIME_CONTEXT_CONFIGURATION_ABI_H_
#define FIBER_FIBER_RUNTIME_CONTEXT_CONFIGURATION_ABI_H_

#include "fiber_api_attributes.h"
#include "fiber_api_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FIBER_RUNTIME_CONTEXT_CONFIGURATION_ABI_VERSION 1u

/* A selected-port feature retains this exact anchor only when its matching
 * optional common lifecycle object is linked. */
extern const unsigned char
fiber_internal_runtime_context_configuration_abi_v1_anchor;

#define FIBER_RUNTIME_CONTEXT_CONFIGURATION_ABI_RETAIN_V1() \
	((void)*(volatile const unsigned char *) \
			&fiber_internal_runtime_context_configuration_abi_v1_anchor)

/* Rejects NULL and closes configuration once fiber_start() has begun. The
 * selected feature still owns every port-private validation and mutation. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_runtime_require_context_configuration_open(
		const FiberContext *ctx);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_FIBER_RUNTIME_CONTEXT_CONFIGURATION_ABI_H_ */

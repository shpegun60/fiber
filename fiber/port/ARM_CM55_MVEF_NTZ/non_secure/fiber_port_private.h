/* ARM_CM55_MVEF_NTZ declarations shared by construction-only objects.
 *
 * Slice 1 owns immutable boot metadata, the initial basic exception frame,
 * and the MVE-FP FPU policy.  It intentionally exposes no first-start,
 * scheduler, SVC, or PendSV declarations before those implementation slices
 * exist. */
#ifndef FIBER_PORT_ARM_CM55_MVEF_NTZ_FIBER_PORT_PRIVATE_H_
#define FIBER_PORT_ARM_CM55_MVEF_NTZ_FIBER_PORT_PRIVATE_H_

#include "fiber_portmacro.h"
#include "fiber_port_boot.h"
#include "../../../fiber_runtime_port_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_init_context_frame(FiberContext *ctx);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_fpu_prepare(void);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_fpu_require_configured(void);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_fpu_require_ready(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM55_MVEF_NTZ_FIBER_PORT_PRIVATE_H_ */

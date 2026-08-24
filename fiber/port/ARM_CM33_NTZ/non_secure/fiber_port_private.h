/* ARM_CM33_NTZ declarations shared only by construction objects. */
#ifndef FIBER_PORT_ARM_CM33_NTZ_FIBER_PORT_PRIVATE_H_
#define FIBER_PORT_ARM_CM33_NTZ_FIBER_PORT_PRIVATE_H_

#include "fiber_portmacro.h"
#include "fiber_port_boot.h"
#include "../../fiber_port_runtime_abi.h"
#include "../../../fiber_runtime_port_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

void fiber_port_init_context_frame(FiberContext *ctx);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM33_NTZ_FIBER_PORT_PRIVATE_H_ */

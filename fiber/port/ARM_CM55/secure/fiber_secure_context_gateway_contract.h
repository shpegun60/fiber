/*
 * ARM_CM55 C55S SecureContext capacity gateway contract.
 *
 * This Secure companion capacity gateway also provides one-shot CPU/pool
 * initialization and guarded allocation/load/save. These remain private
 * selected-companion imports, not a portable lifecycle API.
 */
#ifndef FIBER_PORT_ARM_CM55_SECURE_FIBER_SECURE_CONTEXT_GATEWAY_CONTRACT_H_
#define FIBER_PORT_ARM_CM55_SECURE_FIBER_SECURE_CONTEXT_GATEWAY_CONTRACT_H_

#include <stdint.h>

#define FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_ABI_VERSION 1u
#define FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT 8u
#define FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_SVC_EXCEPTION_NUMBER 11u
#define FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_PENDSV_EXCEPTION_NUMBER 14u

#endif /* FIBER_PORT_ARM_CM55_SECURE_FIBER_SECURE_CONTEXT_GATEWAY_CONTRACT_H_ */

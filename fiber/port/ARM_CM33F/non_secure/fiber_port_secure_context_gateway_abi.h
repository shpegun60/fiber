/* Capacity and boot initializer imports; allocate/load/save are undeclared. */
#ifndef FIBER_ARM_CM33F_NS_SECURE_CONTEXT_GATEWAY_ABI_H_
#define FIBER_ARM_CM33F_NS_SECURE_CONTEXT_GATEWAY_ABI_H_
#include <stdint.h>
#include "../../../fiber_api_attributes.h"
#include "../secure/fiber_secure_context_gateway_contract.h"
#ifdef __cplusplus
extern "C" {
#endif
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_secure_context_gateway_c3fs_v1_abi_version(void);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_secure_context_gateway_c3fs_v1_stack_alignment(void);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_secure_context_gateway_c3fs_v1_max_stack_bytes(void);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_secure_context_gateway_c3fs_v1_max_contexts(void);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_secure_context_gateway_c3fs_v1_initialize(void);
#ifdef __cplusplus
}
#endif
#endif

/* C3FS-only imports; never satisfied by scalar C33S or C55S archives. */
#ifndef FIBER_ARM_CM33F_NS_SECURE_GATEWAY_ABI_H_
#define FIBER_ARM_CM33F_NS_SECURE_GATEWAY_ABI_H_
#include <stdint.h>
#include "../../../fiber_api_attributes.h"
#include "../secure/fiber_secure_gateway_contract.h"
#ifdef __cplusplus
extern "C" {
#endif
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_secure_gateway_c3fs_v1_abi_version(void);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_secure_gateway_c3fs_v1_context_port_id(void);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_secure_gateway_c3fs_v1_context_layout_version(void);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_secure_gateway_c3fs_v1_context_feature_mask(void);
#ifdef __cplusplus
}
#endif
#endif

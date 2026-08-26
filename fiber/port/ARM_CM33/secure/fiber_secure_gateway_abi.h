/*
 * fiber_secure_gateway_abi.h
 *
 * Secure-image side of the ARM_CM33 companion gateway. Each function is an
 * NSC veneer export and carries the ABI version in its symbol spelling so a
 * stale import library fails at Non-secure link time.
 */

#ifndef FIBER_PORT_ARM_CM33_SECURE_FIBER_SECURE_GATEWAY_ABI_H_
#define FIBER_PORT_ARM_CM33_SECURE_FIBER_SECURE_GATEWAY_ABI_H_

#include <stdint.h>

#include "mcu_core.h"
#include "fiber_secure_gateway_contract.h"

#if !defined(__ARM_ARCH_8M_MAIN__)
# error "[fiber]: ARM_CM33 Secure gateway requires an ARMv8-M Mainline target"
#endif

#if !defined(__ARM_FEATURE_CMSE) || ((__ARM_FEATURE_CMSE + 0) != 3)
# error "[fiber]: ARM_CM33 Secure gateway requires a Secure CMSE level 3 build"
#endif

#if !defined(__CORTEX_M) || (__CORTEX_M != 33)
# error "[fiber]: ARM_CM33 Secure gateway manifest requires CMSIS __CORTEX_M == 33"
#endif

#if defined(__FPU_USED) && ((__FPU_USED + 0) != 0)
# error "[fiber]: ARM_CM33 Secure gateway is the no-FPU companion ABI"
#endif

#if defined(__ARM_FP) && ((__ARM_FP + 0) != 0)
# error "[fiber]: ARM_CM33 Secure gateway does not permit an FP register ABI"
#endif

#if defined(__VFP_FP__) && !defined(__SOFTFP__)
# error "[fiber]: ARM_CM33 Secure gateway does not permit a hard-FP compiler ABI"
#endif

#if defined(__ARM_FEATURE_MVE) && ((__ARM_FEATURE_MVE + 0) != 0)
# error "[fiber]: ARM_CM33 Secure gateway does not permit MVE"
#endif

#ifndef fiber_secure_gatewayNON_SECURE_CALLABLE
# if defined(__GNUC__) || defined(__clang__)
#  define fiber_secure_gatewayNON_SECURE_CALLABLE \
	__attribute__((cmse_nonsecure_entry)) __attribute__((used)) \
	__attribute__((noinline))
# else
#  error "[fiber]: ARM_CM33 Secure gateway currently requires GCC/Clang CMSE attributes"
# endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_gateway_v1_abi_version(void);

fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_gateway_v1_context_port_id(void);

fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_gateway_v1_context_layout_version(void);

fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_gateway_v1_context_feature_mask(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM33_SECURE_FIBER_SECURE_GATEWAY_ABI_H_ */

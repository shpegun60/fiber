/*
 * Secure-image side of the exact ARM_CM55 C55S identity gateway.
 *
 * Every NSC symbol carries both the C55S cohort spelling and ABI version.
 * A generic CM33 or another M55 profile import library cannot satisfy this
 * Non-secure link accidentally.
 */
#ifndef FIBER_PORT_ARM_CM55_SECURE_FIBER_SECURE_GATEWAY_ABI_H_
#define FIBER_PORT_ARM_CM55_SECURE_FIBER_SECURE_GATEWAY_ABI_H_

#include <stdint.h>

#include "mcu_core.h"
#include "fiber_secure_gateway_contract.h"

#if !defined(FIBER_PORT_BUILD_SELECTED) || (FIBER_PORT_BUILD_SELECTED != 1)
# error "[fiber]: ARM_CM55 Secure gateway is build-selected only"
#endif

#if !defined(FIBER_PORT_ARMV81M_MAINLINE) || \
		(FIBER_PORT_ARMV81M_MAINLINE != 1)
# error "[fiber]: ARM_CM55 Secure gateway requires ARMv8.1-M Mainline selection"
#endif

/* GCC emits __ARM_ARCH_8M_MAIN__ for the scalar M55 target. */
#if !defined(__ARM_ARCH_8M_MAIN__) && !defined(__ARM_ARCH_8_1M_MAIN__)
# error "[fiber]: ARM_CM55 Secure gateway requires an ARMv8.1-M Mainline target"
#endif

#if !defined(__ARM_FEATURE_CMSE) || ((__ARM_FEATURE_CMSE + 0) != 3)
# error "[fiber]: ARM_CM55 Secure gateway requires a Secure CMSE level 3 build"
#endif

#if !defined(__CORTEX_M) || (__CORTEX_M != 55)
# error "[fiber]: ARM_CM55 Secure gateway manifest requires CMSIS __CORTEX_M == 55"
#endif

#if !defined(__VTOR_PRESENT) || (__VTOR_PRESENT != 1)
# error "[fiber]: ARM_CM55 Secure gateway requires __VTOR_PRESENT == 1"
#endif

#if defined(__FPU_USED) && ((__FPU_USED + 0) != 0)
# error "[fiber]: ARM_CM55 Secure gateway is the no-FPU C55S companion ABI"
#endif

#if defined(__ARM_FP) && ((__ARM_FP + 0) != 0)
# error "[fiber]: ARM_CM55 Secure gateway does not permit an FP register ABI"
#endif

#if defined(__VFP_FP__) && !defined(__SOFTFP__)
# error "[fiber]: ARM_CM55 Secure gateway does not permit a hard-FP compiler ABI"
#endif

#if defined(__ARM_FEATURE_MVE) && ((__ARM_FEATURE_MVE + 0) != 0)
# error "[fiber]: ARM_CM55 Secure gateway does not permit MVE"
#endif

#if defined(__ARM_FEATURE_PAC_DEFAULT) || defined(__ARM_FEATURE_PAUTH) || \
		defined(__ARM_FEATURE_PAUTH_DEFAULT)
# error "[fiber]: ARM_CM55 Secure gateway does not permit PAC"
#endif

#if defined(__ARM_FEATURE_BTI_DEFAULT) || defined(__ARM_FEATURE_BTI)
# error "[fiber]: ARM_CM55 Secure gateway does not permit BTI"
#endif

#if defined(FIBER_PORT_CM55_MPU_TOTAL_REGIONS) || \
		defined(FIBER_PORT_CM55F_MPU_TOTAL_REGIONS) || \
		defined(FIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS) || \
		defined(FIBER_PORT_MPU_TOTAL_REGIONS)
# error "[fiber]: ARM_CM55 Secure gateway is not an MPU companion ABI"
#endif

#ifndef fiber_secure_gatewayNON_SECURE_CALLABLE
# if defined(__GNUC__) || defined(__clang__)
#  define fiber_secure_gatewayNON_SECURE_CALLABLE \
	__attribute__((cmse_nonsecure_entry)) __attribute__((used)) \
	__attribute__((noinline))
# else
#  error "[fiber]: ARM_CM55 Secure gateway currently requires GCC/Clang CMSE attributes"
# endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_gateway_c55s_v1_abi_version(void);

fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_gateway_c55s_v1_context_port_id(void);

fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_gateway_c55s_v1_context_layout_version(void);

fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_gateway_c55s_v1_context_feature_mask(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM55_SECURE_FIBER_SECURE_GATEWAY_ABI_H_ */

/* Eight immutable NSC queries and one boot initializer for staged C3FS. */
#ifndef FIBER_ARM_CM33F_SECURE_GATEWAY_ABI_H_
#define FIBER_ARM_CM33F_SECURE_GATEWAY_ABI_H_
#include <stdint.h>
#include "../../../fiber_api_attributes.h"
#include "mcu_core.h"
#include "fiber_secure_gateway_contract.h"
#include "fiber_secure_context_gateway_contract.h"

#if !defined(__GNUC__) || !defined(__ARM_ARCH_8M_MAIN__) || \
        !defined(__ARM_FEATURE_CMSE) || (__ARM_FEATURE_CMSE != 3) || \
        !defined(__CORTEX_M) || (__CORTEX_M != 33)
# error "[fiber]: C3FS Secure requires GCC Mainline CMSIS33 CMSE3"
#endif
#if !defined(__FPU_PRESENT) || (__FPU_PRESENT != 1) || \
        !defined(__FPU_USED) || (__FPU_USED != 1) || \
        !defined(__ARM_FP) || (__ARM_FP != 4)
# error "[fiber]: C3FS Secure requires CMSIS FPU present/used and scalar-SP __ARM_FP == 4"
#endif
#if defined(__ARM_ARCH_8_1M_MAIN__) || \
        (defined(__ARM_FEATURE_MVE) && (__ARM_FEATURE_MVE != 0)) || \
        defined(__ARM_FEATURE_PAC_DEFAULT) || defined(__ARM_FEATURE_PAUTH) || \
        defined(__ARM_FEATURE_PAUTH_DEFAULT) || defined(__ARM_FEATURE_BTI) || \
        defined(__ARM_FEATURE_BTI_DEFAULT)
# error "[fiber]: C3FS Secure excludes ARMv8.1-M, MVE, PAC and BTI"
#endif
#ifdef FIBER_C3FS_NSC
# error "[fiber]: C3FS NSC attributes must not be predefined"
#endif
#define FIBER_C3FS_NSC __attribute__((cmse_nonsecure_entry)) \
        FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY

/* Boot-owned prerequisite even for read-only queries. This never grants FPU
 * access or changes NSACR/FPCCR policy. CONTROL.nPRIV or CP10/11 mismatch is
 * terminal, not a return path through a potentially FP-using CMSE envelope.
 * Maintained codegen must additionally prove no FP instruction precedes it. */
static inline __attribute__((always_inline))
FIBER_API_ATTR_INLINE_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_secure_c3fs_query_preflight(void)
{
    uint32_t scratch;
    __asm volatile(
        "mrs %0, control\n\t"
        "tst %0, #1\n\t"
        "bne 1f\n\t"
        "ldr %0, =0xE000ED88\n\t"
        "ldr %0, [%0]\n\t"
        "and %0, %0, #0x00F00000\n\t"
        "cmp %0, #0x00F00000\n\t"
        "beq 2f\n"
        "1: udf #75\n\tb 1b\n"
        "2:"
        : "=&r"(scratch) :: "cc", "memory");
}
#ifdef __cplusplus
extern "C" {
#endif
FIBER_C3FS_NSC uint32_t fiber_secure_gateway_c3fs_v1_abi_version(void);
FIBER_C3FS_NSC uint32_t fiber_secure_gateway_c3fs_v1_context_port_id(void);
FIBER_C3FS_NSC uint32_t fiber_secure_gateway_c3fs_v1_context_layout_version(void);
FIBER_C3FS_NSC uint32_t fiber_secure_gateway_c3fs_v1_context_feature_mask(void);
FIBER_C3FS_NSC uint32_t fiber_secure_context_gateway_c3fs_v1_abi_version(void);
FIBER_C3FS_NSC uint32_t fiber_secure_context_gateway_c3fs_v1_stack_alignment(void);
FIBER_C3FS_NSC uint32_t fiber_secure_context_gateway_c3fs_v1_max_stack_bytes(void);
FIBER_C3FS_NSC uint32_t fiber_secure_context_gateway_c3fs_v1_max_contexts(void);
FIBER_C3FS_NSC uint32_t fiber_secure_context_gateway_c3fs_v1_initialize(void);
#ifdef __cplusplus
}
#endif
#endif

/* Secure-private capacity/record contract, not an allocated pool. */
#ifndef FIBER_ARM_CM33F_SECURE_CONTEXT_MANIFEST_H_
#define FIBER_ARM_CM33F_SECURE_CONTEXT_MANIFEST_H_
#include <stddef.h>
#include <stdint.h>
#include "../../../fiber_api_attributes.h"

#ifndef FIBER_ARM_CM33F_SECURE_CONTEXT_MAX_COUNT
# error "[fiber]: C3FS manifest requires FIBER_ARM_CM33F_SECURE_CONTEXT_MAX_COUNT"
#endif
#ifndef FIBER_ARM_CM33F_SECURE_CONTEXT_MAX_STACK_BYTES
# error "[fiber]: C3FS manifest requires FIBER_ARM_CM33F_SECURE_CONTEXT_MAX_STACK_BYTES"
#endif
#if FIBER_ARM_CM33F_SECURE_CONTEXT_MAX_COUNT == 0
# error "[fiber]: C3FS capacity count must be nonzero"
#endif
#if (FIBER_ARM_CM33F_SECURE_CONTEXT_MAX_STACK_BYTES < 8) || \
        (FIBER_ARM_CM33F_SECURE_CONTEXT_MAX_STACK_BYTES % 8 != 0) || \
        (FIBER_ARM_CM33F_SECURE_CONTEXT_MAX_STACK_BYTES > 0xFFFFFFF7u)
# error "[fiber]: C3FS capacity must be eight-byte aligned and leave seal space"
#endif
#define FIBER_ARM_CM33F_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES 8u
#define FIBER_ARM_CM33F_SECURE_CONTEXT_STACK_SEAL_WORDS 2u
#define FIBER_ARM_CM33F_SECURE_CONTEXT_STACK_SEAL_BYTES 8u
#define FIBER_ARM_CM33F_SECURE_CONTEXT_STACK_SEAL_VALUE 0xFEF5EDA5u
#define FIBER_ARM_CM33F_SECURE_CONTEXT_RECORD_LAYOUT_REVISION 1u

/* The first four fields match the reference. These extra two fields bind
 * bounded capacity and allocation state, but no storage exists in this slice. */
typedef struct FiberSecureContextRecord {
    uintptr_t current_stack_pointer;
    uintptr_t stack_limit;
    uintptr_t stack_top;
    uintptr_t owner_token;
    uint32_t stack_bytes;
    uint32_t allocation_state;
} FiberSecureContextRecord;

#ifdef __cplusplus
extern "C" {
#endif
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_secure_context_manifest_c3fs_v1_cohort_provider(void);
#ifdef __cplusplus
}
#endif
#endif

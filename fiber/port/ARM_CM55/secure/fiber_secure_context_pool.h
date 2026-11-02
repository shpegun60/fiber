/*
 * Secure-image-private static capacity and lifecycle for ARM_CM55 C55S.
 *
 * This is not an NSC ABI and must not be included by the Non-secure image.
 * Callers are serialized, single-core Secure code; concurrent or reentrant
 * lifecycle calls are unsupported. This module does not change CPU registers,
 * interrupt masks, or runtime activation. There is no free or detach operation.
 * The explicit manifest prevents a hidden Secure-RAM cost.
 */
#ifndef FIBER_PORT_ARM_CM55_SECURE_FIBER_SECURE_CONTEXT_POOL_H_
#define FIBER_PORT_ARM_CM55_SECURE_FIBER_SECURE_CONTEXT_POOL_H_

#include <stdint.h>

#include "../../../fiber_api_attributes.h"
#include "fiber_secure_context_gateway_contract.h"

/* Canonical source attributes cover the complete private call graph. Selected
 * Secure-image instrumentation/sanitizer/FP counterflags remain mandatory. */

#ifndef FIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT
# error "[fiber]: ARM_CM55 SecureContext pool requires FIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT"
#endif

#ifndef FIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES
# error "[fiber]: ARM_CM55 SecureContext pool requires FIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES"
#endif

#define FIBER_ARM_CM55_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES 8u
#define FIBER_ARM_CM55_SECURE_CONTEXT_STACK_SEAL_WORDS 2u
#define FIBER_ARM_CM55_SECURE_CONTEXT_STACK_SEAL_BYTES 8u
#define FIBER_ARM_CM55_SECURE_CONTEXT_STACK_SEAL_VALUE 0xFEF5EDA5u
#define FIBER_ARM_CM55_SECURE_CONTEXT_RECORD_LAYOUT_REVISION 1u

#if FIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT == 0u
# error "[fiber]: ARM_CM55 SecureContext pool count must be non-zero"
#endif

/* Opaque index-plus-one handles retain zero as invalid. */
#if FIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT > 0xFFFFFFFEu
# error "[fiber]: ARM_CM55 SecureContext pool count exceeds handle range"
#endif

#if FIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES < \
		FIBER_ARM_CM55_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES
# error "[fiber]: ARM_CM55 SecureContext stack capacity is too small"
#endif

#if (FIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES % \
		FIBER_ARM_CM55_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES) != 0u
# error "[fiber]: ARM_CM55 SecureContext stack capacity must be eight-byte aligned"
#endif

#if FIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES > 0xFFFFFFF7u
# error "[fiber]: ARM_CM55 SecureContext stack capacity overflows the seal allocation"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t FiberSecureContextHandle;

#define FIBER_SECURE_CONTEXT_HANDLE_INVALID ((FiberSecureContextHandle)0u)

/* The first four words intentionally match the FreeRTOS SecureContext record:
 * saved PSP, PSPLIM, stack top, then an opaque Non-secure owner token. Secure
 * code compares that token but never dereferences it. */
typedef struct FiberSecureContextRecord {
	uintptr_t current_stack_pointer;
	uintptr_t stack_limit;
	uintptr_t stack_top;
	uintptr_t owner_token;
	uint32_t stack_bytes;
	uint32_t allocation_state;
} FiberSecureContextRecord;

/* Strong C archive-extraction edge for the Secure-private exact cohort. This
 * non-NSC helper emits one read-only provider byte but does not initialize or
 * access pool/BSS/CPU state. It is safe before Secure pool initialization. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_secure_context_pool_c55s_v1_cohort_provider(void);

/* One shot per normal Secure BSS initialization. The private 4-byte BSS marker
 * is outside the unchanged NOLOAD records+stacks image. Returns 1 only after
 * erasing and verifying the complete image. INITIALIZING/READY repeats return
 * 0 before any erase; partial failure cannot be retried until a fresh boot.
 * Unknown state or internal corruption fails closed. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_secure_context_pool_boot_initialize(void);

/* Requires READY. Returns 0 for an invalid request, duplicate owner, or full
 * pool. All records are checked before allocation publication. Corrupted
 * Secure metadata or stack seals fail closed rather than becoming free slots. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberSecureContextHandle fiber_secure_context_pool_allocate(
		uint32_t secure_stack_bytes,
		uintptr_t owner_token);

/* Requires READY. Returns NULL for an invalid/unallocated handle or a wrong
 * owner. A returned pointer is Secure-private; it never crosses an NSC ABI.
 * Corruption of the selected record or its seal fails closed. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberSecureContextRecord *fiber_secure_context_pool_lookup_owned(
		FiberSecureContextHandle handle,
		uintptr_t owner_token);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM55_SECURE_FIBER_SECURE_CONTEXT_POOL_H_ */

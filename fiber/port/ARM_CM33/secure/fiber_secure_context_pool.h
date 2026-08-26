/*
 * fiber_secure_context_pool.h
 *
 * Secure-image-private storage foundation for the no-MPU, no-FPU ARM_CM33
 * SecureContext companion. It is not an NSC ABI and must never be included by
 * the Non-secure image. The later selected port owns every NSC bridge and all
 * SVC/PendSV save-load mechanics.
 */

#ifndef FIBER_PORT_ARM_CM33_SECURE_FIBER_SECURE_CONTEXT_POOL_H_
#define FIBER_PORT_ARM_CM33_SECURE_FIBER_SECURE_CONTEXT_POOL_H_

#include <stdint.h>

#include "fiber_secure_gateway_abi.h"

/* These are Secure-image integration settings, not fiber_core.h settings.
 * There is deliberately no hidden default: a Secure manifest must budget the
 * maximum number of attached fibers and the largest one Secure stack. */
#ifndef FIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT
# error "[fiber]: ARM_CM33 SecureContext pool requires FIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT"
#endif

#ifndef FIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES
# error "[fiber]: ARM_CM33 SecureContext pool requires FIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES"
#endif

#define FIBER_ARM_CM33_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES 8u
#define FIBER_ARM_CM33_SECURE_CONTEXT_STACK_SEAL_WORDS 2u
#define FIBER_ARM_CM33_SECURE_CONTEXT_STACK_SEAL_BYTES 8u
#define FIBER_ARM_CM33_SECURE_CONTEXT_STACK_SEAL_VALUE 0xFEF5EDA5u

#if FIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT == 0u
# error "[fiber]: ARM_CM33 SecureContext pool count must be non-zero"
#endif

#if FIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES < \
		FIBER_ARM_CM33_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES
# error "[fiber]: ARM_CM33 SecureContext stack capacity is too small"
#endif

#if (FIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES % \
		FIBER_ARM_CM33_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES) != 0u
# error "[fiber]: ARM_CM33 SecureContext stack capacity must be eight-byte aligned"
#endif

#if FIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES > 0xFFFFFFF7u
# error "[fiber]: ARM_CM33 SecureContext stack capacity overflows the seal allocation"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t FiberSecureContextHandle;

#define FIBER_SECURE_CONTEXT_HANDLE_INVALID \
	((FiberSecureContextHandle)0u)

/* The first four words deliberately retain the FreeRTOS SecureContext shape:
 * saved PSP, PSPLIM, stack top, then an opaque owner identity. The owner token
 * is compared only; Secure code must never dereference it. */
typedef struct FiberSecureContextRecord {
	uintptr_t current_stack_pointer;
	uintptr_t stack_limit;
	uintptr_t stack_top;
	uintptr_t owner_token;
	uint32_t stack_bytes;
	uint32_t allocation_state;
} FiberSecureContextRecord;

/* Destructive Secure-boot initialization. It erases every record and stack
 * slot, then opens the pool for the future selected-port allocation bridge.
 * It must run exactly once per Secure boot, before any context is allocated. */
void fiber_secure_context_pool_boot_initialize(void);

/* Returns zero for an invalid request, duplicate owner, or exhausted pool.
 * A nonzero handle is an index-plus-one opaque token, matching the FreeRTOS
 * invalid-handle convention. This function does not create an NSC veneer. */
FiberSecureContextHandle fiber_secure_context_pool_allocate(
		uint32_t secure_stack_bytes,
		uintptr_t owner_token);

/* Returns NULL for a foreign, stale, or invalid handle. Internal Secure-state
 * corruption fails closed inside the implementation before a record is used. */
FiberSecureContextRecord *fiber_secure_context_pool_lookup_owned(
		FiberSecureContextHandle handle,
		uintptr_t owner_token);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM33_SECURE_FIBER_SECURE_CONTEXT_POOL_H_ */

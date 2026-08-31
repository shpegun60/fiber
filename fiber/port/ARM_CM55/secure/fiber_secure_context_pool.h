/*
 * Secure-image-private static capacity reservation for ARM_CM55 C55S.
 *
 * No public or NSC lifecycle operation reads this storage in Slice 3. A later
 * one-shot Secure initialization must erase it before allocation becomes
 * possible. The explicit manifest prevents a hidden Secure-RAM cost.
 */
#ifndef FIBER_PORT_ARM_CM55_SECURE_FIBER_SECURE_CONTEXT_POOL_H_
#define FIBER_PORT_ARM_CM55_SECURE_FIBER_SECURE_CONTEXT_POOL_H_

#include <stdint.h>

#include "fiber_secure_context_gateway_contract.h"

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

#if FIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT == 0u
# error "[fiber]: ARM_CM55 SecureContext pool count must be non-zero"
#endif

/* A later opaque index-plus-one handle must retain zero as invalid. */
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

/* The first four words intentionally match the FreeRTOS SecureContext record:
 * saved PSP, PSPLIM, stack top, then an opaque Non-secure owner token. */
typedef struct FiberSecureContextRecord {
	uintptr_t current_stack_pointer;
	uintptr_t stack_limit;
	uintptr_t stack_top;
	uintptr_t owner_token;
	uint32_t stack_bytes;
	uint32_t allocation_state;
} FiberSecureContextRecord;

#endif /* FIBER_PORT_ARM_CM55_SECURE_FIBER_SECURE_CONTEXT_POOL_H_ */

/* ARM_CM55 C55S SecureContext static-capacity image. */

#include <stddef.h>
#include <stdint.h>

#include "fiber_secure_context_pool.h"

#if !defined(__GNUC__) && !defined(__clang__)
# error "[fiber]: ARM_CM55 SecureContext pool requires GCC/Clang attributes"
#endif

#define fiber_secure_contextPOOL_STORAGE \
	__attribute__((section(".fiber_secure_context_pool"), used, aligned(8)))

typedef union FiberSecureContextStackStorage {
	uint8_t bytes[FIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES +
		FIBER_ARM_CM55_SECURE_CONTEXT_STACK_SEAL_BYTES];
	uint64_t force_eight_byte_alignment;
} FiberSecureContextStackStorage;

typedef struct FiberSecureContextPoolImage {
	FiberSecureContextRecord records[
		FIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT];
	FiberSecureContextStackStorage stacks[
		FIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT];
} FiberSecureContextPoolImage;

/* Deliberately private and NOLOAD. Slice 3 reserves the exact Secure RAM
 * budget, but later one-shot initialization owns every write and read. */
static FiberSecureContextPoolImage fiber_secure_context_pool_image
	fiber_secure_contextPOOL_STORAGE;

_Static_assert(sizeof(uintptr_t) == 4u,
		"[fiber]: ARM_CM55 SecureContext pool requires 32-bit pointers");
_Static_assert(FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT ==
		FIBER_ARM_CM55_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES,
		"[fiber]: ARM_CM55 SecureContext gateway/pool alignment mismatch");
_Static_assert(FIBER_ARM_CM55_SECURE_CONTEXT_STACK_SEAL_BYTES ==
		(FIBER_ARM_CM55_SECURE_CONTEXT_STACK_SEAL_WORDS * sizeof(uint32_t)),
		"[fiber]: ARM_CM55 SecureContext stack seal geometry changed");
_Static_assert(offsetof(FiberSecureContextRecord, current_stack_pointer) == 0u,
		"[fiber]: ARM_CM55 SecureContext PSP word moved");
_Static_assert(offsetof(FiberSecureContextRecord, stack_limit) == 4u,
		"[fiber]: ARM_CM55 SecureContext PSPLIM word moved");
_Static_assert(offsetof(FiberSecureContextRecord, stack_top) == 8u,
		"[fiber]: ARM_CM55 SecureContext stack-top word moved");
_Static_assert(offsetof(FiberSecureContextRecord, owner_token) == 12u,
		"[fiber]: ARM_CM55 SecureContext owner word moved");
_Static_assert(sizeof(FiberSecureContextRecord) == 24u,
		"[fiber]: ARM_CM55 SecureContext record geometry changed");
_Static_assert(_Alignof(FiberSecureContextStackStorage) >=
		FIBER_ARM_CM55_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES,
		"[fiber]: ARM_CM55 SecureContext storage lost stack alignment");
_Static_assert(sizeof(fiber_secure_context_pool_image) ==
		(FIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT *
			(sizeof(FiberSecureContextRecord) +
			 (FIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES +
			  FIBER_ARM_CM55_SECURE_CONTEXT_STACK_SEAL_BYTES))),
		"[fiber]: ARM_CM55 SecureContext pool image geometry changed");

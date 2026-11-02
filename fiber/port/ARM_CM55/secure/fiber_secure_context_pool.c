/* ARM_CM55 C55S Secure-private static pool; no NSC or CPU-state operations. */

#include <stddef.h>
#include <stdint.h>

#include "fiber_secure_context_pool.h"
#include "fiber_secure_context_cohort.h"

#if !defined(__GNUC__) && !defined(__clang__)
# error "[fiber]: ARM_CM55 SecureContext pool requires GCC/Clang attributes"
#endif

#define fiber_secure_contextPOOL_STORAGE \
	__attribute__((section(".fiber_secure_context_pool"), used, aligned(8)))

#define fiber_secure_contextPOOL_INITIALIZING 0x53435042u
#define fiber_secure_contextPOOL_READY 0x53435052u
#define fiber_secure_contextSTATE_FREE 0u
#define fiber_secure_contextSTATE_ALLOCATED 0x53435458u

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

/* Deliberately private and NOLOAD. One-shot initialization owns every byte
 * before records or stacks may be read through the allocation/lookup API. */
static FiberSecureContextPoolImage fiber_secure_context_pool_image
	fiber_secure_contextPOOL_STORAGE;

/* Normal zero-initialized BSS, never the retained NOLOAD image. This costs
 * exactly four additional bytes outside the manifest records+stacks budget. */
static volatile uint32_t fiber_secure_context_pool_state;

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
_Static_assert(sizeof(fiber_secure_context_pool_state) == 4u,
		"[fiber]: ARM_CM55 SecureContext BSS marker geometry changed");

/* Keep the C symbol visible to the archive/LTO index and the build-owned
 * generation ASSERT. The canonical noipa bundle prevents cloning/inlining. */
#if defined(__GNUC__) && !defined(__clang__)
__attribute__((externally_visible))
#endif
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_secure_context_pool_c55s_v1_cohort_provider(void)
{
	FIBER_C55S_PRIVATE_COHORT_DEFINE();
}

static FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_secure_context_pool_fail_closed(void)
{
	__builtin_trap();
	for (;;) {
	}
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_secure_context_pool_require_ready(void)
{
	if (fiber_secure_context_pool_state != fiber_secure_contextPOOL_READY) {
		fiber_secure_context_pool_fail_closed();
	}
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_secure_context_pool_record_is_free(
		const FiberSecureContextRecord * const record)
{
	return (record->current_stack_pointer == 0u) &&
			(record->stack_limit == 0u) &&
			(record->stack_top == 0u) &&
			(record->owner_token == 0u) &&
			(record->stack_bytes == 0u) &&
			(record->allocation_state == fiber_secure_contextSTATE_FREE);
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_secure_context_pool_write_stack_seal(
		uint8_t * const stack_limit,
		const uint32_t stack_bytes)
{
	const uint32_t value = FIBER_ARM_CM55_SECURE_CONTEXT_STACK_SEAL_VALUE;
	const unsigned char * const representation =
			(const unsigned char *)(const void *)&value;
	volatile unsigned char * const seal =
			(volatile unsigned char *)(void *)(stack_limit + stack_bytes);

	/* Character accesses preserve the word's native object representation
	 * without type-punning the declared byte array through uint32_t pointers. */
	for (size_t byte = 0u;
			byte < FIBER_ARM_CM55_SECURE_CONTEXT_STACK_SEAL_BYTES; ++byte) {
		seal[byte] = representation[byte % sizeof(value)];
	}
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_secure_context_pool_stack_seal_is_valid(
		const uint8_t * const stack_limit,
		const uint32_t stack_bytes)
{
	const uint32_t value = FIBER_ARM_CM55_SECURE_CONTEXT_STACK_SEAL_VALUE;
	const unsigned char * const representation =
			(const unsigned char *)(const void *)&value;
	const volatile unsigned char * const seal =
			(const volatile unsigned char *)(const void *)(stack_limit + stack_bytes);

	for (size_t byte = 0u;
			byte < FIBER_ARM_CM55_SECURE_CONTEXT_STACK_SEAL_BYTES; ++byte) {
		if (seal[byte] != representation[byte % sizeof(value)]) {
			return 0u;
		}
	}
	return 1u;
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_secure_context_pool_record_is_valid(const uint32_t index)
{
	if (index >= FIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT) {
		return 0u;
	}
	const FiberSecureContextRecord * const record =
			&fiber_secure_context_pool_image.records[index];
	const uint32_t stack_bytes = record->stack_bytes;
	const uintptr_t stack_limit =
			(uintptr_t)fiber_secure_context_pool_image.stacks[index].bytes;

	if ((record->allocation_state != fiber_secure_contextSTATE_ALLOCATED) ||
			(record->owner_token == 0u) ||
			(stack_bytes == 0u) ||
			(stack_bytes > FIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES) ||
			((stack_bytes %
				FIBER_ARM_CM55_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES) != 0u)) {
		return 0u;
	}
	if (stack_limit > UINTPTR_MAX -
			sizeof(fiber_secure_context_pool_image.stacks[index].bytes)) {
		return 0u;
	}
	const uintptr_t stack_top = stack_limit + (uintptr_t)stack_bytes;
	if (((stack_limit | stack_top | record->current_stack_pointer) &
			(FIBER_ARM_CM55_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES - 1u)) != 0u) {
		return 0u;
	}
	if ((record->stack_limit != stack_limit) ||
			(record->stack_top != stack_top) ||
			(record->current_stack_pointer < stack_limit) ||
			(record->current_stack_pointer > stack_top)) {
		return 0u;
	}

	/* Only checked geometry may determine an address used for a seal read. */
	return fiber_secure_context_pool_stack_seal_is_valid(
			fiber_secure_context_pool_image.stacks[index].bytes, stack_bytes);
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_secure_context_pool_boot_initialize(void)
{
	const uint32_t state = fiber_secure_context_pool_state;
	if ((state == fiber_secure_contextPOOL_INITIALIZING) ||
			(state == fiber_secure_contextPOOL_READY)) {
		return 0u;
	}
	if (state != 0u) {
		fiber_secure_context_pool_fail_closed();
	}

	fiber_secure_context_pool_state = fiber_secure_contextPOOL_INITIALIZING;
	__asm volatile("" ::: "memory");
	volatile unsigned char * const image =
			(volatile unsigned char *)(void *)&fiber_secure_context_pool_image;
	/* NOLOAD contents are untrusted. Volatile byte writes/readback cover the
	 * complete image, including unused stack tails and object padding, without
	 * a compiler-generated memset/memcpy or an eliminable dead-store scrub. */
	for (size_t byte = 0u; byte < sizeof(fiber_secure_context_pool_image); ++byte) {
		image[byte] = 0u;
	}
	for (size_t byte = 0u; byte < sizeof(fiber_secure_context_pool_image); ++byte) {
		if (image[byte] != 0u) {
			fiber_secure_context_pool_fail_closed();
		}
	}
	if (fiber_secure_context_pool_state != fiber_secure_contextPOOL_INITIALIZING) {
		fiber_secure_context_pool_fail_closed();
	}
	__asm volatile("" ::: "memory");
	fiber_secure_context_pool_state = fiber_secure_contextPOOL_READY;
	__asm volatile("" ::: "memory");
	if (fiber_secure_context_pool_state != fiber_secure_contextPOOL_READY) {
		fiber_secure_context_pool_fail_closed();
	}
	return 1u;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberSecureContextHandle fiber_secure_context_pool_allocate(
		const uint32_t secure_stack_bytes,
		const uintptr_t owner_token)
{
	fiber_secure_context_pool_require_ready();
	if ((owner_token == 0u) || (secure_stack_bytes == 0u) ||
			(secure_stack_bytes > FIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES) ||
			((secure_stack_bytes %
				FIBER_ARM_CM55_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES) != 0u)) {
		return FIBER_SECURE_CONTEXT_HANDLE_INVALID;
	}

	uint32_t first_free = FIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT;
	uint32_t duplicate_owner = 0u;
	for (uint32_t index = 0u;
			index < FIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT; ++index) {
		const FiberSecureContextRecord * const record =
				&fiber_secure_context_pool_image.records[index];
		if (record->allocation_state == fiber_secure_contextSTATE_FREE) {
			if (!fiber_secure_context_pool_record_is_free(record)) {
				fiber_secure_context_pool_fail_closed();
			}
			if (first_free == FIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT) {
				first_free = index;
			}
		} else if (record->allocation_state == fiber_secure_contextSTATE_ALLOCATED) {
			if (!fiber_secure_context_pool_record_is_valid(index)) {
				fiber_secure_context_pool_fail_closed();
			}
			/* Earlier records are already validated. Duplicate stored ownership
			 * is corruption, unlike a repeated allocation request for one owner. */
			for (uint32_t prior = 0u; prior < index; ++prior) {
				if (fiber_secure_context_pool_image.records[prior].owner_token ==
						record->owner_token) {
					fiber_secure_context_pool_fail_closed();
				}
			}
			if (record->owner_token == owner_token) {
				duplicate_owner = 1u;
			}
		} else {
			fiber_secure_context_pool_fail_closed();
		}
	}
	if ((duplicate_owner != 0u) ||
			(first_free == FIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT)) {
		return FIBER_SECURE_CONTEXT_HANDLE_INVALID;
	}

	FiberSecureContextRecord * const record =
			&fiber_secure_context_pool_image.records[first_free];
	const uintptr_t stack_limit =
			(uintptr_t)fiber_secure_context_pool_image.stacks[first_free].bytes;
	if (stack_limit > UINTPTR_MAX -
			sizeof(fiber_secure_context_pool_image.stacks[first_free].bytes)) {
		fiber_secure_context_pool_fail_closed();
	}
	const uintptr_t stack_top = stack_limit + (uintptr_t)secure_stack_bytes;
	fiber_secure_context_pool_write_stack_seal(
			fiber_secure_context_pool_image.stacks[first_free].bytes,
			secure_stack_bytes);
	record->current_stack_pointer = stack_top;
	record->stack_limit = stack_limit;
	record->stack_top = stack_top;
	record->owner_token = owner_token;
	record->stack_bytes = secure_stack_bytes;
	__asm volatile("" ::: "memory");
	record->allocation_state = fiber_secure_contextSTATE_ALLOCATED;
	__asm volatile("" ::: "memory");
	if (!fiber_secure_context_pool_record_is_valid(first_free)) {
		fiber_secure_context_pool_fail_closed();
	}
	fiber_secure_context_pool_require_ready();
	return (FiberSecureContextHandle)(first_free + 1u);
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberSecureContextRecord *fiber_secure_context_pool_lookup_owned(
		const FiberSecureContextHandle handle,
		const uintptr_t owner_token)
{
	fiber_secure_context_pool_require_ready();
	if ((handle == FIBER_SECURE_CONTEXT_HANDLE_INVALID) ||
			(handle > FIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT) ||
			(owner_token == 0u)) {
		return NULL;
	}
	const uint32_t index = (uint32_t)(handle - 1u);
	FiberSecureContextRecord * const record =
			&fiber_secure_context_pool_image.records[index];
	if (record->allocation_state == fiber_secure_contextSTATE_FREE) {
		if (!fiber_secure_context_pool_record_is_free(record)) {
			fiber_secure_context_pool_fail_closed();
		}
		return NULL;
	}
	if (!fiber_secure_context_pool_record_is_valid(index)) {
		fiber_secure_context_pool_fail_closed();
	}
	if (record->owner_token != owner_token) {
		return NULL;
	}
	return record;
}

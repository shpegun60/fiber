/*
 * fiber_secure_context_pool.c
 *
 * Bounded static replacement for the FreeRTOS ARM_CM33 secure_heap-backed
 * SecureContext allocator. Fiber contexts have static lifetime, so this module
 * intentionally has no free or detach operation.
 */

#include <stddef.h>
#include <stdint.h>

#include "fiber_secure_context_pool.h"

#if !defined(__GNUC__) && !defined(__clang__)
# error "[fiber]: ARM_CM33 SecureContext pool requires GCC/Clang attributes"
#endif

#define fiber_secure_contextPOOL_STORAGE \
	__attribute__((section(".fiber_secure_context_pool"), used))

#define fiber_secure_contextPOOL_INITIALIZED 0x53435049u
#define fiber_secure_contextSTATE_FREE 0u
#define fiber_secure_contextSTATE_ALLOCATED 0x53435458u

typedef union FiberSecureContextStackStorage {
	uint8_t bytes[FIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES +
		FIBER_ARM_CM33_SECURE_CONTEXT_STACK_SEAL_BYTES];
	uint64_t force_eight_byte_alignment;
} FiberSecureContextStackStorage;

static FiberSecureContextRecord fiber_secure_context_pool_records[
		FIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT]
		fiber_secure_contextPOOL_STORAGE __attribute__((aligned(8)));

static FiberSecureContextStackStorage fiber_secure_context_pool_stacks[
		FIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT]
		fiber_secure_contextPOOL_STORAGE __attribute__((aligned(8)));

static uint32_t fiber_secure_context_pool_initialized
		fiber_secure_contextPOOL_STORAGE __attribute__((aligned(4)));

_Static_assert(sizeof(uintptr_t) == 4u,
		"[fiber]: ARM_CM33 SecureContext pool requires 32-bit pointers");
_Static_assert(FIBER_ARM_CM33_SECURE_CONTEXT_STACK_SEAL_BYTES ==
		(FIBER_ARM_CM33_SECURE_CONTEXT_STACK_SEAL_WORDS * sizeof(uint32_t)),
		"[fiber]: ARM_CM33 SecureContext stack seal geometry changed");
_Static_assert(offsetof(FiberSecureContextRecord, current_stack_pointer) == 0u,
		"[fiber]: ARM_CM33 SecureContext PSP word moved");
_Static_assert(offsetof(FiberSecureContextRecord, stack_limit) == 4u,
		"[fiber]: ARM_CM33 SecureContext PSPLIM word moved");
_Static_assert(offsetof(FiberSecureContextRecord, stack_top) == 8u,
		"[fiber]: ARM_CM33 SecureContext stack-top word moved");
_Static_assert(offsetof(FiberSecureContextRecord, owner_token) == 12u,
		"[fiber]: ARM_CM33 SecureContext owner word moved");
_Static_assert(sizeof(FiberSecureContextRecord) == 24u,
		"[fiber]: ARM_CM33 SecureContext record geometry changed");
_Static_assert(_Alignof(FiberSecureContextStackStorage) >=
		FIBER_ARM_CM33_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES,
		"[fiber]: ARM_CM33 SecureContext storage lost stack alignment");

static __attribute__((noreturn, noinline))
void fiber_secure_context_pool_fail_closed(void)
{
	__builtin_trap();
	for (;;) {
	}
}

static void fiber_secure_context_pool_clear_record(
		FiberSecureContextRecord * const record)
{
	record->current_stack_pointer = 0u;
	record->stack_limit = 0u;
	record->stack_top = 0u;
	record->owner_token = 0u;
	record->stack_bytes = 0u;
	record->allocation_state = fiber_secure_contextSTATE_FREE;
}

static void fiber_secure_context_pool_clear_stack(
		uint8_t * const stack_limit)
{
	uint32_t index;

	/* The dedicated linker section is intentionally NOLOAD. Do not rely on a
	 * generic C startup .bss loop to erase Secure metadata or old stack data. */
	for (index = 0u;
			index < (FIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES +
					FIBER_ARM_CM33_SECURE_CONTEXT_STACK_SEAL_BYTES);
			++index) {
		stack_limit[index] = 0u;
	}
}

static uint32_t fiber_secure_context_pool_record_is_free(
		const FiberSecureContextRecord * const record)
{
	return (record->current_stack_pointer == 0u) &&
			(record->stack_limit == 0u) &&
			(record->stack_top == 0u) &&
			(record->owner_token == 0u) &&
			(record->stack_bytes == 0u) &&
			(record->allocation_state == fiber_secure_contextSTATE_FREE);
}

static void fiber_secure_context_pool_write_stack_seal(
		uint8_t * const stack_limit,
		const uint32_t stack_bytes)
{
	uint32_t * const seal = (uint32_t *)(void *)(stack_limit + stack_bytes);

	seal[0] = FIBER_ARM_CM33_SECURE_CONTEXT_STACK_SEAL_VALUE;
	seal[1] = FIBER_ARM_CM33_SECURE_CONTEXT_STACK_SEAL_VALUE;
}

static uint32_t fiber_secure_context_pool_stack_seal_is_valid(
		const uint8_t * const stack_limit,
		const uint32_t stack_bytes)
{
	const uint32_t * const seal =
			(const uint32_t *)(const void *)(stack_limit + stack_bytes);

	return (seal[0] == FIBER_ARM_CM33_SECURE_CONTEXT_STACK_SEAL_VALUE) &&
			(seal[1] == FIBER_ARM_CM33_SECURE_CONTEXT_STACK_SEAL_VALUE);
}

static uint32_t fiber_secure_context_pool_record_is_valid(
		const uint32_t index)
{
	const FiberSecureContextRecord * const record =
			&fiber_secure_context_pool_records[index];
	const uintptr_t stack_limit =
			(uintptr_t)fiber_secure_context_pool_stacks[index].bytes;
	const uintptr_t stack_top = stack_limit + (uintptr_t)record->stack_bytes;

	if (record->allocation_state != fiber_secure_contextSTATE_ALLOCATED) {
		return 0u;
	}
	if ((record->owner_token == 0u) || (record->stack_bytes == 0u) ||
			(record->stack_bytes > FIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES) ||
			((record->stack_bytes %
					FIBER_ARM_CM33_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES) != 0u)) {
		return 0u;
	}
	if (((stack_limit | stack_top | record->current_stack_pointer) &
				(FIBER_ARM_CM33_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES - 1u)) != 0u) {
		return 0u;
	}
	if ((record->stack_limit != stack_limit) ||
			(record->stack_top != stack_top) ||
			(record->current_stack_pointer < stack_limit) ||
			(record->current_stack_pointer > stack_top)) {
		return 0u;
	}

	return fiber_secure_context_pool_stack_seal_is_valid(
			fiber_secure_context_pool_stacks[index].bytes,
			record->stack_bytes);
}

void fiber_secure_context_pool_boot_initialize(void)
{
	uint32_t index;

	/* This intentionally does not trust a retained NOLOAD marker. It is called
	 * only from Secure boot, so erasing all prior Secure stack contents is the
	 * correct reset behavior rather than an ordinary runtime reinitialization. */
	for (index = 0u; index < FIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT; ++index) {
		fiber_secure_context_pool_clear_record(
				&fiber_secure_context_pool_records[index]);
		fiber_secure_context_pool_clear_stack(
				fiber_secure_context_pool_stacks[index].bytes);
	}
	fiber_secure_context_pool_initialized = fiber_secure_contextPOOL_INITIALIZED;
}

FiberSecureContextHandle fiber_secure_context_pool_allocate(
		const uint32_t secure_stack_bytes,
		const uintptr_t owner_token)
{
	uint32_t index;
	uint32_t first_free = FIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT;
	FiberSecureContextRecord *record;
	uintptr_t stack_limit;
	uintptr_t stack_top;

	if (fiber_secure_context_pool_initialized !=
			fiber_secure_contextPOOL_INITIALIZED) {
		fiber_secure_context_pool_fail_closed();
	}
	if ((owner_token == 0u) || (secure_stack_bytes == 0u) ||
			(secure_stack_bytes > FIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES) ||
			((secure_stack_bytes %
					FIBER_ARM_CM33_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES) != 0u)) {
		return FIBER_SECURE_CONTEXT_HANDLE_INVALID;
	}

	for (index = 0u; index < FIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT; ++index) {
		record = &fiber_secure_context_pool_records[index];
		if (record->allocation_state == fiber_secure_contextSTATE_FREE) {
			if (!fiber_secure_context_pool_record_is_free(record)) {
				fiber_secure_context_pool_fail_closed();
			}
			if (first_free == FIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT) {
				first_free = index;
			}
		} else if (record->allocation_state == fiber_secure_contextSTATE_ALLOCATED) {
			if (!fiber_secure_context_pool_record_is_valid(index)) {
				fiber_secure_context_pool_fail_closed();
			}
			if (record->owner_token == owner_token) {
				return FIBER_SECURE_CONTEXT_HANDLE_INVALID;
			}
		} else {
			fiber_secure_context_pool_fail_closed();
		}
	}
	if (first_free == FIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT) {
		return FIBER_SECURE_CONTEXT_HANDLE_INVALID;
	}

	record = &fiber_secure_context_pool_records[first_free];
	stack_limit = (uintptr_t)fiber_secure_context_pool_stacks[first_free].bytes;
	stack_top = stack_limit + (uintptr_t)secure_stack_bytes;
	fiber_secure_context_pool_write_stack_seal(
			fiber_secure_context_pool_stacks[first_free].bytes,
			secure_stack_bytes);
	record->current_stack_pointer = stack_top;
	record->stack_limit = stack_limit;
	record->stack_top = stack_top;
	record->owner_token = owner_token;
	record->stack_bytes = secure_stack_bytes;
	record->allocation_state = fiber_secure_contextSTATE_ALLOCATED;

	if (!fiber_secure_context_pool_record_is_valid(first_free)) {
		fiber_secure_context_pool_fail_closed();
	}
	return (FiberSecureContextHandle)(first_free + 1u);
}

FiberSecureContextRecord *fiber_secure_context_pool_lookup_owned(
		const FiberSecureContextHandle handle,
		const uintptr_t owner_token)
{
	const uint32_t index = (uint32_t)(handle - 1u);
	FiberSecureContextRecord * const record =
			((handle != FIBER_SECURE_CONTEXT_HANDLE_INVALID) &&
				(handle <= FIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT))
			? &fiber_secure_context_pool_records[index]
			: 0;

	if (fiber_secure_context_pool_initialized !=
			fiber_secure_contextPOOL_INITIALIZED) {
		fiber_secure_context_pool_fail_closed();
	}
	if ((record == 0) || (owner_token == 0u)) {
		return 0;
	}
	if (record->allocation_state == fiber_secure_contextSTATE_FREE) {
		if (!fiber_secure_context_pool_record_is_free(record)) {
			fiber_secure_context_pool_fail_closed();
		}
		return 0;
	}
	if ((record->allocation_state != fiber_secure_contextSTATE_ALLOCATED) ||
			!fiber_secure_context_pool_record_is_valid(index)) {
		fiber_secure_context_pool_fail_closed();
	}
	if (record->owner_token != owner_token) {
		return 0;
	}

	return record;
}

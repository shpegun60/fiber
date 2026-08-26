#include <stdint.h>

#include "fiber_secure_context_pool.h"

static volatile uint32_t fiber_arm_cm33_secure_context_pool_probe_word;

void fiber_arm_cm33_secure_context_pool_probe(void)
{
	FiberSecureContextHandle first;
	FiberSecureContextHandle second;
	FiberSecureContextRecord *first_record;
	FiberSecureContextRecord *second_record;

	fiber_secure_context_pool_boot_initialize();
	first = fiber_secure_context_pool_allocate(64u, (uintptr_t)0x20000040u);
	second = fiber_secure_context_pool_allocate(128u, (uintptr_t)0x20000080u);
	first_record = fiber_secure_context_pool_lookup_owned(first,
			(uintptr_t)0x20000040u);
	second_record = fiber_secure_context_pool_lookup_owned(second,
			(uintptr_t)0x20000080u);

	if ((first == FIBER_SECURE_CONTEXT_HANDLE_INVALID) ||
			(second == FIBER_SECURE_CONTEXT_HANDLE_INVALID) ||
			(first_record == 0) || (second_record == 0) ||
			(first_record->stack_bytes != 64u) ||
			(second_record->stack_bytes != 128u) ||
			(first_record->current_stack_pointer != first_record->stack_top) ||
			(second_record->current_stack_pointer != second_record->stack_top) ||
			(fiber_secure_context_pool_allocate(64u,
					(uintptr_t)0x20000040u) !=
				FIBER_SECURE_CONTEXT_HANDLE_INVALID) ||
			(fiber_secure_context_pool_allocate(
					FIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES + 8u,
					(uintptr_t)0x200000C0u) !=
				FIBER_SECURE_CONTEXT_HANDLE_INVALID) ||
			(fiber_secure_context_pool_lookup_owned(first,
					(uintptr_t)0x20000080u) != 0)) {
		__builtin_trap();
	}

	fiber_arm_cm33_secure_context_pool_probe_word =
			first ^ second ^ first_record->stack_bytes ^ second_record->stack_bytes;
}

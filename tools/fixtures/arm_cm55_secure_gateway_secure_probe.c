#include <stdint.h>

#include "fiber_secure_gateway_abi.h"
#include "fiber_secure_context_gateway_abi.h"
#include "fiber_secure_context_pool.h"

static volatile uint32_t fiber_arm_cm55_secure_gateway_probe_word;

void Reset_Handler(void)
{
	/* Secure-only link-retention probe, not Non-secure runtime activation. */
	if (fiber_secure_context_pool_boot_initialize() != 1u) {
		__builtin_trap();
	}
	const FiberSecureContextHandle handle = fiber_secure_context_pool_allocate(
			64u, (uintptr_t)0x20000040u);
	const FiberSecureContextRecord * const record =
			fiber_secure_context_pool_lookup_owned(handle,
					(uintptr_t)0x20000040u);
	if ((handle == FIBER_SECURE_CONTEXT_HANDLE_INVALID) || (record == 0)) {
		__builtin_trap();
	}
	fiber_arm_cm55_secure_gateway_probe_word =
			handle ^ record->stack_bytes ^
			fiber_secure_gateway_c55s_v1_abi_version() ^
			fiber_secure_gateway_c55s_v1_context_port_id() ^
			fiber_secure_gateway_c55s_v1_context_layout_version() ^
			fiber_secure_gateway_c55s_v1_context_feature_mask() ^
			fiber_secure_context_gateway_c55s_v1_abi_version() ^
			fiber_secure_context_gateway_c55s_v1_stack_alignment() ^
			fiber_secure_context_gateway_c55s_v1_max_stack_bytes() ^
			fiber_secure_context_gateway_c55s_v1_max_contexts() ^
			fiber_secure_context_gateway_c55s_v1_initialize() ^
			fiber_secure_context_gateway_c55s_v1_allocate(
					64u, (uintptr_t)0x20000040u) ^
			fiber_secure_context_gateway_c55s_v1_load(
					1u, (uintptr_t)0x20000040u) ^
			fiber_secure_context_gateway_c55s_v1_save(
					1u, (uintptr_t)0x20000040u);

	for (;;) {
		__asm volatile ("wfe");
	}
}

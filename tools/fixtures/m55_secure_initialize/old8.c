/* Frozen old C55S-v1 provider: deliberately no initializer, no live ABI headers. */
#include <stdint.h>
#define NSC __attribute__((cmse_nonsecure_entry, used, noinline))
NSC uint32_t fiber_secure_gateway_c55s_v1_abi_version(void) { return 1; }
NSC uint32_t fiber_secure_gateway_c55s_v1_context_port_id(void) { return 0x43353553; }
NSC uint32_t fiber_secure_gateway_c55s_v1_context_layout_version(void) { return 0x10001; }
NSC uint32_t fiber_secure_gateway_c55s_v1_context_feature_mask(void) { return 0x8a; }
NSC uint32_t fiber_secure_context_gateway_c55s_v1_abi_version(void) { return 1; }
NSC uint32_t fiber_secure_context_gateway_c55s_v1_stack_alignment(void) { return 8; }
NSC uint32_t fiber_secure_context_gateway_c55s_v1_max_stack_bytes(void) { return 128; }
NSC uint32_t fiber_secure_context_gateway_c55s_v1_max_contexts(void) { return 3; }

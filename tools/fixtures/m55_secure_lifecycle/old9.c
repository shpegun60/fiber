/* Frozen initializer-era C55S v1 import provider. Link-only, no live headers. */
#include <stdint.h>
#define ENTRY __attribute__((cmse_nonsecure_entry,used,noinline))
ENTRY uint32_t fiber_secure_gateway_c55s_v1_abi_version(void) { return 1; }
ENTRY uint32_t fiber_secure_gateway_c55s_v1_context_port_id(void) { return 0x43353553; }
ENTRY uint32_t fiber_secure_gateway_c55s_v1_context_layout_version(void) { return 0x10001; }
ENTRY uint32_t fiber_secure_gateway_c55s_v1_context_feature_mask(void) { return 0x8a; }
ENTRY uint32_t fiber_secure_context_gateway_c55s_v1_abi_version(void) { return 1; }
ENTRY uint32_t fiber_secure_context_gateway_c55s_v1_stack_alignment(void) { return 8; }
ENTRY uint32_t fiber_secure_context_gateway_c55s_v1_max_stack_bytes(void) { return 128; }
ENTRY uint32_t fiber_secure_context_gateway_c55s_v1_max_contexts(void) { return 3; }
ENTRY uint32_t fiber_secure_context_gateway_c55s_v1_initialize(void) { return 1; }

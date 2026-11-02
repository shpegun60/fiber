/* Explicit same-state NS test doubles: not Secure gateway implementations.
 * Production attachment is unchanged. Real SG queries have a separate positive. */
#include <stdint.h>
#include "fixture.h"
extern void fixture_disturb(uint32_t field);
static uint32_t query(uint32_t index, uint32_t value)
{
    const uint32_t n = fixture_case;
    require_query(index);
    if (n >= 100u && n < 108u && n-100u == index) {
        if (index == 6u) { return 0u; }
        if (index == 7u) { return 7u; }
        return value ^ 1u;
    }
    if (index == 7u && n == 108u) { return 0u; }
    if (index == 7u && n == 109u) { return 129u; }
    if (n >= 200u && n < 248u && (n-200u)/6u == index) {
        fixture_disturb((n-200u)%6u);
    }
    return value;
}
uint32_t fiber_secure_gateway_c55s_v1_abi_version(void) { return query(0, 1); }
uint32_t fiber_secure_gateway_c55s_v1_context_port_id(void) { return query(1, 0x43353553); }
uint32_t fiber_secure_gateway_c55s_v1_context_layout_version(void) { return query(2, 0x10001); }
uint32_t fiber_secure_gateway_c55s_v1_context_feature_mask(void) { return query(3, 0x8a); }
uint32_t fiber_secure_context_gateway_c55s_v1_abi_version(void) { return query(4, 1); }
uint32_t fiber_secure_context_gateway_c55s_v1_stack_alignment(void) { return query(5, 8); }
uint32_t fiber_secure_context_gateway_c55s_v1_max_contexts(void) { return query(6, 3); }
uint32_t fiber_secure_context_gateway_c55s_v1_max_stack_bytes(void) { return query(7, 128); }

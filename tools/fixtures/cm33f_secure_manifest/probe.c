/* Explicit staged-only providers and read-query doubles. No forward ABI
 * operations, runtime bundle, handler, pool or Secure lifecycle is supplied. */
#include "fiber_portmacro.h"
#include "fiber_port_boot.h"
#include "fiber_port_secure_context_gateway_abi.h"
#include "fiber_port_secure_gateway_abi.h"
#include "fiber/fiber_runtime_port_abi.h"
#include "fiber/fiber_runtime_context_configuration_abi.h"

#ifndef FIXTURE_OMIT_COHORT
FIBER_PORT_CONTEXT_COHORT_DEFINE();
#endif
#ifndef FIXTURE_OMIT_REVERSE
const unsigned char fiber_internal_runtime_port_abi_v1_anchor = 1;
#endif
const unsigned char fiber_internal_runtime_context_configuration_abi_v1_anchor = 1;
volatile uint32_t fixture_closed, fixture_query_index, fixture_query_value;
volatile uint32_t fixture_query_count;

/* Freestanding library support, not a port operation. Production integration
 * must likewise provide instrumentation-safe, general-register implementations
 * when GCC lowers aggregate boot-record initialization/copy to these calls. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void *memcpy(void *destination, const void *source, size_t count)
{
    unsigned char *d=destination;
    const unsigned char *s=source;
    for(size_t i=0; i<count; ++i) {d[i]=s[i];}
    return destination;
}
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void *memset(void *destination, int value, size_t count)
{
    unsigned char *d=destination;
    for(size_t i=0; i<count; ++i) {d[i]=(unsigned char)value;}
    return destination;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_runtime_require_context_configuration_open(const FiberContext *ctx)
{
    FIBER_REQUIRE(ctx != 0, 'n');
    FIBER_REQUIRE(fixture_closed == 0, 'k');
}
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_ram(uintptr_t lo, uintptr_t hi)
{
    return lo >= 0x20000000u && hi <= 0x20040000u && hi > lo;
}
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_code(uintptr_t address)
{
    return address >= 0x08000000u && address < 0x08040000u;
}
FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_panic(char code)
{
    (void)code;
    for (;;) { __asm volatile("udf #71"); }
}
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fixture_task(void *arg)
{
    __asm volatile("" :: "r"(arg) : "memory");
}
static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fixture_query(uint32_t number, uint32_t value)
{
    fixture_query_count++;
    return fixture_query_index == number ? fixture_query_value : value;
}
#define QUERY(name, index, value) \
    FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY \
    uint32_t name(void) { return fixture_query(index, value); }
QUERY(fiber_secure_gateway_c3fs_v1_abi_version, 1, 1u)
QUERY(fiber_secure_gateway_c3fs_v1_context_port_id, 2, 0x43334653u)
QUERY(fiber_secure_gateway_c3fs_v1_context_layout_version, 3, 0x00010001u)
QUERY(fiber_secure_gateway_c3fs_v1_context_feature_mask, 4, 0x8Bu)
QUERY(fiber_secure_context_gateway_c3fs_v1_abi_version, 5, 1u)
QUERY(fiber_secure_context_gateway_c3fs_v1_stack_alignment, 6, 8u)
QUERY(fiber_secure_context_gateway_c3fs_v1_max_contexts, 7, 3u)
QUERY(fiber_secure_context_gateway_c3fs_v1_max_stack_bytes, 8, 256u)

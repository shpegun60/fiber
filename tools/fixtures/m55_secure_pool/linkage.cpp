#include <stddef.h>
#include <stdint.h>

#include "fiber/fiber_api_attributes.h"
#include "fiber_secure_context_pool.h"

static_assert(sizeof(FiberSecureContextRecord) == 24u, "record size");
static_assert(offsetof(FiberSecureContextRecord, current_stack_pointer) == 0u,
        "PSP offset");
static_assert(offsetof(FiberSecureContextRecord, stack_limit) == 4u,
        "limit offset");
static_assert(offsetof(FiberSecureContextRecord, stack_top) == 8u,
        "top offset");
static_assert(offsetof(FiberSecureContextRecord, owner_token) == 12u,
        "owner offset");
static_assert(offsetof(FiberSecureContextRecord, stack_bytes) == 16u,
        "size offset");
static_assert(offsetof(FiberSecureContextRecord, allocation_state) == 20u,
        "state offset");

extern "C" {

extern const uint32_t m55_pool_geometry[] __attribute__((used)) = {
    FIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT,
    FIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES,
    sizeof(FiberSecureContextRecord),
    FIBER_ARM_CM55_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES,
    FIBER_ARM_CM55_SECURE_CONTEXT_STACK_SEAL_BYTES,
    FIBER_ARM_CM55_SECURE_CONTEXT_STACK_SEAL_VALUE
};

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t m55_pool_cpp_initialize(void)
{
    return fiber_secure_context_pool_boot_initialize();
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t m55_pool_cpp_allocate(uint32_t bytes, uintptr_t owner)
{
    return fiber_secure_context_pool_allocate(bytes, owner);
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberSecureContextRecord *m55_pool_cpp_lookup(uint32_t handle, uintptr_t owner)
{
    return fiber_secure_context_pool_lookup_owned(handle, owner);
}

}

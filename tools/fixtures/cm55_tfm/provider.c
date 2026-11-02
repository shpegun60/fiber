#include "tfm_v2_boundary.h"
#include <stddef.h>
uint32_t tfm_ns_interface_init(void)
{
    return os_wrapper_mutex_create() != NULL ? 0u : UINT32_MAX;
}
/* Model TF-M references explicitly, including the mutex calls not used at init. */
__attribute__((used, section(".proof_roots")))
static const uintptr_t tfm_mutex_roots[] = {
    (uintptr_t)os_wrapper_mutex_acquire, (uintptr_t)os_wrapper_mutex_release,
    (uintptr_t)os_wrapper_mutex_delete
};
int fiber_addr_plausible_ram(uintptr_t start, uintptr_t end)
{ return start >= 0x20000000u && end <= 0x20010000u && start < end; }
int fiber_addr_plausible_code(uintptr_t address)
{ return (address & ~(uintptr_t)1u) >= 0x08000000u && address < 0x08100000u; }

#include "fiber_port_boot.h"

static_assert(sizeof(FiberPortBoot) == 88u, "boot record");
static_assert(sizeof(FiberPortProtectedContext) == 216u, "54-word backing");

/* Compile the actual private API as C++, then retain relocations to its C
 * definitions. This fixture does not define any operation or provider. */
extern "C" {
__attribute__((used, section(".fixture_boot_linkage")))
extern const uintptr_t constructor_fixture_cpp_symbols[] = {
    (uintptr_t)&fiber_port_context_init,
    (uintptr_t)&fiber_port_mpu_load_linker_layout,
    (uintptr_t)&fiber_port_mpu_linker_layout_check,
    (uintptr_t)&fiber_port_mpu_try_encode_exact_region,
    (uintptr_t)&fiber_port_mpu_build_global_regions,
    (uintptr_t)&fiber_port_context_compute_seal,
    (uintptr_t)&fiber_port_context_seal_check,
    (uintptr_t)&fiber_port_context_validate_initial_restore,
    (uintptr_t)&fiber_port_fpu_prepare,
    (uintptr_t)&fiber_port_fpu_require_configured,
    (uintptr_t)&fiber_port_fpu_require_ready
};
}

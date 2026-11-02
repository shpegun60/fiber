#include "fiber_portmacro.h"

/* A declaration-only marker lets the runner remove the actual expanded
 * sensitive bundle from one preprocessed helper, retaining its target. */
FIBER_API_ATTR_INLINE_SENSITIVE void inline_cpu_attribute_marker(void);

#ifdef __cplusplus
extern "C" {
#endif

#define INLINE_CPU_WRAPPERS(suffix, target) \
FIBER_API_ATTR_SENSITIVE target \
uint32_t inline_cpu_read_r9##suffix(void) { return fiber_port_read_r9(); } \
FIBER_API_ATTR_SENSITIVE target \
uint32_t inline_cpu_basepri_read##suffix(void) { return fiber_port_basepri_read(); } \
FIBER_API_ATTR_SENSITIVE target \
void inline_cpu_basepri_write##suffix(uint32_t value) { fiber_port_basepri_write(value); } \
FIBER_API_ATTR_SENSITIVE target \
uintptr_t inline_cpu_vectors_base_addr##suffix(void) { return fiber_port_vectors_base_addr(); } \
FIBER_API_ATTR_SENSITIVE target \
const uint32_t *inline_cpu_vectors_base_ptr##suffix(void) { return fiber_port_vectors_base_ptr(); } \
FIBER_API_ATTR_SENSITIVE target \
uint32_t inline_cpu_read_vector_slot##suffix(uint32_t index) { return fiber_port_read_vector_slot(index); } \
FIBER_API_ATTR_SENSITIVE target \
uint32_t inline_cpu_read_initial_msp##suffix(void) { return fiber_port_read_initial_msp(); } \
FIBER_API_ATTR_SENSITIVE target \
uint32_t inline_cpu_exc_return_is_valid##suffix(uint32_t value) { return fiber_port_exc_return_is_valid(value); }

INLINE_CPU_WRAPPERS(, FIBER_GENERAL_REGS_ONLY)
INLINE_CPU_WRAPPERS(_ordinary, )

#ifdef __cplusplus
}
#endif

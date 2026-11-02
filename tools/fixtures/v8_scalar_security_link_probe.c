/* Link-only CM33 component identity proof; never a board image. */
#include "fiber/fiber_api_attributes.h"
#include "fiber_port_secure_context_gateway_abi.h"
#include "fiber_port_secure_gateway_abi.h"
#include <stddef.h>
#include <stdint.h>

extern void fiber_portable_application_fixture(void) __attribute__((noreturn));
void Default_Handler(void) { for (;;) __asm volatile("wfe"); }
void SVC_Handler(void) __attribute__((weak, alias("Default_Handler")));
void PendSV_Handler(void) __attribute__((weak, alias("Default_Handler")));
void Reset_Handler(void) { fiber_portable_application_fixture(); }
__attribute__((used, section(".isr_vector"), aligned(128)))
const uintptr_t vectors[16] = {
    [0] = 0x2000FF00, [1] = (uintptr_t)Reset_Handler,
    [11] = (uintptr_t)SVC_Handler, [14] = (uintptr_t)PendSV_Handler
};
FIBER_SCHEDULER_HOOK_ATTR
int fiber_addr_plausible_ram(uintptr_t a, uintptr_t b) { return a && b > a; }
FIBER_SCHEDULER_HOOK_ATTR
int fiber_addr_plausible_code(uintptr_t a) { return a != 0; }
FIBER_SCHEDULER_HOOK_ATTR
void *memcpy(void *d, const void *s, size_t n) {
    unsigned char *out = d; const unsigned char *in = s;
    for (size_t i = 0; i < n; ++i) out[i] = in[i];
    return d;
}
FIBER_SCHEDULER_HOOK_ATTR
void *memset(void *d, int v, size_t n) {
    unsigned char *out = d;
    for (size_t i = 0; i < n; ++i) out[i] = (unsigned char)v;
    return d;
}
/* Secure image behavior is irrelevant to link identity. Keep unresolved
 * dependency checks strict without claiming this stubbed image executes. */
uint32_t fiber_secure_gateway_v1_abi_version(void) { return 1; }
uint32_t fiber_secure_gateway_v1_context_port_id(void) { return 0; }
uint32_t fiber_secure_gateway_v1_context_layout_version(void) { return 0; }
uint32_t fiber_secure_gateway_v1_context_feature_mask(void) { return 0; }
uint32_t fiber_secure_context_gateway_v1_abi_version(void) { return 1; }
uint32_t fiber_secure_context_gateway_v1_stack_alignment(void) { return 8; }
uint32_t fiber_secure_context_gateway_v1_max_stack_bytes(void) { return 256; }
uint32_t fiber_secure_context_gateway_v1_max_contexts(void) { return 3; }
uint32_t fiber_secure_context_gateway_v1_initialize(void) { return 1; }
uint32_t fiber_secure_context_gateway_v1_allocate(uint32_t n, uintptr_t owner) { (void)n; (void)owner; return 1; }
uint32_t fiber_secure_context_gateway_v1_load(uint32_t h, uintptr_t owner) { (void)h; (void)owner; return 1; }
uint32_t fiber_secure_context_gateway_v1_save(uint32_t h, uintptr_t owner) { (void)h; (void)owner; return 1; }

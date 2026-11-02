/* CPU-only guard probes. These bridges do not model a scheduler or MPU. */
#include "fiber_port_private.h"
#include "fiber/fiber_runtime_port_abi.h"

FiberContext audit_context;
volatile uintptr_t audit_raw_begin = 0x20010000u;
volatile uintptr_t audit_raw_end = 0x20010200u;
volatile uintptr_t audit_allowed_begin = 0x20010000u;
volatile uintptr_t audit_allowed_end = 0x20020000u;
volatile uint32_t audit_pressure[8] = {1, 2, 3, 4, 5, 6, 7, 8};

#if AUDIT_MPU
fiber_portUNPRIVILEGED_FUNCTION
#endif
void audit_entry(void *arg) { (void)arg; }

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_panic(char code)
{
    (void)code;
    for (;;) { __asm volatile("nop"); }
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_task_return(void)
{
    for (;;) { __asm volatile("nop"); }
}

const unsigned char fiber_internal_runtime_port_abi_v1_anchor = 1;
__attribute__((section(".fiber_port_current_context_slot")))
FiberContext *fiber_internal_runtime_current_context_slot;

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_internal_runtime_select_scheduler_candidate(FiberContext *current)
{ return current; }
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_runtime_publish_current_context(FiberContext *next)
{ fiber_internal_runtime_current_context_slot = next; }
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_runtime_require_current_context(void) { }

#if !AUDIT_MPU
FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_ram(uintptr_t begin, uintptr_t end)
{
    const uintptr_t context = (uintptr_t)&audit_context;
    return end > begin &&
        ((begin >= context && end <= context + sizeof(audit_context)) ||
         (begin >= audit_allowed_begin && end <= audit_allowed_end) ||
         (begin >= 0x2003F000u && end <= 0x20040000u));
}
FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_code(uintptr_t address)
{ return address >= 0x08000000u && address < 0x08020000u; }
#endif

/* Volatile locals stay live across the actual constructor and validator. No
 * fixed-r9 or global-register-variable options are used for these call chains. */
__attribute__((noinline)) void audit_init(void)
{
    uint32_t a = audit_pressure[0], b = audit_pressure[1];
    uint32_t c = audit_pressure[2], d = audit_pressure[3];
    uint32_t e = audit_pressure[4], f = audit_pressure[5];
    uint32_t g = audit_pressure[6], h = audit_pressure[7];
    fiber_port_context_init(&audit_context, (void *)audit_raw_begin,
        (void *)audit_raw_end, audit_entry, (void *)0x12345678u);
    audit_pressure[0] = a ^ b ^ c ^ d ^ e ^ f ^ g ^ h;
}

__attribute__((noinline)) void audit_validate(void)
{
    uint32_t a = audit_pressure[0], b = audit_pressure[1];
    uint32_t c = audit_pressure[2], d = audit_pressure[3];
    uint32_t e = audit_pressure[4], f = audit_pressure[5];
    uint32_t g = audit_pressure[6], h = audit_pressure[7];
#if AUDIT_MPU
    fiber_port_context_validate_initial_restore(&audit_context);
#else
    fiber_port_context_validate_save_current(&audit_context);
#endif
    audit_pressure[1] = a ^ b ^ c ^ d ^ e ^ f ^ g ^ h;
}

/* LTO can introduce these calls after its initial reachability pass. Keep the
 * freestanding implementations available through final native lowering. */
__attribute__((used, externally_visible))
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void *memcpy(void *to, const void *from, size_t count)
{
    unsigned char *dst = to;
    const unsigned char *src = from;
    while (count-- != 0u) { *dst++ = *src++; }
    return to;
}
__attribute__((used, externally_visible))
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void *memset(void *to, int value, size_t count)
{
    unsigned char *dst = to;
    while (count-- != 0u) { *dst++ = (unsigned char)value; }
    return to;
}

#if AUDIT_MPU
__attribute__((used, section(".isr_vector"), aligned(128)))
const uintptr_t audit_vector_table[fiber_portVECTOR_STORAGE_WORDS] = {
    [0] = 0x20040000u, [11] = (uintptr_t)SVC_Handler,
    [14] = (uintptr_t)PendSV_Handler
};
#else
extern const unsigned audit_override_anchor;
uintptr_t audit_fallback_result(void)
{ return fiber_fallback_initial_msp() + audit_override_anchor; }
#endif

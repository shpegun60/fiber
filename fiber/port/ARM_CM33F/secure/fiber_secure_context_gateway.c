/* C3FS configured capacity and destructive, boot-only Secure initialization. */
#include "fiber_secure_context_gateway_abi.h"
#include "fiber_secure_context_cohort.h"
#include "fiber_secure_context_pool.h"

#define FIBER_C3FS_REG(address) (*(volatile uint32_t *)(address))
#define FIBER_C3FS_AIRCR FIBER_C3FS_REG(0xE000ED0Cu)
#define FIBER_C3FS_NSACR FIBER_C3FS_REG(0xE000ED8Cu)
#define FIBER_C3FS_FPCCR FIBER_C3FS_REG(0xE000EF34u)
#define FIBER_C3FS_FPCCR_NS FIBER_C3FS_REG(0xE002EF34u)
#define FIBER_C3FS_INITIALIZING 0x53464742u
#define FIBER_C3FS_READY 0x53464752u
#define FIBER_C3FS_BARRIERS() __asm volatile("dsb 0xf\n\tisb 0xf" ::: "memory")

/* Four normal startup-zeroed bytes, in addition to the pool's four bytes.
 * The NOLOAD image is not a substitute for either startup BSS obligation. */
static volatile uint32_t fiber_secure_context_gateway_state;
_Static_assert(sizeof(fiber_secure_context_gateway_state) == 4u,
        "[fiber]: C3FS gateway marker geometry changed");

static FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_secure_context_gateway_fail_closed(void)
{
    __builtin_trap();
    for (;;) {}
}
uint32_t fiber_secure_context_gateway_c3fs_v1_abi_version(void)
{
    fiber_secure_c3fs_query_preflight();
    FIBER_C3FS_PRIVATE_COHORT_RETAIN();
    return FIBER_ARM_CM33F_SECURE_CONTEXT_GATEWAY_ABI_VERSION;
}
uint32_t fiber_secure_context_gateway_c3fs_v1_stack_alignment(void)
{
    fiber_secure_c3fs_query_preflight();
    FIBER_C3FS_PRIVATE_COHORT_RETAIN();
    return FIBER_ARM_CM33F_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT;
}
uint32_t fiber_secure_context_gateway_c3fs_v1_max_stack_bytes(void)
{
    fiber_secure_c3fs_query_preflight();
    FIBER_C3FS_PRIVATE_COHORT_RETAIN();
    return FIBER_ARM_CM33F_SECURE_CONTEXT_MAX_STACK_BYTES;
}
uint32_t fiber_secure_context_gateway_c3fs_v1_max_contexts(void)
{
    fiber_secure_c3fs_query_preflight();
    FIBER_C3FS_PRIVATE_COHORT_RETAIN();
    return FIBER_ARM_CM33F_SECURE_CONTEXT_MAX_COUNT;
}

uint32_t fiber_secure_context_gateway_c3fs_v1_initialize(void)
{
    /* Capture the incoming caller kind before any helper can replace LR.
     * The inline preflight is integer-only; codegen must prove that the CMSE
     * prologue has not touched FP before it, in hard and softfp builds. */
    const uint32_t nonsecure_caller = __builtin_arm_cmse_nonsecure_caller();
    fiber_secure_c3fs_query_preflight();
    if (nonsecure_caller == 0u) {
        return 0u;
    }
    uint32_t exception_number, control, control_ns;
    __asm volatile("mrs %0, ipsr\n\tmrs %1, control\n\tmrs %2, control_ns" :
            "=r" (exception_number), "=r" (control), "=r" (control_ns) :: "memory");
    if ((exception_number !=
            FIBER_ARM_CM33F_SECURE_CONTEXT_GATEWAY_SVC_EXCEPTION_NUMBER) ||
            (fiber_secure_context_gateway_state != 0u) ||
            ((control & 0xDu) != 0u) || ((control_ns & 4u) != 0u) ||
            ((FIBER_C3FS_FPCCR | FIBER_C3FS_FPCCR_NS) & 1u) != 0u) {
        return 0u;
    }
    const uint32_t aircr = FIBER_C3FS_AIRCR;
    /* PRIS with BFHFNMINS is UNPREDICTABLE; routing belongs to integration. */
    if (((aircr & (1u << 13u)) != 0u) ||
            (fiber_secure_context_pool_boot_is_pristine() != 1u)) {
        return 0u;
    }
    FIBER_C3FS_PRIVATE_COHORT_RETAIN();
    fiber_secure_context_gateway_state = FIBER_C3FS_INITIALIZING;
    FIBER_C3FS_BARRIERS();
    if (fiber_secure_context_gateway_state != FIBER_C3FS_INITIALIZING) {
        fiber_secure_context_gateway_fail_closed();
    }
    const uint32_t expected_aircr = (aircr & ~0xFFFF4000u) | 0x05FA4000u;
    FIBER_C3FS_AIRCR = expected_aircr;
    FIBER_C3FS_BARRIERS();
    if ((FIBER_C3FS_AIRCR & 0xFFFFu) != (expected_aircr & 0xFFFFu)) {
        return 0u;
    }
    uint32_t limit, pointer;
    __asm volatile("msr psplim, %0\n\tmsr psp, %0" :: "r" (0u) : "memory");
    FIBER_C3FS_BARRIERS();
    __asm volatile("mrs %0, psplim\n\tmrs %1, psp" :
            "=r" (limit), "=r" (pointer) :: "memory");
    if ((limit != 0u) || (pointer != 0u) ||
            (fiber_secure_context_pool_boot_initialize() != 1u)) {
        return 0u;
    }
    /* SG is not exception entry. Handler uses MSP but banked SPSEL can read
     * two after MSR. Quiescent admission is required before clearing FPCA. */
    __asm volatile("msr control, %1\n\tisb 0xf\n\tmrs %0, control" :
            "=r" (control) : "r" (2u) : "memory");
    if (control != 2u) {
        return 0u;
    }
    /* Exact reference order: NSACR grant, unlock shared LSPEN policy, then
     * treat high FP state as Secure. Never grant Secure CPACR here or touch
     * NS CPACR/ASPEN. Preserve unrelated policy bits and verify owned bits. */
    const uint32_t nsacr = FIBER_C3FS_NSACR | 0xC00u;
    FIBER_C3FS_NSACR = nsacr;
    FIBER_C3FS_BARRIERS();
    if (FIBER_C3FS_NSACR != nsacr) {
        return 0u;
    }
    const uint32_t fpccr = FIBER_C3FS_FPCCR & ~(1u << 29u);
    FIBER_C3FS_FPCCR = fpccr;
    FIBER_C3FS_BARRIERS();
    if ((FIBER_C3FS_FPCCR & (1u << 29u)) != 0u) {
        return 0u;
    }
    FIBER_C3FS_FPCCR = fpccr | (1u << 26u);
    FIBER_C3FS_BARRIERS();
    /* Policy bits 31..26 are software-owned and stable under the boot
     * exclusivity contract. Status bits may change; LSPACT must stay clear. */
    if ((FIBER_C3FS_FPCCR & 0xFC000001u) !=
            ((fpccr | (1u << 26u)) & 0xFC000000u)) {
        return 0u;
    }
    fiber_secure_context_gateway_state = FIBER_C3FS_READY;
    FIBER_C3FS_BARRIERS();
    if (fiber_secure_context_gateway_state != FIBER_C3FS_READY) {
        fiber_secure_context_gateway_fail_closed();
    }
    return 1u;
}

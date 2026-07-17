/* --------------------------------------------------------------------------
 * fiber_port_exception.c - ARM_CM3 exception setup and validation
 *
 * Exception routing, priority, and vector checks are mandatory port behavior.
 * -------------------------------------------------------------------------- */

#include "../fiber_port_select.h"

#if FIBER_PORT_ARMV7M

#include "fiber_port_private.h"

#ifndef __NVIC_PRIO_BITS
#  error "__NVIC_PRIO_BITS must be defined by the CMSIS device header"
#endif /* __NVIC_PRIO_BITS */

_Static_assert(__NVIC_PRIO_BITS >= 2 && __NVIC_PRIO_BITS <= 8, "__NVIC_PRIO_BITS out of sane range");

static void fiber_require_privileged_thread_msp(void)
{
    const uint32_t control = __get_CONTROL();

    FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
    FIBER_REQUIRE((control & 1u) == 0u, 'v');
    FIBER_REQUIRE((control & 2u) == 0u, 's');
}

/* Small helpers to save/restore PRIMASK while tweaking SCB/NVIC */
__STATIC_FORCEINLINE uint32_t fiber_primask_save_disable(void) {
    uint32_t pm;
    __ASM volatile("mrs %0, primask \n"
                   "cpsid i         \n"
                   : "=r"(pm) :: "memory");
    { __DSB(); __ISB(); }
    return pm;
}

__STATIC_FORCEINLINE void fiber_primask_restore(uint32_t pm) {
    { __DSB(); __ISB(); }
    __ASM volatile("msr primask, %0" :: "r"(pm) : "memory");
    { __DSB(); __ISB(); }
}

/* Compute the lowest representable priority value for this MCU */
__STATIC_FORCEINLINE uint32_t fiber_lowest_prio_val(void) {
    return (1u << __NVIC_PRIO_BITS) - 1u;
}

__STATIC_FORCEINLINE uintptr_t fiber_handler_addr(void (*handler)(void)) {
    return (uintptr_t)handler;
}

__STATIC_FORCEINLINE uintptr_t fiber_strip_thumb_bit(uintptr_t addr) {
    return addr & ~(uintptr_t)1u;
}

/* Clear any pending PendSV before the port begins scheduling. */
__STATIC_FORCEINLINE void fiber_pendsv_clear_pending(void) {
#ifdef SCB_ICSR_PENDSVCLR_Msk
    SCB->ICSR = SCB_ICSR_PENDSVCLR_Msk;
#else
    /* Bit 27 is PENDSVCLR on M3/M4/M7/M33 according to ARMv7-M/ARMv8-M ARM */
    SCB->ICSR = (1UL << 27);
#endif
}

static void fiber_validate_vector_entry(uint32_t index, void (*expected)(void), char code)
{
    const uint32_t *const vectors = fiber_port_vectors_base_ptr();
    const uintptr_t actual = (uintptr_t)vectors[index];
    const uintptr_t expect = fiber_handler_addr(expected);

    FIBER_REQUIRE((actual & 1u) != 0u, code);
    FIBER_REQUIRE(fiber_strip_thumb_bit(actual) == fiber_strip_thumb_bit(expect), code);
}

static void fiber_validate_pendsv_priority(void)
{
    const uint32_t lowest = fiber_lowest_prio_val();
    const uint32_t rd = NVIC_GetPriority(PendSV_IRQn);

    FIBER_REQUIRE(rd == lowest, 'P');
}

static void fiber_validate_svc_priority(void)
{
    const uint32_t rd = NVIC_GetPriority(SVCall_IRQn);

    FIBER_REQUIRE(rd == 0u, 'w');
}

#if FIBER_PORT_HAS_BASEPRI
static uint8_t fiber_probe_implemented_priority_mask(void)
{
    volatile uint8_t *const first_user_priority = (volatile uint8_t *)0xE000E400u;
    const uint32_t pm = fiber_primask_save_disable();
    const uint8_t original_priority = *first_user_priority;

    *first_user_priority = 0xFFu;
    { __DSB(); __ISB(); __COMPILER_BARRIER(); }

    const uint8_t implemented_mask = *first_user_priority;

    *first_user_priority = original_priority;
    { __DSB(); __ISB(); __COMPILER_BARRIER(); }

    FIBER_REQUIRE(*first_user_priority == original_priority, 'Q');

    fiber_primask_restore(pm);

    return implemented_mask;
}

static uint32_t fiber_count_implemented_priority_bits(uint8_t implemented_mask)
{
    uint32_t implemented_bits = 0u;

    while ((implemented_mask & 0x80u) == 0x80u) {
        ++implemented_bits;
        implemented_mask = (uint8_t)(implemented_mask << 1u);
    }

    return implemented_bits;
}

static void fiber_validate_basepri_priority_mask(uint8_t implemented_mask)
{
    const uint32_t implemented_bits =
            fiber_count_implemented_priority_bits(implemented_mask);
    const uint8_t cmsis_mask = (uint8_t)(0xFFu << (8u - __NVIC_PRIO_BITS));

    FIBER_REQUIRE(implemented_mask != 0u, 'Q');
    FIBER_REQUIRE(implemented_mask == cmsis_mask, 'Q');
    FIBER_REQUIRE(implemented_bits == (uint32_t)__NVIC_PRIO_BITS, 'Q');
    FIBER_REQUIRE(((uint32_t)FIBER_PORT_SCHEDULER_BASEPRI & (uint32_t)implemented_mask) != 0u, 'Q');
    FIBER_REQUIRE(((uint32_t)FIBER_PORT_SCHEDULER_BASEPRI & ~(uint32_t)implemented_mask) == 0u, 'q');

    if (implemented_bits == 8u) {
        FIBER_REQUIRE(((uint32_t)FIBER_PORT_SCHEDULER_BASEPRI & 1u) == 0u, 'g');
    }
}

static void fiber_validate_priority_grouping(uint8_t implemented_mask)
{
    const uint32_t implemented_bits =
            fiber_count_implemented_priority_bits(implemented_mask);
    uint32_t max_prigroup = 0u;

    FIBER_REQUIRE(implemented_bits != 0u, 'g');

    if (implemented_bits < 8u) {
        max_prigroup = 7u - implemented_bits;
    }

    max_prigroup = (max_prigroup << 8u) & (0x07u << 8u);
    FIBER_REQUIRE((SCB->AIRCR & (0x07u << 8u)) <= max_prigroup, 'g');
}
#endif /* FIBER_PORT_HAS_BASEPRI */

static void fiber_validate_feature_policy(void)
{
    (void)0;
}

void fiber_exception_runtime_check(void)
{
    FIBER_PORT_CONTEXT_COHORT_RETAIN();
    fiber_require_privileged_thread_msp();

    fiber_validate_feature_policy();

    fiber_validate_pendsv_priority();
    fiber_validate_svc_priority();

    fiber_validate_vector_entry(14u, PendSV_Handler, 'Y');
    fiber_validate_vector_entry(11u, SVC_Handler, 'y');

#if FIBER_PORT_HAS_BASEPRI
    const uint8_t implemented_mask = fiber_probe_implemented_priority_mask();

    fiber_validate_basepri_priority_mask(implemented_mask);
    fiber_validate_priority_grouping(implemented_mask);
#endif
}

/* --------------------------------------------------------------------------
 * Make PendSV the lowest priority. Safe on all Cortex-M used by STM32.
 * If TrustZone is used, CMSIS will route writes to the correct (S/NS) bank.
 * -------------------------------------------------------------------------- */
void fiber_pendsv_init_lowest_priority(void)
{
    fiber_require_privileged_thread_msp();
    FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
#if FIBER_PORT_HAS_BASEPRI
    FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
#endif
#if FIBER_PORT_HAS_FAULTMASK
    FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
#endif

    fiber_validate_feature_policy();

    const uint32_t pm = fiber_primask_save_disable();

    const uint32_t lowest = fiber_lowest_prio_val();

    /* Set PendSV to the absolute lowest preempt priority */
    NVIC_SetPriority(PendSV_IRQn, lowest);

    /* Match the FreeRTOS first-task start policy: SVCall is highest priority. */
    NVIC_SetPriority(SVCall_IRQn, 0u);

    { __DSB(); __ISB(); __COMPILER_BARRIER(); }

    /* Paranoid: clear any spurious pending PendSV that might have been latched */
    fiber_pendsv_clear_pending();

    /* Read back the exact right-justified CMSIS priority value. */
    {
        const uint32_t rd = NVIC_GetPriority(PendSV_IRQn);
        FIBER_REQUIRE(rd == lowest, 'P');
        const uint32_t rd_svc = NVIC_GetPriority(SVCall_IRQn);
        FIBER_REQUIRE(rd_svc == 0u, 'w');
    }

    fiber_primask_restore(pm);

    fiber_exception_runtime_check();
}

#endif /* FIBER_PORT_ARMV7M */

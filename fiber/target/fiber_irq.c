/* --------------------------------------------------------------------------
 * fiber_irq.c - configure PendSV priority for STM32/Cortex-M targets
 *
 * Knobs (optional):
 *   - FIBER_FORCE_PRIGROUP  : [-1..7]  -1 = don't touch grouping (default), otherwise set PRIGROUP
 *   - FIBER_TUNE_SYSTICK    : 0/1      also set SysTick to lowest (default 0)
 *   - FIBER_TUNE_SVCALL     : 0/1      optionally set SVCall to a fixed priority (default 0)
 *   - FIBER_SWITCH_STRICT_BARRIERS : 0/1 add extra DSB/ISB around sensitive writes (you already use it)
 * -------------------------------------------------------------------------- */

#include "mcu_core.h"
#include "fiber_irq.h"
#include "fiber_compiler.h"
#include "fiber_panic.h"

#ifndef FIBER_FORCE_PRIGROUP
#  define FIBER_FORCE_PRIGROUP   (-1)
#endif
#ifndef FIBER_TUNE_SYSTICK
#  define FIBER_TUNE_SYSTICK      0
#endif
#ifndef FIBER_TUNE_SVCALL
#  define FIBER_TUNE_SVCALL       0
#endif

#ifndef __NVIC_PRIO_BITS
#  error "__NVIC_PRIO_BITS must be defined by the CMSIS device header"
#endif /* __NVIC_PRIO_BITS */

_Static_assert(__NVIC_PRIO_BITS >= 2 && __NVIC_PRIO_BITS <= 8, "__NVIC_PRIO_BITS out of sane range");

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
}

/* Compute the lowest representable priority value for this MCU */
__STATIC_FORCEINLINE uint32_t fiber_lowest_prio_val(void) {
    return (1u << __NVIC_PRIO_BITS) - 1u;
}

/* Optional: clear a pending PendSV in case some genius set it earlier */
__STATIC_FORCEINLINE void fiber_pendsv_clear_pending(void) {
#ifdef SCB_ICSR_PENDSVCLR_Msk
    SCB->ICSR = SCB_ICSR_PENDSVCLR_Msk;
#else
    /* Bit 27 is PENDSVCLR on M3/M4/M7/M33 according to ARMv7-M/ARMv8-M ARM */
    SCB->ICSR = (1UL << 27);
#endif
}

/* --------------------------------------------------------------------------
 * Make PendSV the lowest priority. Safe on all Cortex-M used by STM32.
 * If TrustZone is used, CMSIS will route writes to the correct (S/NS) bank.
 * -------------------------------------------------------------------------- */
void fiber_pendsv_init_lowest_priority(void)
{
    const uint32_t pm = fiber_primask_save_disable();

#if FIBER_FORCE_PRIGROUP >= 0
    /* Optionally force PRIGROUP early. Caller should know what they're doing. */
    NVIC_SetPriorityGrouping((uint32_t)FIBER_FORCE_PRIGROUP);
    { __DSB(); __ISB(); __COMPILER_BARRIER(); }
#endif

    const uint32_t lowest = fiber_lowest_prio_val();

    /* Set PendSV to the absolute lowest preempt priority */
    NVIC_SetPriority(PendSV_IRQn, lowest);

#if FIBER_TUNE_SYSTICK
    /* Optional: also drop SysTick to the bottom to never preempt PendSV by accident */
    NVIC_SetPriority(SysTick_IRQn, lowest);
#endif

#if FIBER_TUNE_SVCALL
    /* Optional: set SVCall to a known priority (often above PendSV but below time-critical IRQs) */
    /* Choose 'lowest-1' if available, else just lowest. Hardware will mask extra bits anyway. */
    const uint32_t svc_prio = (lowest ? lowest - 1u : lowest);
    NVIC_SetPriority(SVCall_IRQn, svc_prio);
#endif

    { __DSB(); __ISB(); __COMPILER_BARRIER(); }

    /* Paranoid: clear any spurious pending PendSV that might have been latched */
    fiber_pendsv_clear_pending();

    /* Read-back verify. CMSIS returns right-justified priority; compare masked. */
    {
        const uint32_t rd = NVIC_GetPriority(PendSV_IRQn);
        FIBER_REQUIRE((rd & lowest) == lowest, 'P');  /* 'P' - PendSV priority not at lowest */
#if FIBER_TUNE_SYSTICK
        const uint32_t rd_stk = NVIC_GetPriority(SysTick_IRQn);
        FIBER_REQUIRE((rd_stk & lowest) == lowest, 'K'); /* 'K' - SysTick priority not at lowest */
#endif
    }

    fiber_primask_restore(pm);
}




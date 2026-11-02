#include "main.h"
#include "report.h"

#define REG(address) (*(volatile uint32_t *)(uintptr_t)(address))

static void mark_nonsecure(uint32_t mpc, uint32_t first, uint32_t end)
{
    const uint32_t shift = REG(mpc + 0x14u) + 5u;
    report_check(shift >= 5u && shift <= 12u, 101u);
    REG(mpc) = 0x10u;
    for (uint32_t block = first >> shift; block < (end >> shift); ++block) {
        REG(mpc + 0x18u) = block / 32u;
        REG(mpc + 0x1cu) |= 1u << (block % 32u);
    }
}

uint32_t fixture_secure_setup(void)
{
    /* AN505 IoTKit: code SSRAM MPC0 and the internal SRAM MPC. */
    mark_nonsecure(0x58007000u, 0x10000u, 0x30000u);
    mark_nonsecure(0x50083000u, 0x4000u, 0x8000u);
    SAU->RNR = 0u;
    SAU->RBAR = 0x00010000u;
    SAU->RLAR = 0x0002ffe1u;
    SAU->RNR = 1u;
    SAU->RBAR = 0x20004000u;
    SAU->RLAR = 0x20007fe1u;
    REG(0x50080014u) = 1u;
    SAU->CTRL = 1u;
    SCB->NSACR |= (3u << 10u);
    /* The production priority-width probe uses external IRQ0. Its NS priority
     * register is accessible only when the real target-state bit is NS. */
    NVIC->ITNS[0] |= 1u;
    __DSB(); __ISB();
    report_value("SECURE_NSACR", SCB->NSACR);
    report_check((SCB->NSACR & (3u << 10u)) == (3u << 10u), 102u);
    report_check((NVIC->ITNS[0] & 1u) != 0u, 103u);
    report_value("MODEL_MPU_TYPE", REG(0xe002ed90u));
    report_value("MODEL_MVFR0", REG(0xe002ef40u));
    volatile uint8_t *const priority = (volatile uint8_t *)(uintptr_t)0xe002e400u;
    const uint8_t saved = *priority;
    *priority = 0xffu;
    __DSB(); __ISB();
    const uint32_t mask = *priority;
    *priority = saved;
    __DSB(); __ISB();
    report_value("MODEL_PRIORITY_MASK", mask);
#ifdef EXEC_PROBE_ONLY
    report_exit(0u, "PASS:C3FP-MODEL-PROBE\n");
#endif
    REG(0xe002ed08u) = 0x00010000u;
    __TZ_set_CONTROL_NS(0u);
    __TZ_set_PSP_NS(0u);
    __TZ_set_PSPLIM_NS(0u);
    __TZ_set_MSPLIM_NS(0u);
    __DSB(); __ISB();
    return REG(0x00010004u);
}

__attribute__((noreturn)) void fixture_secure_fault(void)
{
    report_value("SECURE_CFSR", SCB->CFSR);
    report_value("SECURE_HFSR", SCB->HFSR);
    report_value("SECURE_SFSR", SAU->SFSR);
    report_exit(2u, "FAIL:C3FP-SECURE-BOOTSTRAP\n");
}

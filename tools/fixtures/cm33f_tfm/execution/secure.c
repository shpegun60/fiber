/* Test-only AN505 bootstrap, derived from the maintained C3FP execution fixture.
 * This grants NS memory/FP access; it is not a Secure TF-M implementation. */
#include "report.h"
#define REG(a) (*(volatile uint32_t *)(uintptr_t)(a))
static PROTECTED void mark_ns(uint32_t mpc, uint32_t begin, uint32_t end)
{
    const uint32_t shift = REG(mpc + 0x14u) + 5u;
    require_exec(shift >= 5u && shift <= 12u, 101u);
    REG(mpc) = 0x10u;
    for (uint32_t b = begin >> shift; b < (end >> shift); ++b) {
        REG(mpc + 0x18u) = b / 32u;
        REG(mpc + 0x1cu) |= 1u << (b % 32u);
    }
}
PROTECTED uint32_t fixture_secure_setup(void)
{
    mark_ns(0x58007000u, 0x10000u, 0x30000u);
    mark_ns(0x50083000u, 0x4000u, 0x8000u);
    REG(0xe000edd8u) = 0u; REG(0xe000eddcu) = 0x10000u; REG(0xe000ede0u) = 0x2ffe1u;
    REG(0xe000edd8u) = 1u; REG(0xe000eddcu) = 0x20004000u; REG(0xe000ede0u) = 0x20007fe1u;
    REG(0x50080014u) = 1u;
    REG(0xe000edd0u) = 1u;
    REG(0xe000ed8cu) |= 3u << 10u;
    REG(0xe000e380u) |= 1u;
    /* Allow the NS fixture to choose lazy/eager policy; no Secure FP task runs. */
    REG(0xe000ef34u) &= ~(1u << 29u);
    __asm volatile("dsb\nisb" ::: "memory");
    require_exec((REG(0xe000ed8cu) & (3u << 10u)) == (3u << 10u), 102u);
    REG(0xe002ed08u) = 0x10000u;
    __asm volatile("movs r0,#0\nmsr control_ns,r0\nmsr psp_ns,r0\nmsr psplim_ns,r0\nmsr msplim_ns,r0\ndsb\nisb"
                   ::: "r0", "memory");
    return REG(0x10004u);
}
FIBER_API_NORETURN PROTECTED void fixture_secure_fault(void)
{
    report_value("SECURE_CFSR", REG(0xe000ed28u));
    report_value("SECURE_HFSR", REG(0xe000ed2cu));
    report_value("SECURE_SFSR", REG(0xe000ede4u));
    report_exit(24u, "FAIL:C3FT-SECURE-BOOTSTRAP\n");
}

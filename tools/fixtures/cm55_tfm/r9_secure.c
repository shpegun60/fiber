#include "main.h"
#define REG(a) (*(volatile uint32_t *)(uintptr_t)(a))
__attribute__((noreturn, noipa, section(".text.r9_secure_main"))) void r9_secure_main(void)
{
    /* SSE-300 TCM attribution only; no TF-M, NSC entry or runtime service. */
    REG(0xe000ed08) = 0;
    SAU->RNR = 0; SAU->RBAR = 0x00010000; SAU->RLAR = 0x0001ffe1;
    SAU->RNR = 1; SAU->RBAR = 0x20010000; SAU->RLAR = 0x2001ffe1;
    REG(0x50080014) = 1;
    SAU->CTRL = 1;
    REG(0xe002ed08) = 0x00010000;
    NVIC->ITNS[0] |= 1u;
    __TZ_set_CONTROL_NS(0);
    __TZ_set_MSP_NS(0x20020000);
    __TZ_set_PSP_NS(0);
    __TZ_set_PSPLIM_NS(0);
    __TZ_set_MSPLIM_NS(0);
    __DSB(); __ISB();
    const uint32_t reset = *(const uint32_t *)0x00010004;
    __asm volatile("bxns %0" :: "r"(reset & ~1u) : "memory");
    for (;;) { __asm volatile("wfe"); }
}

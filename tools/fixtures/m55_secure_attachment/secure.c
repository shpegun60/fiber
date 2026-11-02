#include "report.h"

__attribute__((noreturn)) void attachment_fault_report(uint32_t exc_return, uint32_t ipsr)
{
    emit("FAULT:C55S-ATTACH:Secure EXC_RETURN="); hex(exc_return);
    emit(" IPSR="); hex(ipsr); emit("\n"); finish(91, "FAULT-EXIT\n");
}

__attribute__((noreturn)) void attachment_secure_main(void)
{
    REG(0xe000ed08) = 0;
    REG(0xe000edd8) = 0; REG(0xe000eddc) = 0x00010000; REG(0xe000ede0) = 0x0001ffe1;
    REG(0xe000edd8) = 1; REG(0xe000eddc) = 0x20010000; REG(0xe000ede0) = 0x2001ffe1;
    REG(0xe000edd8) = 2; REG(0xe000eddc) = 0x10008000; REG(0xe000ede0) = 0x10008fe3;
    REG(0x50080014) = 1;
    REG(0xe000edd0) = 1;
    REG(0xe002ed08) = 0x00010000;
    __TZ_set_CONTROL_NS(0);
    __TZ_set_MSP_NS(0x20020000);
    __TZ_set_PSPLIM_NS(0);
    __DSB(); __ISB();
    emit("START:C55S-ATTACH:Secure-M55\n");
    const uint32_t reset = *(const uint32_t *)0x00010004;
    __asm volatile("bxns %0" :: "r"(reset & ~1u) : "memory");
    for (;;) { __asm volatile("wfe"); }
}

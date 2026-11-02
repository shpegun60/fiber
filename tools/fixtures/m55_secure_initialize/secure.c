#include "report.h"
#include "fiber_secure_context_gateway_abi.h"
#include "fiber_secure_context_pool.h"

/* Debugger-triggered platform-policy setup. A Secure CPU STR is required:
 * debugger MMIO transactions need not carry the executing CPU's attribution.
 * This is not exported through CMSE and is never called by production. */
__attribute__((naked, used)) void init_fixture_policy_store(void)
{
    __asm volatile("str r0, [r1]\n\tbx lr");
}
__attribute__((naked, used)) void init_fixture_mask_store(void)
{
    __asm volatile("msr primask, r0\n\tmsr basepri, r1\n\tmsr faultmask, r2\n\tbx lr");
}
__attribute__((naked, used)) void init_fixture_register_offset_store(void)
{
    __asm volatile("str r0, [r1, r2]\n\tbx lr");
}
__attribute__((naked, used)) void init_fixture_unrecognized_store(void)
{
    __asm volatile("strt r0, [r1]\n\tbx lr");
}

extern unsigned char __pool_start[], __pool_end[];
static volatile uint32_t secure_rejected;

CHECKPOINT void init_fixture_secure_rejected(void) { __asm volatile("nop" ::: "memory"); }

void init_secure_svc(void)
{
    require(__get_IPSR() == 11u, 1);
    const uint32_t before_control = __get_CONTROL();
    const uint32_t before_aircr = REG(0xe000ed0c);
    const uint32_t before_primask = __get_PRIMASK(), before_basepri = __get_BASEPRI();
    const uint32_t before_faultmask = __get_FAULTMASK();
    require(fiber_secure_context_gateway_c55s_v1_initialize() == 0u, 2);
    require(__get_CONTROL() == before_control && REG(0xe000ed0c) == before_aircr &&
            __get_PRIMASK() == before_primask && __get_BASEPRI() == before_basepri &&
            __get_FAULTMASK() == before_faultmask && __get_PSP() == 0x30006000u &&
            __get_PSPLIM() == 0x30005000u, 3);
    for (uint32_t i=0; i<480; ++i) { require(((volatile unsigned char *)__pool_start)[i] == 0xa5, 4); }
    secure_rejected = 1;
    init_fixture_secure_rejected();
    emit("PASS:C55S-INITIALIZE:direct-Secure-SVC-rejected\n");
}

__attribute__((noreturn)) void init_fault_report(const uint32_t *frame, uint32_t exc_return)
{
    emit("FAULT:C55S-INITIALIZE PC="); hex(frame[6]);
    emit(" CFSR="); hex(REG(0xe000ed28)); emit(" HFSR="); hex(REG(0xe000ed2c));
    emit(" IPSR="); hex(__get_IPSR()); emit(" EXC_RETURN="); hex(exc_return);
    emit(" FRAME="); hex((uint32_t)(uintptr_t)frame); emit(" XPSR="); hex(frame[7]);
    emit("\n"); finish(42, "FAULT-EXIT:C55S-INITIALIZE\n");
}

__attribute__((noreturn)) void init_secure_main(void)
{
    require((uintptr_t)__pool_end-(uintptr_t)__pool_start == 480u, 5);
    for (uint32_t i=0; i<480; ++i) { ((volatile unsigned char *)__pool_start)[i] = 0xa5; }
    REG(0xe000ed08)=0;
    REG(0xe000ed24) |= 1u<<18;
    REG(0xe000ed0c)=0x05fa0500u;
    __set_PSPLIM(0x30005000u); __set_PSP(0x30006000u);
    __DSB(); __ISB();
    emit("START:C55S-INITIALIZE:Secure-M55\n");
    __asm volatile("svc #0" ::: "memory");
    require(secure_rejected == 1u, 6);
    /* SSE-300 TCM and its Secure alias. Attribution is fixture policy only. */
    REG(0xe000edd8)=0; REG(0xe000eddc)=0x00010000; REG(0xe000ede0)=0x0001ffe1;
    REG(0xe000edd8)=1; REG(0xe000eddc)=0x20010000; REG(0xe000ede0)=0x2001ffe1;
    REG(0xe000edd8)=2; REG(0xe000eddc)=0x10008000; REG(0xe000ede0)=0x10008fe3;
    REG(0x50080014)=1;
    REG(0xe000edd0)=1;
    REG(0xe002ed08)=0x00010000;
    __TZ_set_CONTROL_NS(0);
    __TZ_set_MSP_NS(0x20020000);
    __DSB(); __ISB();
    const uint32_t reset = *(const uint32_t *)0x00010004;
    __asm volatile("bxns %0" :: "r"(reset & ~1u) : "memory");
    for (;;) { __asm volatile("wfe"); }
}

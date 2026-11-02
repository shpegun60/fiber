#include "report.h"
#include "fiber_secure_context_gateway_abi.h"
#include "fiber_secure_context_pool.h"
extern unsigned char __pool_start[],__pool_end[];

__attribute__((naked,used)) void lifecycle_set_stacks(void)
{
    __asm volatile("msr psplim,r0\n\tmsr psp,r1\n\tbx lr");
}
__attribute__((naked,used)) void lifecycle_set_control(void)
{
    __asm volatile("msr control,r0\n\tisb 0xf\n\tbx lr");
}
__attribute__((naked,used)) void lifecycle_set_masks(void)
{
    __asm volatile("msr primask,r0\n\tmsr basepri,r1\n\tmsr faultmask,r2\n\tbx lr");
}
POINT void lifecycle_direct_done(void) { __asm volatile("nop" ::: "memory"); }
/* Entered only by the debugger while paused in Secure Handler mode. These
 * are genuine direct BL calls (odd incoming LR), not NSC fixture exports. */
POINT void lifecycle_direct_probe(void)
{
    require(fiber_secure_context_gateway_c55s_v1_allocate(64,0xd1)==0,1);
    require(fiber_secure_context_gateway_c55s_v1_load(0,0xd1)==0,2);
    require(fiber_secure_context_gateway_c55s_v1_save(0,0xd1)==0,3);
    lifecycle_direct_done();
    for(;;) { __asm volatile("wfe"); }
}
void lifecycle_secure_svc(void) { require(0,4); }
__attribute__((noreturn)) void lifecycle_fault_report(const uint32_t *frame,uint32_t ret)
{
    emit("FAULT:C55S-LIFECYCLE PC=");hex(frame[6]);
    emit(" CFSR=");hex(REG(0xe000ed28));emit(" HFSR=");hex(REG(0xe000ed2c));
    emit(" IPSR=");hex(__get_IPSR());emit(" EXC_RETURN=");hex(ret);
    emit(" FRAME=");hex((uint32_t)(uintptr_t)frame);emit(" XPSR=");hex(frame[7]);
    emit("\n");finish(42,"FAULT-EXIT:C55S-LIFECYCLE\n");
}
__attribute__((noreturn)) void lifecycle_secure_main(void)
{
    require((uintptr_t)__pool_end-(uintptr_t)__pool_start==480,5);
    for(uint32_t i=0;i<480;++i) { ((volatile unsigned char *)__pool_start)[i]=0xa5; }
    REG(0xe000ed08)=0;
    REG(0xe000ed24)|=1u<<18;
    REG(0xe000ed0c)=0x05fa0500;
    __set_PSPLIM(0);__set_PSP(0);
    emit("START:C55S-LIFECYCLE:Secure-M55\n");
    SAU->CTRL=0;
    SAU->RNR=0;SAU->RBAR=0x10000;SAU->RLAR=0x1ffe1;
    SAU->RNR=1;SAU->RBAR=0x20010000;SAU->RLAR=0x2001ffe1;
    SAU->RNR=2;SAU->RBAR=0x10008000;SAU->RLAR=0x10008fe3;
    REG(0x50080014)=1;SAU->CTRL=1;
    SCB_NS->VTOR=0x10000;
    __TZ_set_CONTROL_NS(0);__TZ_set_MSP_NS(0x20020000);
    __DSB();__ISB();
    const uint32_t target=REG(0x10004)&~1u;
    __asm volatile("bxns %0" :: "r"(target) : "memory");
    __builtin_unreachable();
}

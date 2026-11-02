#include "report.h"
#include "main.h"
#include "fiber_secure_context_gateway_abi.h"
extern unsigned char __pool_start[],__pool_end[];
CHECKPOINT void fixture_direct_done(void) { __asm volatile("nop" ::: "memory"); }
static COLD void mark_nonsecure(uint32_t mpc,uint32_t first,uint32_t end)
{
    const uint32_t shift=REG(mpc+0x14)+5;
    require(shift>=5 && shift<=12,1);
    REG(mpc)=0x10;
    for (uint32_t block=first>>shift; block<(end>>shift); ++block) {
        REG(mpc+0x18)=block/32;
        REG(mpc+0x1c)=REG(mpc+0x1c)|(1u<<(block%32));
    }
}
COLD void fixture_secure_svc(void)
{
    require(fiber_secure_context_gateway_c3fs_v1_initialize()==0,2);
    for (uint32_t i=0;i<864;++i) { require(__pool_start[i]==0xa5,3); }
    fixture_direct_done();
}
__attribute__((noreturn)) COLD
void fixture_fault_report(const uint32_t *frame,uint32_t exc_return)
{
    uint32_t ipsr;
    __asm volatile("mrs %0,ipsr":"=r"(ipsr));
    emit("FAULT:C3FS-INITIALIZE PC="); hex(frame[6]);
    emit(" CFSR="); hex(REG(0xe000ed28)); emit(" HFSR="); hex(REG(0xe000ed2c));
    emit(" IPSR="); hex(ipsr); emit(" EXC_RETURN="); hex(exc_return);
    emit(" FRAME="); hex((uint32_t)(uintptr_t)frame); emit(" XPSR="); hex(frame[7]);
    finish(42,"\nFAULT-EXIT:C3FS-INITIALIZE\n");
}
__attribute__((noreturn)) COLD void fixture_secure_main(void)
{
    require((uintptr_t)__pool_end-(uintptr_t)__pool_start==864,4);
    for (uint32_t i=0;i<864;++i) { __pool_start[i]=0xa5; }
    REG(0xe000ed88)=0xf00000; /* Secure boot prerequisite, not port setup. */
    REG(0xe000ef34)=(REG(0xe000ef34)|0x20000000u)&~0x04000000u;
    REG(0xe000ed0c)=0x05fa0500;
    REG(0xe000ed24)|=1u<<18;
    REG(0xe000ed1c)&=0x00ffffffu;
    __asm volatile("dsb\nisb\nmsr psplim,%0\nmsr psp,%1" ::
            "r"(0x30001000u),"r"(0x30002000u):"memory");
    __asm volatile("svc #0" ::: "memory");
    REG(0xe000edd8)=0; REG(0xe000eddc)=0x10000; REG(0xe000ede0)=0x1ffe1;
    REG(0xe000edd8)=1; REG(0xe000eddc)=0x20004000; REG(0xe000ede0)=0x20007fe1;
    REG(0xe000edd8)=2; REG(0xe000eddc)=0x10008000; REG(0xe000ede0)=0x10008063;
    REG(0x50080014)=1; REG(0xe000edd0)=1;
    mark_nonsecure(0x58007000,0x10000,0x20000);
    mark_nonsecure(0x50083000,0x4000,0x8000);
    REG(0xe002ed08)=0x10000;
    __asm volatile("msr msp_ns,%0\nmsr psp_ns,%1\nmsr control_ns,%2\ndsb\nisb" ::
            "r"(0x20008000u),"r"(0x20007000u),"r"(0u):"memory");
    const uint32_t entry=*(const uint32_t *)0x10004;
    __asm volatile("bxns %0" ::"r"(entry&~1u):"memory");
    for (;;) {}
}

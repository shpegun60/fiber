#include "report.h"
#include "fiber_port_secure_gateway_abi.h"
#include "fiber_port_secure_context_gateway_abi.h"
volatile uint32_t fixture_result,fixture_phase;
static volatile uint32_t pendsv_done,systick_done;
CHECKPOINT void fixture_wrong_done(void) { __asm volatile("nop" ::: "memory"); }
CHECKPOINT void fixture_first_result(void) { __asm volatile("nop" ::: "memory"); }
CHECKPOINT void fixture_repeat_result(void) { __asm volatile("nop" ::: "memory"); }
CHECKPOINT void fixture_ns_done(void) { __asm volatile("nop" ::: "memory"); }
static COLD void queries(void)
{
    require(fiber_secure_gateway_c3fs_v1_abi_version()==1,10);
    require(fiber_secure_gateway_c3fs_v1_context_port_id()==0x43334653,11);
    require(fiber_secure_gateway_c3fs_v1_context_layout_version()==0x10001,12);
    require(fiber_secure_gateway_c3fs_v1_context_feature_mask()==0x8b,13);
    require(fiber_secure_context_gateway_c3fs_v1_abi_version()==1,14);
    require(fiber_secure_context_gateway_c3fs_v1_stack_alignment()==8,15);
    require(fiber_secure_context_gateway_c3fs_v1_max_stack_bytes()==256,16);
    require(fiber_secure_context_gateway_c3fs_v1_max_contexts()==3,17);
}
COLD void fixture_ns_pendsv(void)
{
    require(fiber_secure_context_gateway_c3fs_v1_initialize()==0,18); pendsv_done=1;
}
COLD void fixture_ns_systick(void)
{
    require(fiber_secure_context_gateway_c3fs_v1_initialize()==0,19); systick_done=1;
}
COLD void fixture_ns_svc(void)
{
    fixture_result=fiber_secure_context_gateway_c3fs_v1_initialize();
    if (fixture_phase==0) { fixture_first_result(); }
    else { fixture_repeat_result(); }
    /* Handler queries remain valid after initialization while no Secure PSP
     * is loaded. Do not call Thread-mode Secure code on the deliberately zero
     * PSP after CONTROL2. This fixture supplies no allocator shortcut. */
    queries();
}
__attribute__((noreturn)) COLD
void fixture_fault_report(const uint32_t *frame,uint32_t exc_return)
{
    (void)frame; (void)exc_return; finish(43,"FAULT:C3FS-INITIALIZE:NS\n");
}
__attribute__((noreturn)) COLD void fixture_ns_main(void)
{
    REG(0xe000ed1c)=0x80000000;
    queries();
    require(fiber_secure_context_gateway_c3fs_v1_initialize()==0,20);
    REG(0xe000ed04)=1u<<28; __asm volatile("dsb\nisb" ::: "memory");
    while (!pendsv_done) { __asm volatile("nop"); }
    REG(0xe000ed04)=1u<<26; __asm volatile("dsb\nisb" ::: "memory");
    while (!systick_done) { __asm volatile("nop"); }
    fixture_wrong_done();
    fixture_phase=0; __asm volatile("svc #0" ::: "memory");
    const uint32_t first=fixture_result;
    fixture_phase=1; __asm volatile("svc #0" ::: "memory");
    require(fixture_result==0,21);
    if (first==1) {
        /* Explicit test-owned NS CPACR setup after the production NSACR grant.
         * These two probes establish actual physical FP access, not context
         * allocation, lazy save, preservation or a Fiber runtime. */
        REG(0xe000ed88)=0xf00000;
        __asm volatile("dsb\nisb" ::: "memory");
        uint32_t low,high;
        __asm volatile(
#ifdef FIXTURE_FP_NOP_CONTROL
                "nop.w\nnop.w\nmov %0,#0\nmov %1,#0\nnop.w\nnop.w"
#else
                "vmov s0,%2\nvmov s31,%3\nmov %0,#0\nmov %1,#0\nvmov %0,s0\nvmov %1,s31"
#endif
                :"=&r"(low),"=&r"(high):"r"(0x3f800000u),"r"(0x40200000u):"memory");
        require(low==0x3f800000u && high==0x40200000u,22);
    }
    fixture_ns_done();
    finish(0,"PASS:C3FS-INITIALIZE:paired\n");
}

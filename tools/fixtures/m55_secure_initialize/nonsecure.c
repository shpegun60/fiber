#include "report.h"
/* Import-only: this does not select or activate a Non-secure fiber runtime. */
#include "fiber_port_secure_context_gateway_abi.h"
#ifdef __cplusplus
extern "C" {
#endif
extern uint32_t fiber_secure_gateway_c55s_v1_abi_version(void);
extern uint32_t fiber_secure_gateway_c55s_v1_context_port_id(void);
extern uint32_t fiber_secure_gateway_c55s_v1_context_layout_version(void);
extern uint32_t fiber_secure_gateway_c55s_v1_context_feature_mask(void);

#ifndef INIT_FAULT_CASE
#define INIT_FAULT_CASE 0
#endif
#ifndef INIT_CONTROL
#define INIT_CONTROL 0
#endif
static volatile uint32_t phase, pendsv_done, systick_done;
volatile uint32_t init_fixture_result;

CHECKPOINT void init_fixture_wrong_done(void) { __asm volatile("nop" ::: "memory"); }
CHECKPOINT void init_fixture_rejected(void) { __asm volatile("nop" ::: "memory"); }
CHECKPOINT void init_fixture_first_result(void) { __asm volatile("nop" ::: "memory"); }
CHECKPOINT void init_fixture_repeat_result(void) { __asm volatile("nop" ::: "memory"); }
CHECKPOINT void init_fixture_unrelated_udf(void) { __asm volatile("udf #1"); }

void init_ns_pendsv(void)
{
    require(__get_IPSR() == 14u && fiber_secure_context_gateway_c55s_v1_initialize() == 0, 10);
    pendsv_done=1;
}
void init_ns_systick(void)
{
    require(__get_IPSR() == 15u && fiber_secure_context_gateway_c55s_v1_initialize() == 0, 11);
    systick_done=1;
}
void init_ns_svc(void)
{
    require(__get_IPSR() == 11u, 12);
    const uint32_t primask=__get_PRIMASK(), basepri=__get_BASEPRI(), faultmask=__get_FAULTMASK();
    init_fixture_result = fiber_secure_context_gateway_c55s_v1_initialize();
    require(__get_PRIMASK()==primask && __get_BASEPRI()==basepri && __get_FAULTMASK()==faultmask, 13);
    if (phase<2) {
        require(init_fixture_result==0u, 14);
        init_fixture_rejected();
    } else if (phase==2) {
        require(init_fixture_result==(INIT_FAULT_CASE ? 0u : 1u), 15);
        init_fixture_first_result();
    } else {
        require(init_fixture_result==0u, 16);
        init_fixture_repeat_result();
    }
}
__attribute__((noreturn)) void init_fault_report(const uint32_t *frame, uint32_t exc_return)
{
    emit("FAULT:C55S-INITIALIZE PC="); hex(frame[6]);
    emit(" CFSR="); hex(REG(0xe000ed28)); emit(" HFSR="); hex(REG(0xe000ed2c));
    emit(" IPSR="); hex(__get_IPSR()); emit(" EXC_RETURN="); hex(exc_return);
    emit(" FRAME="); hex((uint32_t)(uintptr_t)frame); emit(" XPSR="); hex(frame[7]);
    emit("\n"); finish(42, "FAULT-EXIT:C55S-INITIALIZE\n");
}
__attribute__((noreturn)) void init_ns_main(void)
{
    emit("START:C55S-INITIALIZE:Nonsecure-M55\n");
    /* Secure UsageFault priority zero must preempt NS SVC for exact UDF proof. */
    REG(0xe000ed1c)=0x80000000u;
#if INIT_CONTROL == 1
    REG(0xe000ed24) |= 1u<<18;
    init_fixture_unrelated_udf();
#elif INIT_CONTROL == 2
    finish(42, "FAULT-EXIT:C55S-INITIALIZE\n");
#elif INIT_CONTROL == 3
    for (;;) { __asm volatile("wfe"); }
#endif
    volatile uint32_t query = fiber_secure_gateway_c55s_v1_abi_version() ^
        fiber_secure_gateway_c55s_v1_context_port_id() ^
        fiber_secure_gateway_c55s_v1_context_layout_version() ^
        fiber_secure_gateway_c55s_v1_context_feature_mask() ^
        fiber_secure_context_gateway_c55s_v1_abi_version() ^
        fiber_secure_context_gateway_c55s_v1_stack_alignment() ^
        fiber_secure_context_gateway_c55s_v1_max_stack_bytes() ^
        fiber_secure_context_gateway_c55s_v1_max_contexts();
    (void)query;
    require(__get_IPSR()==0u && fiber_secure_context_gateway_c55s_v1_initialize()==0u, 17);
    REG(0xe000ed04)=1u<<28; __DSB(); __ISB();
    while (!pendsv_done) { __asm volatile("nop"); }
    REG(0xe000ed04)=1u<<26; __DSB(); __ISB();
    while (!systick_done) { __asm volatile("nop"); }
    init_fixture_wrong_done();
    for (phase=0; phase<4; ++phase) { __asm volatile("svc #0" ::: "memory"); }
    finish(0, "PASS:C55S-INITIALIZE:complete\nEXIT:C55S-INITIALIZE:0\n");
}
#ifdef __cplusplus
}
#endif

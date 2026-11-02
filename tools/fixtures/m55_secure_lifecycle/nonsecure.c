#include "report.h"
#include "fiber_port_secure_context_gateway_abi.h"
#ifdef __cplusplus
extern "C" {
#endif
extern uint32_t fiber_secure_gateway_c55s_v1_abi_version(void);
extern uint32_t fiber_secure_gateway_c55s_v1_context_port_id(void);
extern uint32_t fiber_secure_gateway_c55s_v1_context_layout_version(void);
extern uint32_t fiber_secure_gateway_c55s_v1_context_feature_mask(void);
typedef struct Step { uint32_t mode,op,arg,owner,expected; } Step;
#include "scenario.h"
#ifndef LIFE_COUNTERFEIT_THREAD_RESUME
#define LIFE_COUNTERFEIT_THREAD_RESUME 0
#endif
volatile uint32_t lifecycle_index,lifecycle_op,lifecycle_arg,lifecycle_owner;
volatile uint32_t lifecycle_result,lifecycle_terminal,lifecycle_done;
POINT void lifecycle_ns_checkpoint(void) { __asm volatile("nop" ::: "memory"); }
POINT void lifecycle_thread_checkpoint(void) { __asm volatile("nop" ::: "memory"); }
static void terminal_record(uint32_t origin)
{
    emit("TERMINAL:C55S-LIFECYCLE STEP=");hex(lifecycle_index);
    emit(" OP=");hex(lifecycle_op);emit(" IPSR=");hex(origin);emit("\n");
}
POINT __attribute__((noreturn)) void lifecycle_terminal_stop(void)
{
    const uint32_t origin=__get_IPSR();
    require((origin==11u||origin==14u)&&origin==steps[lifecycle_index].mode&&lifecycle_result==0,11);
    terminal_record(origin);
    finish(0,"PASS:C55S-LIFECYCLE:terminal-handler\nEXIT:C55S-LIFECYCLE:0\n");
}
static void dispatch(void)
{
    const uint32_t pm=__get_PRIMASK(),bp=__get_BASEPRI(),fm=__get_FAULTMASK();
    switch(lifecycle_op) {
    case 0:lifecycle_result=fiber_secure_context_gateway_c55s_v1_initialize();break;
    case 1:lifecycle_result=fiber_secure_context_gateway_c55s_v1_allocate(lifecycle_arg,lifecycle_owner);break;
    case 2:lifecycle_result=fiber_secure_context_gateway_c55s_v1_load(lifecycle_arg,lifecycle_owner);break;
    case 3:lifecycle_result=fiber_secure_context_gateway_c55s_v1_save(lifecycle_arg,lifecycle_owner);break;
    default:require(0,6);
    }
    require(pm==__get_PRIMASK()&&bp==__get_BASEPRI()&&fm==__get_FAULTMASK(),7);
    lifecycle_ns_checkpoint();
#if !LIFE_COUNTERFEIT_THREAD_RESUME
    if(lifecycle_terminal) { lifecycle_terminal_stop(); }
#endif
    lifecycle_done=1;
}
void lifecycle_ns_svc(void) { require(__get_IPSR()==11,8);dispatch(); }
void lifecycle_ns_pendsv(void) { require(__get_IPSR()==14,9);dispatch(); }
void lifecycle_ns_systick(void) { require(__get_IPSR()==15,10);dispatch(); }
__attribute__((noreturn)) void lifecycle_fault_report(const uint32_t *frame,uint32_t ret)
{
    emit("FAULT:C55S-LIFECYCLE PC=");hex(frame[6]);
    emit(" CFSR=");hex(REG(0xe000ed28));emit(" HFSR=");hex(REG(0xe000ed2c));
    emit(" IPSR=");hex(__get_IPSR());emit(" EXC_RETURN=");hex(ret);
    emit(" FRAME=");hex((uint32_t)(uintptr_t)frame);emit(" XPSR=");hex(frame[7]);
    emit("\n");finish(42,"FAULT-EXIT:C55S-LIFECYCLE\n");
}
__attribute__((noreturn)) void lifecycle_ns_main(void)
{
    emit("START:C55S-LIFECYCLE:Nonsecure-M55\n");
    REG(0xe000ed1c)=0x80000000u;
    __set_PSPLIM(0x20017000);__set_PSP(0x20018000);
    volatile uint32_t queries=fiber_secure_gateway_c55s_v1_abi_version()^
        fiber_secure_gateway_c55s_v1_context_port_id()^fiber_secure_gateway_c55s_v1_context_layout_version()^
        fiber_secure_gateway_c55s_v1_context_feature_mask()^fiber_secure_context_gateway_c55s_v1_abi_version()^
        fiber_secure_context_gateway_c55s_v1_stack_alignment()^fiber_secure_context_gateway_c55s_v1_max_stack_bytes()^
        fiber_secure_context_gateway_c55s_v1_max_contexts();
    (void)queries;
    for(lifecycle_index=0;lifecycle_index<sizeof(steps)/sizeof(steps[0]);++lifecycle_index) {
        const Step *s=&steps[lifecycle_index];
        lifecycle_op=s->op;lifecycle_arg=s->arg;lifecycle_owner=s->owner;lifecycle_done=0;
        if(s->mode==11) { __asm volatile("svc #0" ::: "memory"); }
        else if(s->mode==0) { dispatch(); }
        else { REG(0xe000ed04)=1u<<(s->mode==14?28:26);__DSB();__ISB(); }
        while(!lifecycle_done) { __asm volatile("nop"); }
        lifecycle_thread_checkpoint();
        if(lifecycle_terminal) {
#if LIFE_COUNTERFEIT_THREAD_RESUME
            /* Deliberately counterfeit a correct-looking Handler record from
             * resumed Thread mode. The debugger origin oracle must reject it. */
            terminal_record(s->mode);
            finish(0,"PASS:C55S-LIFECYCLE:terminal-handler\nEXIT:C55S-LIFECYCLE:0\n");
#else
            require(0,12);
#endif
        }
        require(lifecycle_result==s->expected,0x1000+lifecycle_index);
    }
    finish(0,"PASS:C55S-LIFECYCLE:complete\nEXIT:C55S-LIFECYCLE:0\n");
}
#ifdef __cplusplus
}
#endif

#include "fiber_portmacro.h"
#include "fiber_port_private.h"
#include "fiber_port_secure_context_abi.h"
#include "fiber/fiber_runtime_state.h"
#include "report.h"
extern void running_construct(FiberContext *,void *,void *,entry_t,void *,uint32_t);
extern uint32_t running_secure_work(uint32_t tag);
extern void running_ns_window(uint32_t tag);
void *memset(void *,int,size_t);

/* Explicit staged harness identity; no forward runtime/provider is defined. */
FIBER_PORT_CONTEXT_COHORT_DEFINE();
__attribute__((section(".fixture_case"),used)) volatile const uint32_t running_case=0;
__attribute__((section(".fixture_fault"),used)) volatile const uint32_t running_fault=0;
__attribute__((used,externally_visible)) FiberContext running_contexts[2];
__attribute__((used,externally_visible)) volatile uint32_t running_selected;
__attribute__((used,externally_visible)) volatile uint32_t running_switches;
__attribute__((used,externally_visible,aligned(8))) unsigned char running_stacks[2][4096];
POINT void running_prepared(void){__asm volatile("nop" ::: "memory");}
POINT void running_task_checkpoint(void){__asm volatile("nop" ::: "memory");}
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_ram(uintptr_t begin,uintptr_t end)
{return begin>=0x20010000u&&end<=0x20020000u&&end>begin;}
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_code(uintptr_t address)
{return address>=0x10000u&&address<0x20000u;}
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_memory_barrier(void){__DMB();__DSB();__ISB();}
FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_task_return(void)
{finish(92,"FAIL:C55S-RUNNING:task-return\n");}
FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_panic(char code)
{
    emit("PANIC:C55S-RUNNING code=");hex((uint32_t)code);
    emit(" IPSR=");hex(__get_IPSR());emit("\n");
    finish(93,"PANIC-EXIT:C55S-RUNNING\n");
}
POINT FiberContext *running_pick(FiberContext *current,void *user)
{
    require(user==(void *)0x12344321u,50);
    if(!current){require(__get_IPSR()==0u,51);return &running_contexts[0];}
    require(__get_IPSR()==14u&&current==&running_contexts[running_selected],52);
    ++running_switches;running_selected^=1u;
    if(running_fault==1u){return NULL;}
    return &running_contexts[running_selected];
}
POINT __attribute__((noreturn)) void running_task(void *argument)
{
    const uint32_t id=(uintptr_t)argument;
    require(id<=1u&&running_selected==id,60);
    require(fiber_internal_runtime_current_context_slot==&running_contexts[id],61);
    running_task_checkpoint();
    const uint32_t attached=(running_case==1u||running_case==4u||
        (running_case==2u&&id==0u)||(running_case==3u&&id==1u));
    if(attached&&running_case!=4u){require(running_secure_work(id)==(0x53470000u|id),62);}
    else{running_ns_window(id);}
    require(id==0u&&running_switches==2u&&running_selected==0u,63);
    require(fiber_internal_runtime_current_context_slot==&running_contexts[0],64);
    require(__get_IPSR()==0u&&__get_CONTROL()==2u&&__get_PRIMASK()==0u&&
        __get_BASEPRI()==0u&&__get_FAULTMASK()==0u,65);
    finish(0,"PASS:C55S-RUNNING:fiber\n");
}
__attribute__((noreturn)) void running_ns_main(void)
{
    emit("START:C55S-RUNNING:NS-fiber\n");
    require(running_case<=4u,70);
    for(uint32_t id=0;id<2u;++id){
        memset(running_stacks[id],0xa5,sizeof(running_stacks[id]));
        memset(&running_contexts[id],0xa5,sizeof(running_contexts[id]));
        running_construct(&running_contexts[id],running_stacks[id]+3,running_stacks[id]+4093,
            running_task,(void *)(uintptr_t)id,0x91000000u|id);
        const uint32_t attached=(running_case==1u||running_case==4u||
            (running_case==2u&&id==0u)||(running_case==3u&&id==1u));
        if(attached){fiber_port_secure_context_attach(&running_contexts[id],512u);}
    }
    NVIC_SetPriority(PendSV_IRQn,7u);
    fiber_internal_scheduler_store_pick_next(running_pick,(void *)0x12344321u);
    FiberContext *const first=fiber_internal_runtime_select_scheduler_candidate(NULL);
    fiber_internal_runtime_close_context_configuration();
    fiber_internal_runtime_publish_current_context(first);
    running_prepared();
    fiber_port_first_start(first);
}

#include "fiber/fiber_core.h"
#include "fiber_port_secure_context_abi.h"
#include "report.h"
extern uint32_t origin_secure_work(uint32_t tag);
extern void origin_ns_window(uint32_t tag);
__attribute__((section(".fixture_case"),used)) volatile const uint32_t origin_case=0;
__attribute__((used,externally_visible)) FiberContext origin_contexts[2];
__attribute__((used,externally_visible)) volatile uint32_t origin_selected,origin_switches;
__attribute__((used,externally_visible,aligned(8))) unsigned char origin_stacks[2][2048];
POINT void origin_prepared(void){__asm volatile("nop" ::: "memory");}
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_ram(uintptr_t begin,uintptr_t end)
{return begin>=0x20004000u&&end<=0x20008000u&&end>begin;}
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_code(uintptr_t address)
{return address>=0x10000u&&address<0x20000u;}
FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_panic(char code)
{
    emit("PANIC:C33-ORIGIN code=");hex((uint32_t)code);
    emit(" IPSR=");hex(__get_IPSR());emit("\n");
    finish(93,"PANIC-EXIT:C33-ORIGIN\n");
}
POINT FiberContext *origin_pick(FiberContext *current,void *user)
{
    require(user==(void *)0x12344321u,50);
    if(!current){require(__get_IPSR()==0u,51);return &origin_contexts[0];}
    require(__get_IPSR()==14u&&current==&origin_contexts[origin_selected],52);
    ++origin_switches;origin_selected^=1u;
    return &origin_contexts[origin_selected];
}
POINT __attribute__((noreturn)) void origin_task(void *argument)
{
    const uint32_t id=(uintptr_t)argument;
    require(id<=1u&&origin_selected==id&&fiber_current()==&origin_contexts[id],60);
    const uint32_t attached=origin_case==1u||origin_case==4u||
        (origin_case==2u&&id==0u)||(origin_case==3u&&id==1u);
    if(attached&&origin_case!=4u){require(origin_secure_work(id)==(0x53470000u|id),61);}
    else{origin_ns_window(id);}
    require(id==0u&&origin_switches==2u&&origin_selected==0u,62);
    require(fiber_current()==&origin_contexts[0]&&__get_IPSR()==0u&&__get_CONTROL()==2u&&
        __get_PRIMASK()==0u&&__get_BASEPRI()==0u&&__get_FAULTMASK()==0u,63);
    finish(0,"PASS:C33-ORIGIN:runtime\n");
}
__attribute__((noreturn)) void origin_ns_main(void)
{
    require(origin_case<=4u,64);
    for(uint32_t id=0;id<2u;++id){
        memset(origin_stacks[id],0xa5,sizeof(origin_stacks[id]));
        memset(&origin_contexts[id],0xa5,sizeof(origin_contexts[id]));
        fiber_init(&origin_contexts[id],origin_stacks[id]+3,origin_stacks[id]+2045,origin_task,(void *)(uintptr_t)id);
        const uint32_t attached=origin_case==1u||origin_case==4u||
            (origin_case==2u&&id==0u)||(origin_case==3u&&id==1u);
        if(attached){fiber_port_secure_context_attach(&origin_contexts[id],512u);}
    }
    fiber_scheduler_set_pick_next(origin_pick,(void *)0x12344321u);
    origin_prepared();fiber_start();
}

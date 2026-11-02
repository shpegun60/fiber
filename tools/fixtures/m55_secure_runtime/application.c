#include "fiber/fiber_core.h"
#include "fiber/fiber_panic.h"
#include "fiber/port/fiber_settings.h"
#include "fiber_port_secure_context_abi.h"
#include "api_fixture.h"
#include "report.h"
extern void runtime_construct(FiberContext *,void *,void *,entry_t,void *,uint32_t);
extern void runtime_ns_window(uint32_t),runtime_public_window(uint32_t);
extern uint32_t runtime_secure_work(uint32_t);
void *memset(void *,int,size_t);
__attribute__((section(".fixture_case"),used)) volatile const uint32_t runtime_case=0;
__attribute__((section(".fixture_fault"),used)) volatile const uint32_t runtime_fault=0;
__attribute__((used,externally_visible)) FiberContext runtime_contexts[2];
/* Includes the compiler's 4 KiB generic-stack-check probe budget in hostile builds. */
__attribute__((used,externally_visible,aligned(8))) unsigned char runtime_stacks[2][8192];
__attribute__((used,externally_visible)) volatile uint32_t runtime_phase;
__attribute__((used,externally_visible)) volatile uint32_t runtime_entered;
__attribute__((used,externally_visible)) volatile uint32_t runtime_mutated;
__attribute__((used,externally_visible)) volatile uint32_t runtime_hooks[4][2];
__attribute__((used,externally_visible,section(".fixture_policy"))) const uint32_t runtime_policy[]={
    FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH,FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH,
    FIBER_REWIND_MSP,FIBER_STACK_CANARY
};
POINT void runtime_prestart(void){__asm volatile("nop" ::: "memory");}
POINT void runtime_constructed(void){__asm volatile("nop" ::: "memory");}
POINT void runtime_callback_inside(void){__asm volatile("nop" ::: "memory");}
POINT void runtime_steady_checkpoint(void){__asm volatile("nop" ::: "memory");}
POINT void runtime_success_terminal(void){__asm volatile("nop" ::: "memory");}
POINT void runtime_warm_before(void){__asm volatile("nop" ::: "memory");}
POINT void runtime_warm_after(void){__asm volatile("nop" ::: "memory");}
POINT void runtime_panic_terminal(uint32_t code){__asm volatile("" :: "r"(code) : "memory");}
POINT void runtime_callback_action(void)
{
    if(runtime_fault==3u){fiber_start();}
    if(runtime_fault==4u){fiber_init(&runtime_contexts[0],runtime_stacks[0],runtime_stacks[0]+8192,0,0);}
    if(runtime_fault==5u){fiber_port_secure_context_attach(&runtime_contexts[0],512u);}
    if(runtime_fault==6u){fiber_scheduler_set_pick_next(0,0);}
    if(runtime_scheduler.first_calls!=0u){
        if(runtime_fault==16u){runtime_register(&runtime_contexts[0],&runtime_contexts[1]);}
        if(runtime_fault==17u){fiber_schedule();}
        if(runtime_fault==18u){fiber_start();}
    }
}
POINT __attribute__((noreturn)) void runtime_application_failure(uint32_t check)
{emit("FAIL:C55S-RUNTIME check=");hex(check);emit("\n");finish(90,"FAIL-EXIT:C55S-RUNTIME\n");}
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_ram(uintptr_t begin,uintptr_t end)
{
    const uint32_t phase=runtime_phase;
    require(phase<4u,20);++runtime_hooks[phase][0];
    if(phase==3u){
        if(runtime_fault==31u){return 0;}
        if(runtime_fault==33u){__set_PRIMASK(1u);}
        if(runtime_fault==34u){__set_CONTROL(2u);}
        if(runtime_fault==35u){__set_BASEPRI(2u<<(8u-__NVIC_PRIO_BITS));}
        if(runtime_fault==36u){__set_FAULTMASK(1u);}
        if(runtime_fault==37u){__set_PSPLIM(__get_PSPLIM()+8u);}
        if(runtime_fault==38u){__set_PSP(__get_PSP()+8u);}
        __DSB();__ISB();
    }
    return begin>=0x20010000u&&end<=0x20020000u&&end>begin;
}
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_code(uintptr_t address)
{
    const uint32_t phase=runtime_phase;
    require(phase<4u,21);++runtime_hooks[phase][1];
    if(phase==3u){
        if(runtime_fault==32u){return 0;}
        if(runtime_fault==39u){__set_PRIMASK(1u);__DSB();__ISB();}
    }
    return address>=0x10000u&&address<0x20000u;
}
#ifndef RUNTIME_USE_WEAK_PANIC
FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_panic(char code)
{
    emit("PANIC:C55S-RUNTIME code=");hex((uint32_t)code);
    emit(" IPSR=");hex(__get_IPSR());emit("\n");
    runtime_panic_terminal((uint32_t)code);
    finish(93,"PANIC-EXIT:C55S-RUNTIME\n");
}
#endif
POINT void runtime_task_action(uint32_t id)
{
    if(id!=0u){return;}
    if(runtime_fault==10u){fiber_start();}
    if(runtime_fault==11u){runtime_register(&runtime_contexts[0],&runtime_contexts[1]);}
    if(runtime_fault==12u){fiber_init(&runtime_contexts[0],runtime_stacks[0],runtime_stacks[0]+8192,0,0);}
    if(runtime_fault==13u){fiber_port_secure_context_attach(&runtime_contexts[0],512u);}
}
POINT void runtime_task(void *argument)
{
    const uint32_t id=(uintptr_t)argument;
    require(id<=1u&&runtime_scheduler.selected==id&&fiber_current()==&runtime_contexts[id],30);
    runtime_entered|=1u<<id;
    runtime_phase=runtime_entered==3u?3u:2u;
    runtime_task_action(id);
    if(runtime_fault==14u){return;}
    const uint32_t attached=runtime_case==1u||runtime_case==4u||
        (runtime_case==2u&&id==0u)||(runtime_case==3u&&id==1u);
    for(uint32_t round=0;round<3u;++round){
        if(round==0u){runtime_public_window(id);}
        else if(attached&&runtime_case!=4u){require(runtime_secure_work(id)==(0x53470000u|id),31);}
        else{runtime_ns_window(id);}
        require(fiber_current()==&runtime_contexts[id]&&runtime_scheduler.selected==id,32);
        if(runtime_entered==3u){runtime_phase=3u;runtime_steady_checkpoint();}
        if(id==0u&&runtime_scheduler.switches==2u&&runtime_fault==30u&&runtime_mutated==0u){
            runtime_warm_before();
            ((volatile unsigned char *)&runtime_contexts[0])[76]^=1u;
            runtime_mutated=1u;
            runtime_warm_after();
        }
    }
    require(id==0u&&runtime_scheduler.switches==6u&&runtime_scheduler.first_calls==1u&&runtime_entered==3u,33);
    require(__get_IPSR()==0u&&__get_CONTROL()==2u&&__get_PRIMASK()==0u&&
        __get_BASEPRI()==0u&&__get_FAULTMASK()==0u,34);
    require(runtime_hooks[0][0]>0u&&runtime_hooks[0][1]>0u,35);
    if(FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH){require(runtime_hooks[3][0]>0u&&runtime_hooks[3][1]>0u,36);}
    else{require(runtime_hooks[3][0]==0u&&runtime_hooks[3][1]==0u,37);}
    runtime_success_terminal();
    finish(0,"PASS:C55S-RUNTIME\n");
}
__attribute__((noreturn)) void runtime_ns_main(void)
{
    emit("START:C55S-RUNTIME:NS\n");
    require(runtime_case<=4u&&fiber_current()==0,40);
    for(uint32_t id=0;id<2u;++id){
        memset(runtime_stacks[id],0xa5,8192u);
        memset(&runtime_contexts[id],0xa5,sizeof(FiberContext));
        runtime_construct(&runtime_contexts[id],runtime_stacks[id]+3,runtime_stacks[id]+8189,
            runtime_task,(void *)(uintptr_t)id,0x91000000u|id);
        const uint32_t attached=runtime_case==1u||runtime_case==4u||
            (runtime_case==2u&&id==0u)||(runtime_case==3u&&id==1u);
        if(attached){fiber_port_secure_context_attach(&runtime_contexts[id],512u);}
    }
    runtime_constructed();
    if(runtime_fault==20u){fiber_start();}
    if(runtime_fault==21u){fiber_schedule();}
    if(runtime_fault==22u){fiber_scheduler_set_pick_next(0,0);}
    runtime_register(&runtime_contexts[0],&runtime_contexts[1]);
    /* Production prepare-start must establish these, not the fixture. */
    REG(0xe000ed14)&=~(1u<<9u);
    *(volatile uint8_t *)0xe000ed1fu=0xe0u;
    *(volatile uint8_t *)0xe000ed22u=0u;
    runtime_phase=1u;
    runtime_prestart();
    fiber_start();
}

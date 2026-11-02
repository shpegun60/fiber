#include "FreeRTOS.h"
#include "task.h"
#include "report.h"
extern void vStartFirstTask(void);
extern void vPortAllocateSecureContext(uint32_t bytes);
extern uint32_t running_secure_work(uint32_t tag);
extern void running_ns_window(uint32_t tag);
void *memset(void *,int,size_t);
__attribute__((section(".fixture_case"),used)) volatile const uint32_t running_case=0;
__attribute__((used,externally_visible)) struct {uint32_t *sp;} running_tcbs[2];
__attribute__((used,externally_visible,aligned(8))) uint32_t running_stacks[2][1024];
__attribute__((used,externally_visible)) TaskHandle_t pxCurrentTCB;
__attribute__((used,externally_visible)) volatile uint32_t running_selected;
__attribute__((used,externally_visible)) volatile uint32_t running_switches;
POINT void running_prepared(void){__asm volatile("nop" ::: "memory");}
POINT void running_task_checkpoint(void){__asm volatile("nop" ::: "memory");}
POINT __attribute__((noreturn)) void running_reference_assert(void)
{finish(92,"FAIL:C55S-RUNNING:reference-assert\n");}
POINT __attribute__((noreturn)) void running_task_return(void)
{finish(92,"FAIL:C55S-RUNNING:task-return\n");}
void vTaskSwitchContext(void)
{
    require(__get_IPSR()==14u&&__get_BASEPRI()==128u,20);
    ++running_switches;running_selected^=1u;
    pxCurrentTCB=(TaskHandle_t)&running_tcbs[running_selected];
}
POINT __attribute__((noreturn)) void running_task(void *argument)
{
    const uint32_t id=(uintptr_t)argument;
    require(id<=1u&&running_selected==id,30);
    const uint32_t attached=(running_case==1u||running_case==4u||
        (running_case==2u&&id==0u)||(running_case==3u&&id==1u));
    if(attached){vPortAllocateSecureContext(512u);}
    running_task_checkpoint();
    if(attached&&running_case!=4u){
        require(running_secure_work(id)==(0x53470000u|id),31);
    }else{running_ns_window(id);}
    require(id==0u&&running_switches==2u&&running_selected==0u,32);
    require(__get_IPSR()==0u&&__get_CONTROL()==2u&&__get_PRIMASK()==0u&&
        __get_BASEPRI()==0u&&__get_FAULTMASK()==0u,33);
    finish(0,"PASS:C55S-RUNNING:reference\n");
}
__attribute__((noreturn)) void running_ns_main(void)
{
    emit("START:C55S-RUNNING:NS-reference\n");
    require(running_case<=4u,40);
    for(uint32_t id=0;id<2u;++id){
        memset(running_stacks[id],0xa5,sizeof(running_stacks[id]));
        running_tcbs[id].sp=pxPortInitialiseStack(running_stacks[id]+1024,
            running_stacks[id]+8,running_task,(void *)(uintptr_t)id);
    }
    pxCurrentTCB=(TaskHandle_t)&running_tcbs[0];
    NVIC_SetPriority(PendSV_IRQn,7u);
    running_prepared();
    vStartFirstTask();
    finish(92,"FAIL:C55S-RUNNING:start-return\n");
}

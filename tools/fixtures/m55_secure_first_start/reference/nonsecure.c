#include "FreeRTOS.h"
#include "task.h"
#include "report.h"
extern void first_task_entry(void *);
extern void vStartFirstTask(void);
extern void vPortAllocateSecureContext(uint32_t bytes);
extern uint32_t xSecureContext;
void *memset(void *,int,size_t);
static __attribute__((aligned(8))) uint32_t first_stack[256];
static struct { uint32_t *sp; } first_tcb;
__attribute__((used,externally_visible)) TaskHandle_t pxCurrentTCB;
__attribute__((section(".fixture_case"),used)) volatile const uint32_t first_case=0;
POINT void first_prepared(void){__asm volatile("nop" ::: "memory");}
POINT void first_reference_allocated(void){__asm volatile("nop" ::: "memory");}
POINT __attribute__((noreturn)) void first_reference_assert(void)
{finish(92,"FAIL:C55S-FIRST:reference-configASSERT\n");}
POINT __attribute__((noreturn)) void fiber_internal_task_return(void)
{finish(92,"FAIL:C55S-FIRST:task-returned\n");}
__attribute__((noreturn)) void first_entry_report(const uint32_t *r,uint32_t sp,uint32_t control,uint32_t limit)
{
    require(__get_IPSR()==0u&&control==2u,10);
    require(sp==(uintptr_t)(first_stack+256)&&limit==(uintptr_t)(first_stack+8),11);
    require(r[0]==0x12345678u&&r[1]==0x01010101u&&r[2]==0x02020202u&&
        r[3]==0x03030303u&&r[12]==0x12121212u,12);
    require(r[13]==(((uintptr_t)&fiber_internal_task_return)|1u),13);
    require(__get_PRIMASK()==0u&&__get_BASEPRI()==0u&&__get_FAULTMASK()==0u,14);
    require(xSecureContext==0u,15);
    emit("ENTRY:C55S-FIRST:reference r4-r11=");
    for(uint32_t i=4;i<12;++i){hex(r[i]);emit(" ");}emit("\n");
    if(first_case==1u){
        /* Real later allocation SVC100, not pre-start C55 request policy. */
        vPortAllocateSecureContext(64u);
        require(xSecureContext==1u,16);
        require(__get_IPSR()==0u&&__get_CONTROL()==2u&&__get_PRIMASK()==0u&&
            __get_BASEPRI()==0u&&__get_FAULTMASK()==0u,17);
        first_reference_allocated();
    }
    finish(0,"PASS:C55S-FIRST:reference\nPASS-EXIT:C55S-FIRST\n");
}
__attribute__((noreturn)) void first_ns_main(void)
{
    emit("START:C55S-FIRST:NS-reference case=");hex(first_case);emit("\n");
    require(first_case<=1u,20);
    memset(first_stack,0xa5,sizeof(first_stack));
    first_tcb.sp=pxPortInitialiseStack(first_stack+256,first_stack+8,
        first_task_entry,(void *)0x12345678u);
    require(first_tcb.sp==first_stack+256-19,21);
    const uint32_t expected[19]={0,(uintptr_t)(first_stack+8),0xffffffbcu,
        0x04040404u,0x05050505u,0x06060606u,0x07070707u,0x08080808u,
        0x09090909u,0x10101010u,0x11111111u,0x12345678u,0x01010101u,
        0x02020202u,0x03030303u,0x12121212u,
        ((uintptr_t)&fiber_internal_task_return)|1u,(uintptr_t)first_task_entry,0x01000000u};
    for(uint32_t i=0;i<19;++i){require(first_tcb.sp[i]==expected[i],100+i);}
    pxCurrentTCB=(TaskHandle_t)&first_tcb;
    first_prepared();
    vStartFirstTask();
    finish(93,"FAIL:C55S-FIRST:reference-start-returned\n");
}

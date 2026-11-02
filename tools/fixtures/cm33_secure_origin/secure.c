#include "report.h"
extern unsigned char __pool_start[],__pool_end[];
extern void origin_secure_window(uint32_t tag);
POINT void origin_secure_ready(void){__asm volatile("nop" ::: "memory");}
__attribute__((cmse_nonsecure_entry,noinline,used))
uint32_t origin_secure_work(uint32_t tag)
{
    origin_secure_window(tag);
    return 0x53470000u|tag;
}
static void mark_nonsecure(uint32_t mpc,uint32_t first,uint32_t end)
{
    const uint32_t shift=REG(mpc+0x14)+5u;
    require(shift>=5u&&shift<=12u,70);
    REG(mpc)=0x10;
    for(uint32_t block=first>>shift;block<(end>>shift);++block){
        REG(mpc+0x18)=block/32u;REG(mpc+0x1c)|=1u<<(block%32u);
    }
}
__attribute__((noreturn)) void origin_secure_main(void)
{
    const uint32_t bytes=(uintptr_t)__pool_end-(uintptr_t)__pool_start;
    require(bytes==3172u||bytes==3176u,71);
    for(uint32_t i=0;i<bytes;++i){((volatile unsigned char *)__pool_start)[i]=0xa5;}
    REG(0xe000ed08)=0x10000000;
    REG(0xe000ed24)|=1u<<18;
    REG(0xe000ed0c)=0x05fa0000u;
    SAU->CTRL=0;
    SAU->RNR=0;SAU->RBAR=0x10000;SAU->RLAR=0x1ffe1;
    SAU->RNR=1;SAU->RBAR=0x20004000;SAU->RLAR=0x20007fe1;
    SAU->RNR=2;SAU->RBAR=0x10008000;SAU->RLAR=0x10008fe3;
    REG(0x50080014)=1;SAU->CTRL=1;
    mark_nonsecure(0x58007000,0x10000,0x20000);
    mark_nonsecure(0x50083000,0x4000,0x8000);
    SCB_NS->VTOR=0x10000;
    NVIC->ITNS[0]|=1u;
    __TZ_set_CONTROL_NS(0);__TZ_set_MSP_NS(0x20008000);
    __TZ_set_PSP_NS(0);__TZ_set_PSPLIM_NS(0);__DSB();__ISB();
    emit("START:C33-ORIGIN:Secure\n");origin_secure_ready();
    const uint32_t target=REG(0x10004)&~1u;
    __asm volatile("bxns %0" :: "r"(target) : "memory");
    __builtin_unreachable();
}

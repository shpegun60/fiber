#include "report.h"
extern void first_secure_retain_exports(void);
#ifndef FIRST_REFERENCE
extern unsigned char __pool_start[],__pool_end[];
#endif
POINT void first_secure_ready(void){__asm volatile("nop" ::: "memory");}
__attribute__((noreturn)) void first_secure_main(void)
{
    first_secure_retain_exports();
#ifndef FIRST_REFERENCE
    require((uintptr_t)__pool_end-(uintptr_t)__pool_start==480u,1);
    for(uint32_t i=0;i<480;++i){((volatile unsigned char *)__pool_start)[i]=0xa5;}
#endif
    REG(0xe000ed08)=0;
    REG(0xe000ed24)|=1u<<18;
    REG(0xe000ed0c)=0x05fa0500u;
    __set_PSPLIM(0x30005000u);__set_PSP(0x30006000u);
    SAU->CTRL=0;
    SAU->RNR=0;SAU->RBAR=0x10000;SAU->RLAR=0x1ffe1;
    SAU->RNR=1;SAU->RBAR=0x20010000;SAU->RLAR=0x2001ffe1;
    SAU->RNR=2;SAU->RBAR=0x10008000;SAU->RLAR=0x10008fe3;
    REG(0x50080014)=1;SAU->CTRL=1;
    SCB_NS->VTOR=0x10000;
    __TZ_set_CONTROL_NS(0);__TZ_set_MSP_NS(0x20020000);
    __TZ_set_PSPLIM_NS(0);__DSB();__ISB();
    emit("START:C55S-FIRST:Secure-M55\n");
    first_secure_ready();
    const uint32_t target=REG(0x10004)&~1u;
    __asm volatile("bxns %0" :: "r"(target) : "memory");
    __builtin_unreachable();
}

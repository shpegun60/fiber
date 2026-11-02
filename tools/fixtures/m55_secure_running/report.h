#ifndef C55S_RUNNING_START_REPORT_H
#define C55S_RUNNING_START_REPORT_H
#include <stddef.h>
#include <stdint.h>
#include "main.h"
#define REG(a) (*(volatile uint32_t *)(uintptr_t)(a))
#define POINT __attribute__((noinline,noclone,used,externally_visible))
static inline void emit(const char *text)
{
    register uint32_t op __asm("r0")=4;
    register const char *arg __asm("r1")=text;
    __asm volatile("bkpt 0xab" : "+r"(op) : "r"(arg) : "memory");
}
static inline void hex(uint32_t value)
{
    char text[11]="0x00000000";
    const char digits[]="0123456789abcdef";
    for(uint32_t i=0;i<8;++i){text[9-i]=digits[value&15u];value>>=4;}
    emit(text);
}
static inline __attribute__((noreturn)) void finish(uint32_t code,const char *text)
{
    const uint32_t block[]={0x20026,code};
    emit(text);
    register uint32_t op __asm("r0")=0x20;
    register const uint32_t *arg __asm("r1")=block;
    __asm volatile("bkpt 0xab" : "+r"(op) : "r"(arg) : "memory");
    for(;;){__asm volatile("wfe");}
}
static inline void require(uint32_t condition,uint32_t check)
{
    if(!condition){emit("FAIL:C55S-RUNNING check=");hex(check);emit("\n");finish(90,"FAIL-EXIT:C55S-RUNNING\n");}
}
#endif

#ifndef M55_SECURE_LIFECYCLE_REPORT_H
#define M55_SECURE_LIFECYCLE_REPORT_H
#include <stdint.h>
#include "../m55_secure_initialize/main.h"
#define REG(a) (*(volatile uint32_t *)(uintptr_t)(a))
#define POINT __attribute__((noinline,noclone,used,externally_visible))
static void emit(const char *text)
{
    register uint32_t op __asm("r0")=4;
    register const char *arg __asm("r1")=text;
    __asm volatile("bkpt 0xab" : "+r"(op) : "r"(arg) : "memory");
}
static void hex(uint32_t value)
{
    char text[11]="0x00000000";
    const char digits[]="0123456789abcdef";
    for(uint32_t i=0;i<8;++i) { text[9-i]=digits[value&15]; value>>=4; }
    emit(text);
}
static __attribute__((noreturn)) void finish(uint32_t code,const char *text)
{
    const uint32_t block[]={0x20026,code};
    emit(text);
    register uint32_t op __asm("r0")=0x20;
    register const uint32_t *arg __asm("r1")=block;
    __asm volatile("bkpt 0xab" : "+r"(op) : "r"(arg) : "memory");
    for(;;) { __asm volatile("wfe"); }
}
static void require(uint32_t value,uint32_t check)
{
    if(!value) { emit("FAIL:C55S-LIFECYCLE:");hex(check);emit("\n");finish(90,"EXIT:C55S-LIFECYCLE:assertion\n"); }
}
#endif

#ifndef C3FS_INITIALIZE_REPORT_H_
#define C3FS_INITIALIZE_REPORT_H_
#include <stdint.h>
#include "fiber_api_attributes.h"
#define REG(a) (*(volatile uint32_t *)(uintptr_t)(a))
#define COLD FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
#define CHECKPOINT __attribute__((used)) COLD
static COLD void emit(const char *text)
{
    register uint32_t op __asm("r0") = 4;
    register const char *arg __asm("r1") = text;
    __asm volatile("bkpt 0xab" : "+r"(op) : "r"(arg) : "memory");
}
static COLD void hex(uint32_t value)
{
    char text[11] = "0x00000000";
    const char digits[] = "0123456789abcdef";
    for (uint32_t i=0; i<8; ++i) { text[9-i]=digits[value & 15u]; value>>=4; }
    emit(text);
}
static __attribute__((noreturn)) COLD void finish(uint32_t status, const char *text)
{
    const uint32_t args[2]={0x20026,status};
    emit(text);
    register uint32_t op __asm("r0")=0x20;
    register const uint32_t *arg __asm("r1")=args;
    __asm volatile("bkpt 0xab" : "+r"(op) : "r"(arg) : "memory");
    for (;;) { __asm volatile("wfe"); }
}
static COLD void require(uint32_t condition, uint32_t code)
{
    if (!condition) { emit("FAIL:C3FS-INITIALIZE:"); hex(code); finish(91,"\n"); }
}
#endif

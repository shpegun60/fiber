#ifndef C5SO_RUNTIME_REPORT_H
#define C5SO_RUNTIME_REPORT_H
#include <stdint.h>
static inline void report_text(const char *s)
{
    register uint32_t op __asm__("r0")=4;
    register const char *arg __asm__("r1")=s;
    __asm__ volatile("bkpt 0xab":"+r"(op):"r"(arg):"memory");
}
static inline void report_value(const char *name,uint32_t value)
{
    char s[11]="0x00000000";
    const char digits[]="0123456789abcdef";
    for(unsigned i=0;i<8;++i){s[9-i]=digits[value&15u];value>>=4;}
    report_text(name);report_text("=");report_text(s);report_text("\n");
}
__attribute__((noreturn)) static inline void report_exit(uint32_t code,const char *s)
{
    uint32_t args[2]={0x20026,code};report_text(s);
    register uint32_t op __asm__("r0")=0x20;
    register const uint32_t *arg __asm__("r1")=args;
    __asm__ volatile("bkpt 0xab":"+r"(op):"r"(arg):"memory");
    for(;;){__asm__ volatile("wfi");}
}
static inline void report_check(int ok,unsigned line)
{if(!ok){report_value("FAILED_CHECK",line);report_exit(1,"FAIL:C5SO-RUNTIME\n");}}
#define CHECK(c) report_check((c),__LINE__)
#endif

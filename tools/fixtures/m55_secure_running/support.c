#include "report.h"
/* Kept for compiler-generated aggregate copies introduced during LTO. */
POINT void *memcpy(void *destination,const void *source,size_t count)
{
    unsigned char *d=destination;const unsigned char *s=source;
    while(count--){*d++=*s++;}return destination;
}
POINT void *memset(void *destination,int value,size_t count)
{
    unsigned char *d=destination;
    while(count--){*d++=(unsigned char)value;}return destination;
}
POINT void __aeabi_memcpy(void *d,const void *s,size_t n){(void)memcpy(d,s,n);}
POINT void __aeabi_memcpy4(void *d,const void *s,size_t n){(void)memcpy(d,s,n);}
POINT void __aeabi_memclr4(void *d,size_t n){(void)memset(d,0,n);}

POINT void running_fault_terminal(const uint32_t *frame,uint32_t ret)
{
    __asm volatile("" :: "r"(frame),"r"(ret) : "memory");
}
__attribute__((noreturn)) void first_fault_report(const uint32_t *frame,uint32_t ret)
{
    emit("FAULT:C55S-RUNNING PC=");hex(frame[6]);emit(" RET=");hex(ret);
    emit(" IPSR=");hex(__get_IPSR());emit(" CFSR=");hex(REG(0xe000ed28));
    emit(" HFSR=");hex(REG(0xe000ed2c));emit(" XPSR=");hex(frame[7]);emit("\n");
    running_fault_terminal(frame,ret);
    finish(91,"FAULT-EXIT:C55S-RUNNING\n");
}

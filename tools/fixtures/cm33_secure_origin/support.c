#include "report.h"
void emit(const char *text)
{
    register uint32_t operation __asm("r0")=4;
    register const char *argument __asm("r1")=text;
    __asm volatile("bkpt #0xab" : "+r"(operation) : "r"(argument) : "memory");
}
void hex(uint32_t value)
{
    char output[11]="0x00000000";
    for(uint32_t i=0;i<8u;++i){output[9u-i]="0123456789abcdef"[value&15u];value>>=4;}
    emit(output);
}
__attribute__((noreturn)) void finish(uint32_t status,const char *text)
{
    emit(text);
    uint32_t block[2]={0x20026u,status};
    register uint32_t operation __asm("r0")=0x20;
    register uint32_t *argument __asm("r1")=block;
    __asm volatile("bkpt #0xab" : "+r"(operation) : "r"(argument) : "memory");
    for(;;){}
}
void require(uint32_t condition,uint32_t code)
{
    if(!condition){emit("FAIL:C33-ORIGIN code=");hex(code);emit("\n");finish(90,"FAIL-EXIT:C33-ORIGIN\n");}
}
POINT void *memset(void *destination,int value,size_t size)
{
    volatile unsigned char *p=destination;
    for(size_t i=0;i<size;++i){p[i]=(unsigned char)value;}
    return destination;
}
POINT void *memcpy(void *destination,const void *source,size_t size)
{
    volatile unsigned char *out=destination;
    const volatile unsigned char *in=source;
    for(size_t i=0;i<size;++i){out[i]=in[i];}
    return destination;
}
__attribute__((noreturn)) void origin_fault_report(uint32_t *frame,uint32_t ret)
{
    emit("FAULT:C33-ORIGIN frame=");hex((uintptr_t)frame);
    emit(" RET=");hex(ret);emit(" IPSR=");hex(__get_IPSR());emit("\n");
    finish(94,"FAULT-EXIT:C33-ORIGIN\n");
}

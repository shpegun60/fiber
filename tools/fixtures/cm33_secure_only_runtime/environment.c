#include "fixture.h"
#include "main.h"
/* Real integration-owned maps, not permissive production-hook substitutes. */
FIBER_GENERAL_REGS_ONLY int fiber_addr_plausible_ram(uintptr_t begin,uintptr_t end)
{
#if EXEC_CASE == 17
    if(fixture_phase==4 && __get_IPSR()==14) {__set_BASEPRI(64);}
#endif
    return begin>=0x30000000u && end>begin && end<=0x30008000u;
}
FIBER_GENERAL_REGS_ONLY int fiber_addr_plausible_code(uintptr_t address)
{return address>=0x10000800u && address<0x10020000u && (address&1u)==0;}
/* Freestanding libc primitives with ordinary ABI and no CPU-state effects. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void *memcpy(void *dest,const void *source,size_t count)
{unsigned char *d=dest;const unsigned char *s=source;for(size_t i=0;i<count;++i)d[i]=s[i];return dest;}
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void *memset(void *dest,int value,size_t count)
{unsigned char *d=dest;for(size_t i=0;i<count;++i)d[i]=(unsigned char)value;return dest;}

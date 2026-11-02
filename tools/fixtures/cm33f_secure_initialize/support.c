/* Explicit fixture-only integer library admission; not a port operation. */
#include <stddef.h>
#include "report.h"
COLD void *memcpy(void *destination,const void *source,size_t size)
{
    unsigned char *d=destination;
    const unsigned char *s=source;
    for (size_t i=0;i<size;++i) { d[i]=s[i]; }
    return destination;
}
COLD void *memset(void *destination,int value,size_t size)
{
    unsigned char *d=destination;
    for (size_t i=0;i<size;++i) { d[i]=(unsigned char)value; }
    return destination;
}

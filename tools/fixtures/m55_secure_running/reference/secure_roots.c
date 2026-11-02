#include <stdint.h>
#include "secure_init.h"
#include "secure_context.h"
static void (*volatile const roots[])(void)={
    (void (*)(void))SecureInit_DePrioritizeNSExceptions,
    (void (*)(void))SecureContext_Init,
    (void (*)(void))SecureContext_AllocateContext,
    (void (*)(void))SecureContext_SaveContext,
    (void (*)(void))SecureContext_LoadContext};
void running_secure_retain(void)
{for(uint32_t i=0;i<sizeof(roots)/sizeof(roots[0]);++i){(void)roots[i];}}

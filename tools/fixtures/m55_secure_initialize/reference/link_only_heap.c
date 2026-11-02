/* Unexecuted heap dependencies of other retained FreeRTOS CMSE exports.
 * Initialization itself has no heap dependency. Do not use this as a heap. */
#include <stddef.h>
void *pvPortMalloc(size_t bytes)
{
    (void)bytes;
    __builtin_trap();
}
void vPortFree(void *pointer)
{
    (void)pointer;
    __builtin_trap();
}

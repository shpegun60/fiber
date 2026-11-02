/* Executed platform allocator for the unmodified pinned Secure allocator.
 * This is not a Fiber pool, gateway adapter or claimed FreeRTOS heap policy. */
#include "report.h"
__attribute__((aligned(8),used,externally_visible)) unsigned char first_reference_heap[1024];
__attribute__((used,externally_visible)) volatile uint32_t first_reference_heap_used;
POINT void *pvPortMalloc(size_t bytes)
{
    require(bytes==72u&&first_reference_heap_used==0u,30);
    first_reference_heap_used=(uint32_t)bytes;
    return first_reference_heap;
}
POINT void vPortFree(void *address)
{(void)address;finish(92,"FAIL:C55S-FIRST:unexpected-reference-free\n");}
POINT __attribute__((noreturn)) void first_reference_assert(void)
{finish(92,"FAIL:C55S-FIRST:reference-configASSERT\n");}

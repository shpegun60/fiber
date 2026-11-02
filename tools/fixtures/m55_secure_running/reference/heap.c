#include <stdint.h>
#include <stddef.h>
#include "report.h"
__attribute__((used,externally_visible,aligned(8))) unsigned char running_reference_heap[3][520];
__attribute__((used,externally_visible)) uint32_t running_reference_allocations;
void *pvPortMalloc(size_t bytes)
{
    require(bytes==520u&&running_reference_allocations<3u,90);
    return running_reference_heap[running_reference_allocations++];
}
void vPortFree(void *p){(void)p;finish(92,"FAIL:C55S-RUNNING:unexpected-free\n");}

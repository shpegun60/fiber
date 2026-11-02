#include <stdint.h>
extern void Reset_Handler(void), SVC_Handler(void), PendSV_Handler(void);
static void fault(void) { for (;;) {} }
__attribute__((used, section(".vectors")))
const uintptr_t admission_vectors[16] = {
    0x20020000u, (uintptr_t)Reset_Handler, (uintptr_t)fault, (uintptr_t)fault,
    (uintptr_t)fault, (uintptr_t)fault, (uintptr_t)fault, (uintptr_t)fault,
    0, 0, 0, (uintptr_t)SVC_Handler, (uintptr_t)fault, 0,
    (uintptr_t)PendSV_Handler, (uintptr_t)fault
};

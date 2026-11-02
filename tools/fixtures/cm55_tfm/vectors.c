#include <stdint.h>
extern void Reset_Handler(void), SVC_Handler(void), PendSV_Handler(void);
__attribute__((used, section(".vectors")))
const uintptr_t vectors[512] = {
    [0] = 0x20010000u, [1] = (uintptr_t)Reset_Handler,
    [11] = (uintptr_t)SVC_Handler, [14] = (uintptr_t)PendSV_Handler
};

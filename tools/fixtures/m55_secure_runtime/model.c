#include "report.h"
__attribute__((noreturn)) void runtime_secure_main(void)
{
    volatile uint8_t *const priority=(volatile uint8_t *)0xe002e400u;
    const uint32_t targets=REG(0xe000e380);
    REG(0xe000e380)=targets|1u;__DSB();__ISB();
    const uint8_t original=*priority;
    *priority=255u;__DSB();__ISB();
    const uint8_t mask=*priority;
    *priority=original;__DSB();__ISB();
    require(*priority==original,1);
    REG(0xe000e380)=targets;__DSB();__ISB();
    require(REG(0xe000e380)==targets,2);
    emit("MODEL:NS-IRQ0-MASK=");hex(mask);emit("\n");
    finish(0,"PASS:C55S-RUNTIME:MODEL\n");
}

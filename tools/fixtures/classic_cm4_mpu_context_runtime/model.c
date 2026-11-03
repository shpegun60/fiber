#include "fixture.h"
PILOT_NORETURN PILOT_GRO void fixture_fault_record(uint32_t *frame, uint32_t exc_return, uint32_t ipsr)
{
    (void)frame; (void)exc_return; (void)ipsr;
    fixture_unexpected();
}
PILOT_NORETURN PILOT_GRO void fixture_main(void)
{
    volatile uint8_t *const irq0_priority = (volatile uint8_t *)0xe000e400u;
    const uint8_t saved = *irq0_priority;
    *irq0_priority = 0xffu;
    __asm volatile("dsb\nisb" ::: "memory");
    const uint32_t mask = *irq0_priority;
    *irq0_priority = saved;
    __asm volatile("dsb\nisb" ::: "memory");
    fixture_write("MODEL:CM4-MPU:CPUID="); fixture_hex(*(volatile uint32_t *)0xe000ed00u);
    fixture_write(":MPU_TYPE="); fixture_hex(*(volatile uint32_t *)0xe000ed90u);
    fixture_write(":NVIC_MASK="); fixture_hex(mask);
    fixture_write(":MVFR0="); fixture_hex(*(volatile uint32_t *)0xe000ef40u);
    fixture_write(":MPU_CTRL="); fixture_hex(*(volatile uint32_t *)0xe000ed94u);
    fixture_write("\nPASS:CM4-MPU:MODEL\n");
    fixture_exit(0u);
}

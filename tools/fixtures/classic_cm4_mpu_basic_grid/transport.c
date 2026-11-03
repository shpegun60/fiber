#include "fixture.h"
PILOT_GRO void fixture_write(const char *text)
{
    register uint32_t operation __asm("r0") = 4u;
    register const char *argument __asm("r1") = text;
    __asm volatile("bkpt 0xab" : "+r"(operation) : "r"(argument) : "memory");
}
PILOT_GRO void fixture_hex(uint32_t value)
{
    char text[9];
    for (uint32_t i = 0; i < 8u; ++i) {
        const uint32_t digit = (value >> (28u - 4u * i)) & 15u;
        text[i] = (char)(digit < 10u ? '0' + digit : 'A' + digit - 10u);
    }
    text[8] = 0;
    fixture_write(text);
}
PILOT_NORETURN PILOT_GRO void fixture_exit(uint32_t status)
{
    const uint32_t block[2] = { 0x20026u, status };
    register uint32_t operation __asm("r0") = 0x20u;
    register const uint32_t *argument __asm("r1") = block;
    __asm volatile("bkpt 0xab" : "+r"(operation) : "r"(argument) : "memory");
    for (;;) { __asm volatile("udf #2"); }
}
PILOT_NORETURN PILOT_GRO void fixture_unexpected(void)
{
    fixture_write("FAIL:CM4-MPU:UNEXPECTED\n");
    fixture_exit(70u);
}

#ifndef M55_SECURE_INITIALIZE_REPORT_H
#define M55_SECURE_INITIALIZE_REPORT_H
#include <stdint.h>
#include "main.h"

static void emit(const char *text)
{
    register uint32_t op __asm("r0") = 4u;
    register const char *arg __asm("r1") = text;
    __asm volatile("bkpt 0xab" : "+r"(op) : "r"(arg) : "memory");
}

static __attribute__((unused)) void hex(uint32_t value)
{
    char text[11] = "0x00000000";
    const char digits[] = "0123456789abcdef";
    for (uint32_t i = 0; i < 8; ++i) { text[9u-i] = digits[value & 15u]; value >>= 4; }
    emit(text);
}

static __attribute__((noreturn)) void finish(uint32_t status, const char *message)
{
    const uint32_t block[] = {0x20026u, status};
    emit(message);
    register uint32_t op __asm("r0") = 0x20u;
    register const uint32_t *arg __asm("r1") = block;
    __asm volatile("bkpt 0xab" : "+r"(op) : "r"(arg) : "memory");
    for (;;) { __asm volatile("wfe"); }
}

static void require(uint32_t condition, uint32_t check)
{
    if (!condition) {
        emit("FAIL:C55S-INITIALIZE check="); hex(check); emit("\n");
        finish(90, "EXIT:C55S-INITIALIZE:assertion\n");
    }
}

#define CHECKPOINT __attribute__((noinline, noclone, used, externally_visible))
#define REG(address) (*(volatile uint32_t *)(uintptr_t)(address))
#endif

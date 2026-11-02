#ifndef CM33F_MPU_FIRST_START_EXECUTION_REPORT_H
#define CM33F_MPU_FIRST_START_EXECUTION_REPORT_H
#include <stdint.h>

static inline void report_text(const char *text)
{
    register uint32_t operation __asm__("r0") = 4u;
    register const char *argument __asm__("r1") = text;
    __asm__ volatile ("bkpt 0xab" : "+r"(operation) : "r"(argument) : "memory");
}

static inline void report_hex(uint32_t value)
{
    char text[11] = "0x00000000";
    static const char digits[] = "0123456789abcdef";
    for (uint32_t i = 0u; i < 8u; ++i) {
        text[9u - i] = digits[value & 15u];
        value >>= 4u;
    }
    report_text(text);
}

static inline void report_value(const char *name, uint32_t value)
{
    report_text(name); report_text("="); report_hex(value); report_text("\n");
}

__attribute__((noreturn)) static inline void report_exit(uint32_t code, const char *text)
{
    uint32_t arguments[2] = {0x20026u, code};
    report_text(text);
    register uint32_t operation __asm__("r0") = 0x20u;
    register const uint32_t *argument __asm__("r1") = arguments;
    __asm__ volatile ("bkpt 0xab" : "+r"(operation) : "r"(argument) : "memory");
    for (;;) { __asm__ volatile ("wfi"); }
}

static inline void report_check(int condition, uint32_t number)
{
    if (!condition) {
        report_value("FAILED_CHECK", number);
        report_exit(1u, "FAIL:C3FP-FIRST-START\n");
    }
}
#endif
